//! PostgreSQL 告警域：规则 / 状态 / 事件 / 静默 / 通知渠道。
//!
//! 本文件只写 [`PostgresStorage`] 的**固有方法**，签名与
//! [`Storage`](crate::storage::Storage) 中对应方法逐字一致；统一
//! `impl Storage for PostgresStorage` 由最后的转发层一次性补齐。
//!
//! 行为对照 `sqlite.rs` 的 M4-B1 / B1b / B2 实现：
//!
//! - 事务范围一致：种子、规则更新/删除（含清理状态）、事件与状态的批量落库、
//!   事件/静默清理、渠道引用检查都在单事务内完成；失败整体回滚；
//! - 领域错误一致：`NotFound` / `NameExists` / `LimitReached` / `BuiltinRule` /
//!   `InUse` 与 SQLite 相同，且通过 `anyhow` 上下文后仍可被 hub
//!   `downcast_ref` 命中；
//! - 排序/分页/时间边界一致：所有时间比较的严格/非严格边界与 SQLite 相同；
//!   文本排序显式 `COLLATE "C"`，对齐 SQLite 默认 BINARY 的字节序；
//! - 布尔列（`enabled` / `notified` / `silenced` / `is_builtin` /
//!   `notify_on_resolve`）显式按 `bool` 读写，不沿用 SQLite 的 `i64` 假设；
//! - JSON 列保持 SQLite 的「TEXT + serde_json」格式，不使用 `JSONB`，也不
//!   改写 `filter_labels` / `channel_ids` / `config_json` 的序列化结果。
//!
//! # 与 SQLite `rowid` 的差异
//!
//! PG 没有隐式 `rowid`。schema 为 `samples` / `alert_states` 等表补了
//! `id BIGSERIAL`，因此：
//!
//! - `latest_alert_series` 的同 `ts` 次序用 `samples.id DESC`；
//! - 状态/事件的清理与分页游标用 `alert_states.id` / `alert_events.id`；
//! - `alert_events` 的自增 id 由 `RETURNING id` 返回，和 SQLite
//!   `last_insert_rowid()` 语义一致。
//!
//! # 并发
//!
//! SQLite 用 `BEGIN IMMEDIATE` 把配置写操作串行化，因此「规则数量上限」、
//! 「渠道引用检查」这类先查后写在并发下也不会被击穿。PG 默认 READ COMMITTED
//! 没有这层串行化，所以全部**告警配置写操作**（规则、渠道、静默的增删改与
//! 种子）在事务开头取同一把事务级 advisory lock；热路径
//! [`PostgresStorage::apply_alert_evaluation`] 不取锁，避免评估每轮阻塞管理
//! 操作。并发唯一冲突仍由数据库 UNIQUE 约束兜底并翻译成领域错误，不吞错。

use anyhow::{anyhow, Context, Result};
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::{Row, Transaction};
use rustboard_common::model::Labels;

use super::PostgresStorage;
use crate::alerts::{
    AlertEvent, AlertRule, AlertRuleStoreError, AlertSilence, AlertSilenceStoreError, AlertSource,
    AlertState, AlertStateKind, Comparator, MAX_ALERT_RULES, MAX_ALERT_SILENCES,
};
use crate::channels::{ChannelConfig, ChannelKind, NotificationChannel};
use crate::storage::sqlite::{AlertSeriesSnapshot, ChannelStoreError, MAX_NOTIFICATION_CHANNELS};
use crate::storage::AgentSeriesRow;

/// `alert_rules` 的 SELECT 列表；列顺序与 [`alert_rule_from_row`] 一一对应。
const ALERT_RULE_COLUMNS: &str = "id, name, enabled, source, metric, comparator, threshold, \
     duration_secs, cooldown_secs, filter_agent_id, filter_labels, channel_ids, \
     notify_on_resolve, is_builtin, updated_by, created_at, updated_at";

/// 新建 / 种子共用的插入语句；`created_at` / `updated_at` 由参数显式给出。
const ALERT_RULE_INSERT_SQL: &str = "INSERT INTO alert_rules \
     (id, name, enabled, source, metric, comparator, threshold, duration_secs, \
      cooldown_secs, filter_agent_id, filter_labels, channel_ids, notify_on_resolve, \
      is_builtin, updated_by, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)";

/// 更新语句只覆盖可写字段：`id` 定位，`is_builtin` / `created_at` 保持原值。
const ALERT_RULE_UPDATE_SQL: &str = "UPDATE alert_rules SET name = $2, enabled = $3, \
     source = $4, metric = $5, comparator = $6, threshold = $7, duration_secs = $8, \
     cooldown_secs = $9, filter_agent_id = $10, filter_labels = $11, channel_ids = $12, \
     notify_on_resolve = $13, updated_by = $14, updated_at = $15 WHERE id = $1";

/// `alert_states` 的 SELECT 列表；列顺序与 [`alert_state_from_row`] 一一对应。
const ALERT_STATE_COLUMNS: &str =
    "rule_id, agent_id, series_key, state, since, last_eval_at, last_value, last_notified_at";

/// 插入或更新一条状态；单条 upsert 与批量事务共用。
///
/// `last_notified_at` 只由新插入行携带（引擎的新序列为 NULL），冲突分支
/// **绝不覆盖**：通知时间归 `update_alert_state_notified` 独占，避免
/// “引擎读旧快照 → worker 写通知时间 → 引擎提交”把冷却锚点冲掉。
const ALERT_STATE_UPSERT_SQL: &str = "INSERT INTO alert_states \
     (rule_id, agent_id, series_key, state, since, last_eval_at, last_value, last_notified_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (rule_id, agent_id, series_key) DO UPDATE SET \
        state = EXCLUDED.state, \
        since = EXCLUDED.since, \
        last_eval_at = EXCLUDED.last_eval_at, \
        last_value = EXCLUDED.last_value";

/// 每规则状态硬上限：保留最近 `keep` 条，非 resolved 优先，其次 `last_eval_at`。
const ALERT_STATE_PRUNE_FOR_RULE_SQL: &str = "DELETE FROM alert_states \
     WHERE rule_id = $1 AND id NOT IN ( \
         SELECT id FROM alert_states WHERE rule_id = $1 \
         ORDER BY (state = 'resolved') ASC, last_eval_at DESC, id DESC LIMIT $2 \
     )";

/// `alert_events` 的插入语句；批量事务使用。
const ALERT_EVENT_INSERT_SQL: &str = "INSERT INTO alert_events \
     (ts, rule_id, rule_name, agent_id, series_key, state, value, message, notified, \
      notify_error, silenced) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";

/// 单条事件插入并返回自增 id；与 SQLite `last_insert_rowid()` 对齐。
const ALERT_EVENT_INSERT_RETURNING_SQL: &str = "INSERT INTO alert_events \
     (ts, rule_id, rule_name, agent_id, series_key, state, value, message, notified, \
      notify_error, silenced) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id";

/// `alert_events` 的 SELECT 列表；列顺序与 [`alert_event_from_row`] 一一对应。
const ALERT_EVENT_COLUMNS: &str = "id, ts, rule_id, rule_name, agent_id, series_key, state, \
     value, message, notified, notify_error, silenced";

/// 当前最大告警事件 id；没有事件时返回 0。
const MAX_ALERT_EVENT_ID_SQL: &str = "SELECT COALESCE(MAX(id), 0) FROM alert_events";

/// `alert_silences` 的 SELECT 列表；列顺序与 [`alert_silence_from_row`] 一一对应。
const ALERT_SILENCE_COLUMNS: &str = "id, rule_id, agent_id, until_ts, created_by, created_at";

/// 创建静默并返回自增 id；`silence.id` 被忽略。
const ALERT_SILENCE_INSERT_SQL: &str = "INSERT INTO alert_silences \
     (rule_id, agent_id, until_ts, created_by, created_at) \
     VALUES ($1, $2, $3, $4, $5) RETURNING id";

/// `notification_channels` 的 SELECT 列表；列顺序与
/// [`notification_channel_from_row`] 一一对应。
const NOTIFICATION_CHANNEL_COLUMNS: &str =
    "id, name, kind, config_json, enabled, updated_by, created_at, updated_at";

/// B2 `notify_error` 的存储上限（字节），与 SQLite 一致。
const MAX_ALERT_NOTIFY_ERROR_BYTES: usize = 512;

/// 告警配置写操作的事务级 advisory lock。
///
/// key 与 schema 迁移锁（`SCHEMA_ADVISORY_LOCK_KEY`）刻意不同：迁移只在本进程
/// 启动时用，配置写操作在运行期用，两者不会互相阻塞。锁随事务提交/回滚自动
/// 释放，不需要显式 unlock。
const ALERT_CONFIG_LOCK_KEY: i64 = 0x5242_5047_0000_0011;

impl PostgresStorage {
    // ---- 告警规则（schema v7 `alert_rules`） ----

    /// 写入内置规则种子：按固定 id 已存在的规则（含用户改过的阈值 / 启停状态）
    /// **绝不覆盖**；重复调用幂等，返回本次新插入的条数。
    ///
    /// 与 `INSERT ... ON CONFLICT DO NOTHING` 不同：先按 id 查重、再显式 INSERT。
    /// 这样 `name` 唯一冲突（例如升级前用户已建同名自定义规则）会直接失败并
    /// 回滚整批种子，而不是被静默吞掉、留下「缺内置规则」的半残状态。
    pub fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 seed_builtin_alert_rules 事务失败")?;
            lock_alert_config(&mut tx)?;
            let mut inserted = 0usize;
            for rule in rules {
                let exists = tx
                    .query_opt("SELECT 1 FROM alert_rules WHERE id = $1", &[&rule.id])
                    .context("检查内置告警规则是否已存在失败")?
                    .is_some();
                if exists {
                    // 可能已被用户改过阈值 / 启停 / 名称：种子绝不覆盖。
                    continue;
                }
                let filter_labels = serde_json::to_string(&rule.filter_labels)
                    .context("序列化内置规则 filter_labels 失败")?;
                let channel_ids = serde_json::to_string(&rule.channel_ids)
                    .context("序列化内置规则 channel_ids 失败")?;
                let source = rule.source.as_str();
                let comparator = rule.comparator.as_str();
                let duration_secs = i64::from(rule.duration_secs);
                let cooldown_secs = i64::from(rule.cooldown_secs);
                if let Err(err) = tx.execute(
                    ALERT_RULE_INSERT_SQL,
                    &[
                        &rule.id,
                        &rule.name,
                        &rule.enabled,
                        &source,
                        &rule.metric,
                        &comparator,
                        &rule.threshold,
                        &duration_secs,
                        &cooldown_secs,
                        &rule.filter_agent_id,
                        &filter_labels,
                        &channel_ids,
                        &rule.notify_on_resolve,
                        &rule.is_builtin,
                        &rule.updated_by,
                        &now,
                        &now,
                    ],
                ) {
                    return Err(map_seed_alert_rule_error(err, &rule.id));
                }
                inserted += 1;
            }
            tx.commit()
                .context("提交 seed_builtin_alert_rules 事务失败")?;
            Ok(inserted)
        })
        .context("seed_builtin_alert_rules")
    }

    /// 按 id 读取一条规则；不存在返回 `None`。
    pub fn get_alert_rule(&self, id: &str) -> Result<Option<AlertRule>> {
        self.with_client(|client| {
            let sql = format!("SELECT {ALERT_RULE_COLUMNS} FROM alert_rules WHERE id = $1");
            let row = client
                .query_opt(&sql, &[&id])
                .context("执行 get_alert_rule SQL 失败")?;
            row.as_ref().map(alert_rule_from_row).transpose()
        })
        .context("get_alert_rule")
    }

    /// 列出全部规则：内置在前，同组按名称升序。
    pub fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_RULE_COLUMNS} FROM alert_rules \
                 ORDER BY is_builtin DESC, name COLLATE \"C\" ASC"
            );
            let rows = client
                .query(&sql, &[])
                .context("执行 list_alert_rules SQL 失败")?;
            rows.iter().map(alert_rule_from_row).collect()
        })
        .context("list_alert_rules")
    }

    /// 规则总数（含内置规则）。
    pub fn alert_rule_count(&self) -> Result<usize> {
        self.with_client(|client| {
            let count: i64 = client
                .query_one("SELECT COUNT(*)::BIGINT FROM alert_rules", &[])
                .context("执行 alert_rule_count SQL 失败")?
                .get(0);
            Ok(usize::try_from(count).unwrap_or(0))
        })
        .context("alert_rule_count")
    }

    /// 新建一条规则。
    ///
    /// 事务内先查重再写入，把两种失败翻译成领域错误：
    /// - 总数（含内置）达到 [`MAX_ALERT_RULES`] → [`AlertRuleStoreError::LimitReached`]；
    /// - 名称重复 → [`AlertRuleStoreError::NameExists`]（并发下仍由 UNIQUE 兜底）。
    ///
    /// 事务开头取配置 advisory lock，使「查总数 + 插入」在并发下与 SQLite 的
    /// `BEGIN IMMEDIATE` 语义一致。
    pub fn create_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        let filter_labels =
            serde_json::to_string(&rule.filter_labels).context("序列化 filter_labels 失败")?;
        let channel_ids =
            serde_json::to_string(&rule.channel_ids).context("序列化 channel_ids 失败")?;
        let source = rule.source.as_str();
        let comparator = rule.comparator.as_str();
        let duration_secs = i64::from(rule.duration_secs);
        let cooldown_secs = i64::from(rule.cooldown_secs);
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 create_alert_rule 事务失败")?;
            lock_alert_config(&mut tx)?;
            let count: i64 = tx
                .query_one("SELECT COUNT(*)::BIGINT FROM alert_rules", &[])
                .context("统计告警规则数量失败")?
                .get(0);
            if count >= MAX_ALERT_RULES as i64 {
                return Err(AlertRuleStoreError::LimitReached.into());
            }
            let name_exists = tx
                .query_opt("SELECT 1 FROM alert_rules WHERE name = $1", &[&rule.name])
                .context("检查告警规则名称是否重复失败")?
                .is_some();
            if name_exists {
                return Err(AlertRuleStoreError::NameExists.into());
            }
            if let Err(err) = tx.execute(
                ALERT_RULE_INSERT_SQL,
                &[
                    &rule.id,
                    &rule.name,
                    &rule.enabled,
                    &source,
                    &rule.metric,
                    &comparator,
                    &rule.threshold,
                    &duration_secs,
                    &cooldown_secs,
                    &rule.filter_agent_id,
                    &filter_labels,
                    &channel_ids,
                    &rule.notify_on_resolve,
                    &rule.is_builtin,
                    &rule.updated_by,
                    &rule.created_at,
                    &rule.updated_at,
                ],
            ) {
                return Err(map_alert_rule_write_error(err));
            }
            tx.commit().context("提交 create_alert_rule 事务失败")?;
            Ok(())
        })
        .context("create_alert_rule")
    }

    /// 更新规则的可写字段；不清理 `alert_states`。
    ///
    /// `id` 是定位键，`is_builtin` / `created_at` 保持数据库原值；不存在返回
    /// [`AlertRuleStoreError::NotFound`]，改名冲突返回
    /// [`AlertRuleStoreError::NameExists`]。
    pub fn update_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        self.update_alert_rule_inner(rule, false)
    }

    /// 与 [`Self::update_alert_rule`] 相同，并在同一事务内清空该规则的状态。
    pub fn update_alert_rule_and_clear_states(&self, rule: &AlertRule) -> Result<()> {
        self.update_alert_rule_inner(rule, true)
    }

    fn update_alert_rule_inner(&self, rule: &AlertRule, clear_states: bool) -> Result<()> {
        let filter_labels =
            serde_json::to_string(&rule.filter_labels).context("序列化 filter_labels 失败")?;
        let channel_ids =
            serde_json::to_string(&rule.channel_ids).context("序列化 channel_ids 失败")?;
        let source = rule.source.as_str();
        let comparator = rule.comparator.as_str();
        let duration_secs = i64::from(rule.duration_secs);
        let cooldown_secs = i64::from(rule.cooldown_secs);
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 update_alert_rule 事务失败")?;
            lock_alert_config(&mut tx)?;
            let exists = tx
                .query_opt("SELECT 1 FROM alert_rules WHERE id = $1", &[&rule.id])
                .context("检查告警规则是否存在失败")?
                .is_some();
            if !exists {
                return Err(AlertRuleStoreError::NotFound.into());
            }
            let name_exists = tx
                .query_opt(
                    "SELECT 1 FROM alert_rules WHERE name = $1 AND id <> $2",
                    &[&rule.name, &rule.id],
                )
                .context("检查告警规则名称是否冲突失败")?
                .is_some();
            if name_exists {
                return Err(AlertRuleStoreError::NameExists.into());
            }
            if let Err(err) = tx.execute(
                ALERT_RULE_UPDATE_SQL,
                &[
                    &rule.id,
                    &rule.name,
                    &rule.enabled,
                    &source,
                    &rule.metric,
                    &comparator,
                    &rule.threshold,
                    &duration_secs,
                    &cooldown_secs,
                    &rule.filter_agent_id,
                    &filter_labels,
                    &channel_ids,
                    &rule.notify_on_resolve,
                    &rule.updated_by,
                    &rule.updated_at,
                ],
            ) {
                return Err(map_alert_rule_write_error(err));
            }
            if clear_states {
                tx.execute("DELETE FROM alert_states WHERE rule_id = $1", &[&rule.id])
                    .context("清理告警规则状态失败")?;
            }
            tx.commit().context("提交 update_alert_rule 事务失败")?;
            Ok(())
        })
        .context("update_alert_rule")
    }

    /// 删除自定义规则；内置规则返回 [`AlertRuleStoreError::BuiltinRule`]。
    ///
    /// 不存在与内置是两种不同的错误，调用方分别映射 404 / 403。**不清理**
    /// `alert_states`；API 删除规则时用 [`Self::delete_alert_rule_and_clear_states`]。
    pub fn delete_alert_rule(&self, id: &str) -> Result<()> {
        self.delete_alert_rule_inner(id, false)
    }

    /// 与 [`Self::delete_alert_rule`] 相同，并在同一事务内清空该规则的状态。
    pub fn delete_alert_rule_and_clear_states(&self, id: &str) -> Result<()> {
        self.delete_alert_rule_inner(id, true)
    }

    fn delete_alert_rule_inner(&self, id: &str, clear_states: bool) -> Result<()> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 delete_alert_rule 事务失败")?;
            lock_alert_config(&mut tx)?;
            let is_builtin: Option<bool> = tx
                .query_opt("SELECT is_builtin FROM alert_rules WHERE id = $1", &[&id])
                .context("读取告警规则类型失败")?
                .map(|row| row.get(0));
            match is_builtin {
                None => return Err(AlertRuleStoreError::NotFound.into()),
                Some(true) => return Err(AlertRuleStoreError::BuiltinRule.into()),
                Some(false) => {}
            }
            tx.execute("DELETE FROM alert_rules WHERE id = $1", &[&id])
                .context("删除告警规则失败")?;
            if clear_states {
                tx.execute("DELETE FROM alert_states WHERE rule_id = $1", &[&id])
                    .context("清理告警规则状态失败")?;
            }
            tx.commit().context("提交 delete_alert_rule 事务失败")?;
            Ok(())
        })
        .context("delete_alert_rule")
    }

    // ---- 告警状态 / 事件 / 静默（schema v7） ----

    /// 列出全部告警状态，按 `(rule_id, agent_id, series_key)` 稳定排序。
    pub fn list_alert_states(&self) -> Result<Vec<AlertState>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_STATE_COLUMNS} FROM alert_states \
                 ORDER BY rule_id COLLATE \"C\" ASC, agent_id COLLATE \"C\" ASC, \
                 series_key COLLATE \"C\" ASC"
            );
            let rows = client
                .query(&sql, &[])
                .context("执行 list_alert_states SQL 失败")?;
            rows.iter().map(alert_state_from_row).collect()
        })
        .context("list_alert_states")
    }

    /// 按主键读取一条告警状态；不存在返回 `None`。
    pub fn get_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<Option<AlertState>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_STATE_COLUMNS} FROM alert_states \
                 WHERE rule_id = $1 AND agent_id = $2 AND series_key = $3"
            );
            let row = client
                .query_opt(&sql, &[&rule_id, &agent_id, &series_key])
                .context("执行 get_alert_state SQL 失败")?;
            row.as_ref().map(alert_state_from_row).transpose()
        })
        .context("get_alert_state")
    }

    /// 插入或更新一条告警状态：冲突时覆盖状态、时间与值，但**保留**
    /// 库中已有的 `last_notified_at`（由通知 worker 独占；新行按传入值写入，
    /// 引擎构造的新序列为 NULL）。
    pub fn upsert_alert_state(&self, state: &AlertState) -> Result<()> {
        let state_kind = state.state.as_str();
        self.with_client(|client| {
            client
                .execute(
                    ALERT_STATE_UPSERT_SQL,
                    &[
                        &state.rule_id,
                        &state.agent_id,
                        &state.series_key,
                        &state_kind,
                        &state.since,
                        &state.last_eval_at,
                        &state.last_value,
                        &state.last_notified_at,
                    ],
                )
                .context("执行 upsert_alert_state SQL 失败")?;
            Ok(())
        })
        .context("upsert_alert_state")
    }

    /// 删除一条告警状态，返回受影响行数（0 = 本来不存在）。
    pub fn delete_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<usize> {
        self.with_client(|client| {
            let removed = client
                .execute(
                    "DELETE FROM alert_states \
                     WHERE rule_id = $1 AND agent_id = $2 AND series_key = $3",
                    &[&rule_id, &agent_id, &series_key],
                )
                .context("执行 delete_alert_state SQL 失败")?;
            Ok(usize::try_from(removed).unwrap_or(usize::MAX))
        })
        .context("delete_alert_state")
    }

    /// 只清理 `resolved` 且 `last_eval_at < resolved_before` 的状态。
    ///
    /// pending / firing 无论多旧都不删：它们代表仍然存在的告警，删除会导致下一次
    /// 评估重复产生 firing 事件。
    pub fn prune_alert_states(&self, resolved_before: i64) -> Result<usize> {
        self.with_client(|client| {
            let removed = client
                .execute(
                    "DELETE FROM alert_states \
                     WHERE state = 'resolved' AND last_eval_at < $1",
                    &[&resolved_before],
                )
                .context("执行 prune_alert_states SQL 失败")?;
            Ok(usize::try_from(removed).unwrap_or(usize::MAX))
        })
        .context("prune_alert_states")
    }

    /// 分页清理陈旧的 pending / firing 状态，`max_rows` 限制单次删除量。
    ///
    /// resolved 状态由 [`Self::prune_alert_states`] 负责，不在这里重复处理。
    pub fn prune_stale_alert_states(&self, stale_before: i64, max_rows: usize) -> Result<usize> {
        if max_rows == 0 {
            return Ok(0);
        }
        let limit = i64::try_from(max_rows).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let removed = client
                .execute(
                    "DELETE FROM alert_states WHERE id IN ( \
                         SELECT id FROM alert_states \
                         WHERE state IN ('pending','firing') AND last_eval_at < $1 \
                         ORDER BY state ASC, last_eval_at ASC, id ASC LIMIT $2 \
                     )",
                    &[&stale_before, &limit],
                )
                .context("执行 prune_stale_alert_states SQL 失败")?;
            Ok(usize::try_from(removed).unwrap_or(usize::MAX))
        })
        .context("prune_stale_alert_states")
    }

    /// 插入告警事件，返回自增 id；`event.id` 被忽略。
    pub fn insert_alert_event(&self, event: &AlertEvent) -> Result<i64> {
        let state_kind = event.state.as_str();
        self.with_client(|client| {
            let id: i64 = client
                .query_one(
                    ALERT_EVENT_INSERT_RETURNING_SQL,
                    &[
                        &event.ts,
                        &event.rule_id,
                        &event.rule_name,
                        &event.agent_id,
                        &event.series_key,
                        &state_kind,
                        &event.value,
                        &event.message,
                        &event.notified,
                        &event.notify_error,
                        &event.silenced,
                    ],
                )
                .context("执行 insert_alert_event SQL 失败")?
                .get(0);
            Ok(id)
        })
        .context("insert_alert_event")
    }

    /// 按 id 倒序（最新在前）分页列出事件；`before_id` 是排他游标。
    ///
    /// `limit == 0` 返回空列表，避免上层把 0 当成「无限制」。
    pub fn list_alert_events(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let cursor = before_id;
        let mut sql = format!("SELECT {ALERT_EVENT_COLUMNS} FROM alert_events");
        if cursor.is_some() {
            sql.push_str(" WHERE id < $1");
        }
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        sql.push_str(&format!(
            " ORDER BY id DESC LIMIT ${}",
            if cursor.is_some() { 2 } else { 1 }
        ));
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        if let Some(cursor) = cursor.as_ref() {
            params.push(cursor);
        }
        params.push(&limit_value);
        self.with_client(|client| {
            let rows = client
                .query(&sql, &params)
                .context("执行 list_alert_events SQL 失败")?;
            rows.iter().map(alert_event_from_row).collect()
        })
        .context("list_alert_events")
    }

    /// 清理告警事件：先按时间删 `ts < before_ts`，再按 id 从旧到新删到只剩
    /// `max_rows` 行。两步在同一事务内完成，返回删除总数；`max_rows == 0`
    /// 表示清空全部事件。
    pub fn prune_alert_events(&self, before_ts: i64, max_rows: usize) -> Result<usize> {
        let max_rows = i64::try_from(max_rows).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 prune_alert_events 事务失败")?;
            let mut removed = tx
                .execute("DELETE FROM alert_events WHERE ts < $1", &[&before_ts])
                .context("按时间清理告警事件失败")?;
            let remaining: i64 = tx
                .query_one("SELECT COUNT(*)::BIGINT FROM alert_events", &[])
                .context("统计剩余告警事件失败")?
                .get(0);
            if remaining > max_rows {
                let excess = remaining - max_rows;
                removed += tx
                    .execute(
                        "DELETE FROM alert_events WHERE id IN ( \
                             SELECT id FROM alert_events ORDER BY id ASC LIMIT $1 \
                         )",
                        &[&excess],
                    )
                    .context("按上限清理告警事件失败")?;
            }
            tx.commit().context("提交 prune_alert_events 事务失败")?;
            Ok(usize::try_from(removed).unwrap_or(usize::MAX))
        })
        .context("prune_alert_events")
    }

    /// 创建一条静默，返回自增 id；`silence.id` 被忽略。
    ///
    /// 同一事务内检查生效中数量：达到 [`MAX_ALERT_SILENCES`] 返回
    /// [`AlertSilenceStoreError::LimitReached`]。生效判定以
    /// `silence.created_at` 为 now：`until_ts > created_at`。
    pub fn create_alert_silence(&self, silence: &AlertSilence) -> Result<i64> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 create_alert_silence 事务失败")?;
            lock_alert_config(&mut tx)?;
            let active: i64 = tx
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM alert_silences WHERE until_ts > $1",
                    &[&silence.created_at],
                )
                .context("统计生效中的静默数量失败")?
                .get(0);
            if active >= MAX_ALERT_SILENCES as i64 {
                return Err(AlertSilenceStoreError::LimitReached.into());
            }
            let id: i64 = tx
                .query_one(
                    ALERT_SILENCE_INSERT_SQL,
                    &[
                        &silence.rule_id,
                        &silence.agent_id,
                        &silence.until_ts,
                        &silence.created_by,
                        &silence.created_at,
                    ],
                )
                .context("插入静默失败")?
                .get(0);
            tx.commit().context("提交 create_alert_silence 事务失败")?;
            Ok(id)
        })
        .context("create_alert_silence")
    }

    /// 列出 `now` 时刻仍生效的静默（`until_ts > now`），最新创建的在前。
    pub fn list_active_silences(&self, now: i64) -> Result<Vec<AlertSilence>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_SILENCE_COLUMNS} FROM alert_silences \
                 WHERE until_ts > $1 ORDER BY id DESC"
            );
            let rows = client
                .query(&sql, &[&now])
                .context("执行 list_active_silences SQL 失败")?;
            rows.iter().map(alert_silence_from_row).collect()
        })
        .context("list_active_silences")
    }

    /// 删除一条静默，返回 `false` 表示 id 不存在（API 映射 404）。
    pub fn delete_alert_silence(&self, id: i64) -> Result<bool> {
        self.with_client(|client| {
            let removed = client
                .execute("DELETE FROM alert_silences WHERE id = $1", &[&id])
                .context("执行 delete_alert_silence SQL 失败")?;
            Ok(removed > 0)
        })
        .context("delete_alert_silence")
    }

    /// 清理到期静默（`until_ts <= before_ts`），返回删除行数。
    pub fn prune_alert_silences(&self, before_ts: i64) -> Result<usize> {
        self.with_client(|client| {
            let removed = client
                .execute(
                    "DELETE FROM alert_silences WHERE until_ts <= $1",
                    &[&before_ts],
                )
                .context("执行 prune_alert_silences SQL 失败")?;
            Ok(usize::try_from(removed).unwrap_or(usize::MAX))
        })
        .context("prune_alert_silences")
    }

    /// 列出启用的规则（评估引擎使用）；排序与 [`Self::list_alert_rules`] 一致。
    pub fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRule>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_RULE_COLUMNS} FROM alert_rules WHERE enabled \
                 ORDER BY is_builtin DESC, name COLLATE \"C\" ASC"
            );
            let rows = client
                .query(&sql, &[])
                .context("执行 list_enabled_alert_rules SQL 失败")?;
            rows.iter().map(alert_rule_from_row).collect()
        })
        .context("list_enabled_alert_rules")
    }

    /// 按最近更新时间读取指定规则至多 `limit` 条状态。
    ///
    /// 排序为 `last_eval_at DESC, id DESC`；`limit == 0` 返回空列表。
    pub fn list_alert_states_for_rule(
        &self,
        rule_id: &str,
        limit: usize,
    ) -> Result<Vec<AlertState>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_STATE_COLUMNS} FROM alert_states WHERE rule_id = $1 \
                 ORDER BY last_eval_at DESC, id DESC LIMIT $2"
            );
            let rows = client
                .query(&sql, &[&rule_id, &limit_value])
                .context("执行 list_alert_states_for_rule SQL 失败")?;
            rows.iter().map(alert_state_from_row).collect()
        })
        .context("list_alert_states_for_rule")
    }

    /// 每规则只保留最近 `keep` 条状态，返回删除行数。
    ///
    /// 保留优先级：非 resolved 优先于 resolved，同类按 `last_eval_at` 新→旧，
    /// 相同时间按 `id` 新→旧。`keep == 0` 清空该规则全部状态。
    pub fn prune_alert_states_for_rule(&self, rule_id: &str, keep: usize) -> Result<usize> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 prune_alert_states_for_rule 事务失败")?;
            let removed = prune_alert_states_for_rule_in_tx(&mut tx, rule_id, keep)?;
            tx.commit()
                .context("提交 prune_alert_states_for_rule 事务失败")?;
            Ok(removed)
        })
        .context("prune_alert_states_for_rule")
    }

    /// 告警评估专用的 **raw-only** 最新序列查询。
    ///
    /// 语义：
    /// - 只查 `samples` 原始表，**不回退** 1m / 1h（旧桶不能当当前值）；
    /// - 只取 `ts >= since` 的样本；
    /// - `filter_labels` 是精确子集，SQL 侧用参数化
    ///   `labels::jsonb @> $n::jsonb` 下推（JSON 由 serde 生成），先过滤再做
    ///   `ROW_NUMBER` / 排序 / `LIMIT`，因此截断只作用于匹配的序列；
    /// - 每个 `(agent_id, labels)` 取 `ts` 最大的一行，同 `ts` 取 `id` 最大
    ///   （PG 没有 `rowid`，用 `samples.id DESC` 对齐 SQLite）；
    /// - `agent` 为 `Some` 时只查该 agent；
    /// - SQL 侧向数据库要 `limit + 1` 行：拿到 `limit + 1` 条就说明还有更多
    ///   序列，返回前 `limit` 条并置 `truncated = true`，**不返回
    ///   `QueryTooLarge`**；
    /// - `limit == 0` 返回空快照且 `truncated = true`。
    pub fn latest_alert_series(
        &self,
        metric: &str,
        since: i64,
        agent: Option<&str>,
        filter_labels: &Labels,
        limit: usize,
    ) -> Result<AlertSeriesSnapshot> {
        if limit == 0 {
            return Ok(AlertSeriesSnapshot {
                rows: Vec::new(),
                truncated: true,
            });
        }
        let row_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        // labels 列保持 SQLite 的 TEXT + serde_json 格式；只在查询时 cast 成
        // jsonb 做包含判断，不改写存储格式。空过滤不生成子句。
        let filter_json = (!filter_labels.is_empty())
            .then(|| serde_json::to_string(filter_labels))
            .transpose()
            .context("序列化 filter_labels 失败")?;
        let rows = self
            .with_client(|client| {
                let mut sql = String::from(
                    "SELECT agent_id, metric, labels, ts, value FROM ( \
                         SELECT agent_id, metric, labels, ts, value, \
                                ROW_NUMBER() OVER ( \
                                    PARTITION BY agent_id, labels ORDER BY ts DESC, id DESC \
                                ) AS rn \
                         FROM samples \
                         WHERE metric = $1 AND ts >= $2",
                );
                let mut params: Vec<&(dyn ToSql + Sync)> = vec![&metric, &since];
                if let Some(agent_id) = agent.as_ref() {
                    sql.push_str(&format!(" AND agent_id = ${}", params.len() + 1));
                    params.push(agent_id);
                }
                if let Some(filter_json) = filter_json.as_ref() {
                    sql.push_str(&format!(
                        " AND labels::jsonb @> ${}::jsonb",
                        params.len() + 1
                    ));
                    params.push(filter_json);
                }
                sql.push_str(&format!(
                    ") series WHERE rn = 1 \
                     ORDER BY agent_id COLLATE \"C\" ASC, labels COLLATE \"C\" ASC LIMIT ${}",
                    params.len() + 1
                ));
                params.push(&row_limit);
                let rows = client
                    .query(&sql, &params)
                    .context("执行 latest_alert_series SQL 失败")?;
                let mut series = Vec::with_capacity(rows.len());
                for row in &rows {
                    let labels_json: String = row.get(2);
                    series.push(AgentSeriesRow {
                        agent_id: row.get(0),
                        metric: row.get(1),
                        labels: serde_json::from_str(&labels_json).unwrap_or_default(),
                        ts: row.get(3),
                        value: row.get(4),
                    });
                }
                Ok(series)
            })
            .context("latest_alert_series")?;
        let truncated = rows.len() > limit;
        let mut rows = rows;
        if truncated {
            rows.truncate(limit);
        }
        Ok(AlertSeriesSnapshot { rows, truncated })
    }

    /// 单事务批量落库一条规则产生的全部事件与状态。
    ///
    /// - **事件先插入、状态后 upsert**：状态写失败时整事务回滚，下一轮重试；
    ///   不会出现「状态已推进、事件却没落库」的永久丢告警（at-least-once）；
    /// - 一条规则只取一次连接，避免上千序列逐条插入阻塞 ingest。
    pub fn apply_alert_transitions(
        &self,
        events: &[AlertEvent],
        states: &[AlertState],
    ) -> Result<()> {
        if events.is_empty() && states.is_empty() {
            return Ok(());
        }
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 apply_alert_transitions 事务失败")?;
            insert_alert_transitions(&mut tx, events, states)?;
            tx.commit()
                .context("提交 apply_alert_transitions 事务失败")?;
            Ok(())
        })
        .context("apply_alert_transitions")
    }

    /// 引擎单规则落库：事件 + 状态 + 每规则状态上限清理在同一事务内完成，
    /// 返回本事务淘汰的状态行数。
    pub fn apply_alert_evaluation(
        &self,
        rule_id: &str,
        events: &[AlertEvent],
        states: &[AlertState],
        keep_states: usize,
    ) -> Result<usize> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 apply_alert_evaluation 事务失败")?;
            insert_alert_transitions(&mut tx, events, states)?;
            let removed = prune_alert_states_for_rule_in_tx(&mut tx, rule_id, keep_states)?;
            tx.commit()
                .context("提交 apply_alert_evaluation 事务失败")?;
            Ok(removed)
        })
        .context("apply_alert_evaluation")
    }

    /// 当前最大告警事件 id；没有事件时返回 0。
    pub fn max_alert_event_id(&self) -> Result<i64> {
        self.with_client(|client| {
            let id: i64 = client
                .query_one(MAX_ALERT_EVENT_ID_SQL, &[])
                .context("执行 max_alert_event_id SQL 失败")?
                .get(0);
            Ok(id)
        })
        .context("max_alert_event_id")
    }

    /// 通知队列：只取 `id > after_id` 且未通知、未静默的事件，按 id 升序。
    pub fn list_pending_notification_events_after(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_EVENT_COLUMNS} FROM alert_events \
                 WHERE id > $1 AND notified = FALSE AND silenced = FALSE \
                 ORDER BY id ASC LIMIT $2"
            );
            let rows = client
                .query(&sql, &[&after_id, &limit_value])
                .context("执行 list_pending_notification_events_after SQL 失败")?;
            rows.iter().map(alert_event_from_row).collect()
        })
        .context("list_pending_notification_events_after")
    }

    /// 把事件标记为「已处理」并保留固定原因（`no_channel` / `cooldown` 等）。
    ///
    /// 原因由调用方保证已脱敏，存储层再做一次 UTF-8 字节截断；返回 `false`
    /// 表示事件 id 不存在。
    pub fn mark_notification_processed(&self, id: i64, notify_error: &str) -> Result<bool> {
        let stored_error = truncate_utf8(notify_error, MAX_ALERT_NOTIFY_ERROR_BYTES);
        self.with_client(|client| {
            let updated = client
                .execute(
                    "UPDATE alert_events SET notified = TRUE, notify_error = $2 WHERE id = $1",
                    &[&id, &stored_error],
                )
                .context("执行 mark_notification_processed SQL 失败")?;
            Ok(updated > 0)
        })
        .context("mark_notification_processed")
    }

    /// 通知队列：未通知且未静默的事件，按 id 升序（先发生先发）。
    pub fn list_pending_notification_events(&self, limit: usize) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let sql = format!(
                "SELECT {ALERT_EVENT_COLUMNS} FROM alert_events \
                 WHERE notified = FALSE AND silenced = FALSE ORDER BY id ASC LIMIT $1"
            );
            let rows = client
                .query(&sql, &[&limit_value])
                .context("执行 list_pending_notification_events SQL 失败")?;
            rows.iter().map(alert_event_from_row).collect()
        })
        .context("list_pending_notification_events")
    }

    /// 记录一次通知结果：成功时 `notified = true` 且清空错误信息；失败保留
    /// 错误摘要（最多 512 字节）。返回 `false` 表示事件 id 不存在。
    pub fn mark_notification_result(
        &self,
        id: i64,
        notified: bool,
        notify_error: &str,
    ) -> Result<bool> {
        let stored_error = if notified {
            String::new()
        } else {
            truncate_utf8(notify_error, MAX_ALERT_NOTIFY_ERROR_BYTES)
        };
        self.with_client(|client| {
            let updated = client
                .execute(
                    "UPDATE alert_events SET notified = $2, notify_error = $3 WHERE id = $1",
                    &[&id, &notified, &stored_error],
                )
                .context("执行 mark_notification_result SQL 失败")?;
            Ok(updated > 0)
        })
        .context("mark_notification_result")
    }

    /// 只更新状态的 `last_notified_at`，不整行覆盖。
    ///
    /// 返回 `false` 表示状态已被清理（规则禁用 / 删除或保留期清理）。
    pub fn update_alert_state_notified(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: i64,
    ) -> Result<bool> {
        self.with_client(|client| {
            let updated = client
                .execute(
                    "UPDATE alert_states SET last_notified_at = $4 \
                     WHERE rule_id = $1 AND agent_id = $2 AND series_key = $3",
                    &[&rule_id, &agent_id, &series_key, &last_notified_at],
                )
                .context("执行 update_alert_state_notified SQL 失败")?;
            Ok(updated > 0)
        })
        .context("update_alert_state_notified")
    }

    // ---- 通知渠道（schema v7 `notification_channels`） ----

    /// 列出全部通知渠道，按名称升序（名称 UNIQUE，顺序稳定）。
    ///
    /// 返回完整 [`NotificationChannel`]（含 secret），只允许 hub 内部使用；
    /// API 响应必须走 `ChannelView`。
    pub fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {NOTIFICATION_CHANNEL_COLUMNS} FROM notification_channels \
                 ORDER BY name COLLATE \"C\" ASC"
            );
            let rows = client
                .query(&sql, &[])
                .context("执行 list_notification_channels SQL 失败")?;
            rows.iter().map(notification_channel_from_row).collect()
        })
        .context("list_notification_channels")
    }

    /// 按 id 读取一条渠道；不存在返回 `None`。
    pub fn get_notification_channel(&self, id: &str) -> Result<Option<NotificationChannel>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {NOTIFICATION_CHANNEL_COLUMNS} FROM notification_channels WHERE id = $1"
            );
            let row = client
                .query_opt(&sql, &[&id])
                .context("执行 get_notification_channel SQL 失败")?;
            row.as_ref().map(notification_channel_from_row).transpose()
        })
        .context("get_notification_channel")
    }

    /// 渠道总数（供上限检查与面板统计）。
    pub fn notification_channel_count(&self) -> Result<usize> {
        self.with_client(|client| {
            let count: i64 = client
                .query_one("SELECT COUNT(*)::BIGINT FROM notification_channels", &[])
                .context("执行 notification_channel_count SQL 失败")?
                .get(0);
            Ok(usize::try_from(count).unwrap_or(0))
        })
        .context("notification_channel_count")
    }

    /// 新建一条渠道。
    ///
    /// 事务内先查总数与名称，再写入；并发下仍由 `name UNIQUE` 兜底：
    /// - 达到 [`MAX_NOTIFICATION_CHANNELS`] → [`ChannelStoreError::LimitReached`]；
    /// - 名称重复 → [`ChannelStoreError::NameExists`]；
    /// - `kind` 与 `config.kind` 不一致或字段非法 → [`ChannelStoreError::Invalid`]。
    pub fn create_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        channel
            .validate()
            .map_err(|_| ChannelStoreError::Invalid("通知渠道配置不合法"))?;
        let config_json =
            serde_json::to_string(&channel.config).context("序列化通知渠道配置失败")?;
        let kind = channel.kind.as_str();
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 create_notification_channel 事务失败")?;
            lock_alert_config(&mut tx)?;
            let count: i64 = tx
                .query_one("SELECT COUNT(*)::BIGINT FROM notification_channels", &[])
                .context("统计通知渠道数量失败")?
                .get(0);
            if count >= MAX_NOTIFICATION_CHANNELS as i64 {
                return Err(ChannelStoreError::LimitReached.into());
            }
            let name_exists = tx
                .query_opt(
                    "SELECT 1 FROM notification_channels WHERE name = $1",
                    &[&channel.name],
                )
                .context("检查通知渠道名称是否重复失败")?
                .is_some();
            if name_exists {
                return Err(ChannelStoreError::NameExists.into());
            }
            if let Err(err) = tx.execute(
                "INSERT INTO notification_channels \
                 (id, name, kind, config_json, enabled, updated_by, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &channel.id,
                    &channel.name,
                    &kind,
                    &config_json,
                    &channel.enabled,
                    &channel.updated_by,
                    &channel.created_at,
                    &channel.updated_at,
                ],
            ) {
                return Err(map_notification_channel_write_error(err));
            }
            tx.commit()
                .context("提交 create_notification_channel 事务失败")?;
            Ok(())
        })
        .context("create_notification_channel")
    }

    /// 更新一条渠道的可写字段；`created_at` 保持数据库原值。
    ///
    /// - 不存在 → [`ChannelStoreError::NotFound`]；
    /// - 改成与其它渠道重名 → [`ChannelStoreError::NameExists`]；
    /// - `kind` / `config.kind` 不一致或配置非法 → [`ChannelStoreError::Invalid`]。
    ///
    /// secret 保留语义由调用方用 `ChannelConfigInput::resolve` 完成，存储层只
    /// 接收合并后的完整配置。
    pub fn update_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        channel
            .validate()
            .map_err(|_| ChannelStoreError::Invalid("通知渠道配置不合法"))?;
        let config_json =
            serde_json::to_string(&channel.config).context("序列化通知渠道配置失败")?;
        let kind = channel.kind.as_str();
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 update_notification_channel 事务失败")?;
            lock_alert_config(&mut tx)?;
            let exists = tx
                .query_opt(
                    "SELECT 1 FROM notification_channels WHERE id = $1",
                    &[&channel.id],
                )
                .context("检查通知渠道是否存在失败")?
                .is_some();
            if !exists {
                return Err(ChannelStoreError::NotFound.into());
            }
            let name_exists = tx
                .query_opt(
                    "SELECT 1 FROM notification_channels WHERE name = $1 AND id <> $2",
                    &[&channel.name, &channel.id],
                )
                .context("检查通知渠道名称是否冲突失败")?
                .is_some();
            if name_exists {
                return Err(ChannelStoreError::NameExists.into());
            }
            if let Err(err) = tx.execute(
                "UPDATE notification_channels SET name = $2, kind = $3, config_json = $4, \
                 enabled = $5, updated_by = $6, updated_at = $7 WHERE id = $1",
                &[
                    &channel.id,
                    &channel.name,
                    &kind,
                    &config_json,
                    &channel.enabled,
                    &channel.updated_by,
                    &channel.updated_at,
                ],
            ) {
                return Err(map_notification_channel_write_error(err));
            }
            tx.commit()
                .context("提交 update_notification_channel 事务失败")?;
            Ok(())
        })
        .context("update_notification_channel")
    }

    /// 删除一条渠道；仍被 `alert_rules.channel_ids` 引用时返回
    /// [`ChannelStoreError::InUse`]，绝不留下悬空引用。
    ///
    /// 引用检查与 DELETE 在同一事务内完成，并持配置 advisory lock，避免检查
    /// 通过后另一条规则写入引用造成竞态。`channel_ids` 是 JSON 数组，损坏时
    /// 返回错误而不是放行删除。
    pub fn delete_notification_channel(&self, id: &str) -> Result<()> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 delete_notification_channel 事务失败")?;
            lock_alert_config(&mut tx)?;
            let exists = tx
                .query_opt("SELECT 1 FROM notification_channels WHERE id = $1", &[&id])
                .context("检查通知渠道是否存在失败")?
                .is_some();
            if !exists {
                return Err(ChannelStoreError::NotFound.into());
            }
            let rows = tx
                .query("SELECT id, channel_ids FROM alert_rules", &[])
                .context("读取告警规则渠道引用失败")?;
            for row in &rows {
                let rule_id: String = row.get(0);
                let channel_ids: String = row.get(1);
                let ids: Vec<String> = serde_json::from_str(&channel_ids).with_context(|| {
                    format!("告警规则 {rule_id} 的 channel_ids 损坏，拒绝删除渠道")
                })?;
                if ids.iter().any(|channel_id| channel_id == id) {
                    return Err(ChannelStoreError::InUse.into());
                }
            }
            tx.execute("DELETE FROM notification_channels WHERE id = $1", &[&id])
                .context("删除通知渠道失败")?;
            tx.commit()
                .context("提交 delete_notification_channel 事务失败")?;
            Ok(())
        })
        .context("delete_notification_channel")
    }
}

/// 在告警配置写事务内取 advisory lock。
fn lock_alert_config(tx: &mut Transaction<'_>) -> Result<()> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&ALERT_CONFIG_LOCK_KEY],
    )
    .context("获取告警配置 advisory lock 失败")?;
    Ok(())
}

/// PG 唯一约束冲突是否由指定约束触发。
///
/// 只匹配约束名，避免把主键冲突（例如重复规则 id）误判成 NameExists；
/// 与 SQLite 按 `alert_rules.name` 错误串匹配的粒度一致。
fn is_unique_violation_on(err: &postgres::Error, constraint: &str) -> bool {
    err.as_db_error().is_some_and(|db| {
        db.code() == &SqlState::UNIQUE_VIOLATION && db.constraint() == Some(constraint)
    })
}

/// 把规则写入的 UNIQUE 冲突翻译成领域错误，其它数据库错误不吞、不泄漏 SQL。
fn map_alert_rule_write_error(err: postgres::Error) -> anyhow::Error {
    if is_unique_violation_on(&err, "alert_rules_name_key") {
        return AlertRuleStoreError::NameExists.into();
    }
    tracing::debug!(error = %err, "写入告警规则失败（非名称唯一约束错误）");
    anyhow!("写入告警规则失败（数据库错误，详见日志）")
}

/// 内置规则种子写入失败：名称被其它规则占用必须显式报错，不能静默跳过。
fn map_seed_alert_rule_error(err: postgres::Error, rule_id: &str) -> anyhow::Error {
    if is_unique_violation_on(&err, "alert_rules_name_key") {
        return anyhow!(
            "内置告警规则 {rule_id} 的名称已被其它规则占用；\
             请先重命名冲突规则再启动 hub"
        );
    }
    tracing::debug!(error = %err, rule_id = %rule_id, "写入内置告警规则种子失败（非名称唯一冲突）");
    anyhow!("写入内置告警规则 {rule_id} 失败（数据库错误详见日志）")
}

/// 把通知渠道写入的 UNIQUE 冲突翻译成领域错误，其它数据库错误不吞。
fn map_notification_channel_write_error(err: postgres::Error) -> anyhow::Error {
    if is_unique_violation_on(&err, "notification_channels_name_key") {
        return ChannelStoreError::NameExists.into();
    }
    tracing::debug!(error = %err, "写入通知渠道失败（非名称唯一约束错误）");
    anyhow!("写入通知渠道失败（数据库错误，详见日志）")
}

/// 一行 `alert_rules` 映射成 [`AlertRule`]；列顺序必须与
/// [`ALERT_RULE_COLUMNS`] 一致。
fn alert_rule_from_row(row: &Row) -> Result<AlertRule> {
    let enabled: bool = row.get(2);
    let source_raw: String = row.get(3);
    let comparator_raw: String = row.get(5);
    let duration_raw: i64 = row.get(7);
    let cooldown_raw: i64 = row.get(8);
    let filter_labels_raw: String = row.get(10);
    let channel_ids_raw: String = row.get(11);
    let notify_on_resolve: bool = row.get(12);
    let is_builtin: bool = row.get(13);
    let source =
        AlertSource::parse(&source_raw).ok_or_else(|| anyhow!("alert_rules.source 字段值非法"))?;
    let comparator = Comparator::parse(&comparator_raw)
        .ok_or_else(|| anyhow!("alert_rules.comparator 字段值非法"))?;
    let duration_secs = u32::try_from(duration_raw)
        .map_err(|_| anyhow!("alert_rules.duration_secs 超出 u32 范围"))?;
    let cooldown_secs = u32::try_from(cooldown_raw)
        .map_err(|_| anyhow!("alert_rules.cooldown_secs 超出 u32 范围"))?;
    let filter_labels: Labels = serde_json::from_str(&filter_labels_raw)
        .map_err(|_| anyhow!("alert_rules.filter_labels 字段值非法"))?;
    let channel_ids: Vec<String> = serde_json::from_str(&channel_ids_raw)
        .map_err(|_| anyhow!("alert_rules.channel_ids 字段值非法"))?;
    Ok(AlertRule {
        id: row.get(0),
        name: row.get(1),
        enabled,
        source,
        metric: row.get(4),
        comparator,
        threshold: row.get(6),
        duration_secs,
        cooldown_secs,
        filter_agent_id: row.get(9),
        filter_labels,
        channel_ids,
        notify_on_resolve,
        is_builtin,
        updated_by: row.get(14),
        created_at: row.get(15),
        updated_at: row.get(16),
    })
}

/// 一行 `alert_states` 映射成 [`AlertState`]。
fn alert_state_from_row(row: &Row) -> Result<AlertState> {
    let state_raw: String = row.get(3);
    let state = AlertStateKind::parse(&state_raw)
        .ok_or_else(|| anyhow!("alert_states.state 字段值非法"))?;
    Ok(AlertState {
        rule_id: row.get(0),
        agent_id: row.get(1),
        series_key: row.get(2),
        state,
        since: row.get(4),
        last_eval_at: row.get(5),
        last_value: row.get(6),
        last_notified_at: row.get(7),
    })
}

/// 一行 `alert_events` 映射成 [`AlertEvent`]；`state` 只允许 firing / resolved。
fn alert_event_from_row(row: &Row) -> Result<AlertEvent> {
    let state_raw: String = row.get(6);
    let state = AlertStateKind::parse(&state_raw)
        .filter(|state| state.is_event())
        .ok_or_else(|| anyhow!("alert_events.state 字段值非法"))?;
    let notified: bool = row.get(9);
    let silenced: bool = row.get(11);
    Ok(AlertEvent {
        id: row.get(0),
        ts: row.get(1),
        rule_id: row.get(2),
        rule_name: row.get(3),
        agent_id: row.get(4),
        series_key: row.get(5),
        state,
        value: row.get(7),
        message: row.get(8),
        notified,
        notify_error: row.get(10),
        silenced,
    })
}

/// 一行 `alert_silences` 映射成 [`AlertSilence`]。
fn alert_silence_from_row(row: &Row) -> Result<AlertSilence> {
    Ok(AlertSilence {
        id: row.get(0),
        rule_id: row.get(1),
        agent_id: row.get(2),
        until_ts: row.get(3),
        created_by: row.get(4),
        created_at: row.get(5),
    })
}

/// 一行 `notification_channels` 映射成 [`NotificationChannel`]。
///
/// `kind` 列与 `config_json.kind` 必须一致；任何一侧非法都返回明确错误，不把
/// 损坏的行静默降级成默认渠道。
fn notification_channel_from_row(row: &Row) -> Result<NotificationChannel> {
    let kind_raw: String = row.get(2);
    let kind = ChannelKind::parse(&kind_raw)
        .ok_or_else(|| anyhow!("notification_channels.kind 字段值非法"))?;
    let config_json: String = row.get(3);
    let config: ChannelConfig = serde_json::from_str(&config_json)
        .map_err(|_| anyhow!("notification_channels.config_json 字段值非法"))?;
    if config.kind() != kind {
        return Err(anyhow!("notification_channels.kind 字段值非法"));
    }
    let enabled: bool = row.get(4);
    Ok(NotificationChannel {
        id: row.get(0),
        name: row.get(1),
        kind,
        config,
        enabled,
        updated_by: row.get(5),
        created_at: row.get(6),
        updated_at: row.get(7),
    })
}

/// 在既有事务内插入事件、upsert 状态；事件先于状态。
fn insert_alert_transitions(
    tx: &mut Transaction<'_>,
    events: &[AlertEvent],
    states: &[AlertState],
) -> Result<()> {
    if !events.is_empty() {
        let insert = tx
            .prepare(ALERT_EVENT_INSERT_SQL)
            .context("准备 alert_events 插入语句失败")?;
        for event in events {
            let state_kind = event.state.as_str();
            tx.execute(
                &insert,
                &[
                    &event.ts,
                    &event.rule_id,
                    &event.rule_name,
                    &event.agent_id,
                    &event.series_key,
                    &state_kind,
                    &event.value,
                    &event.message,
                    &event.notified,
                    &event.notify_error,
                    &event.silenced,
                ],
            )
            .context("插入告警事件失败")?;
        }
    }
    if !states.is_empty() {
        let upsert = tx
            .prepare(ALERT_STATE_UPSERT_SQL)
            .context("准备 alert_states upsert 语句失败")?;
        for state in states {
            let state_kind = state.state.as_str();
            tx.execute(
                &upsert,
                &[
                    &state.rule_id,
                    &state.agent_id,
                    &state.series_key,
                    &state_kind,
                    &state.since,
                    &state.last_eval_at,
                    &state.last_value,
                    &state.last_notified_at,
                ],
            )
            .context("写入告警状态失败")?;
        }
    }
    Ok(())
}

/// 在既有事务内做每规则状态裁剪，返回删除行数。
fn prune_alert_states_for_rule_in_tx(
    tx: &mut Transaction<'_>,
    rule_id: &str,
    keep: usize,
) -> Result<usize> {
    let keep = i64::try_from(keep).unwrap_or(i64::MAX);
    let removed = tx
        .execute(ALERT_STATE_PRUNE_FOR_RULE_SQL, &[&rule_id, &keep])
        .context("清理告警规则状态失败")?;
    Ok(usize::try_from(removed).unwrap_or(usize::MAX))
}

/// 按 UTF-8 字符边界截断到 `max_bytes`，与 SQLite 的 `truncate_utf8` 一致。
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    //! 告警域 PostgreSQL 实库测试。
    //!
    //! 未设置 `RUSTBOARD_TEST_PG` 时全部用例打印 `SKIP` 后返回（cargo 记为
    //! passed，但日志明确标注未执行）。设置后每个用例创建独立的
    //! `rb_d3_alerts_<tag>_...` 数据库，结束时 `DROP DATABASE ... WITH (FORCE)`，
    //! 因此可以并行执行、互不污染。DSN 必须显式 `sslmode=disable`。
    //!
    //! 测试只通过 [`PostgresStorage`] 的固有方法访问存储；`samples` 的测试数据
    //! 直接经 `with_client` 写入，避免依赖并行开发的 Core 域方法。

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use postgres::config::SslMode;
    use postgres::NoTls;
    use rustboard_common::model::Labels;

    use super::*;
    use crate::alerts::{
        builtin_rules, AlertEvent, AlertRule, AlertState, AlertStateKind, BUILTIN_AGENT_OFFLINE,
        BUILTIN_DISK_PERCENT,
    };
    use crate::channels::{ChannelConfig, ChannelKind, Secret};
    use crate::storage::postgres::{PostgresOptions, PostgresStorage};

    /// 实库测试 DSN 的环境变量。
    const PG_ENV: &str = "RUSTBOARD_TEST_PG";

    /// 同一纳秒内并发建库时避免撞名。
    static DB_SEQ: AtomicU64 = AtomicU64::new(0);

    fn skip(test_name: &str) {
        eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（告警域 PG 实库测试需要 PostgreSQL）");
    }

    /// 一个临时测试数据库；`Drop` 时用维护库连接强制删除。
    struct TestPg {
        name: String,
        /// 指向 `postgres` 维护库。
        admin: postgres::Config,
        /// 指向测试库、保留原始 query（sslmode=disable）。
        dsn: String,
    }

    impl TestPg {
        fn create(tag: &str) -> Option<Self> {
            let dsn = std::env::var(PG_ENV).ok()?;
            if dsn.trim().is_empty() {
                return None;
            }
            let base: postgres::Config = dsn
                .parse()
                .unwrap_or_else(|err| panic!("{PG_ENV} 解析失败：{err}"));
            assert_eq!(
                base.get_ssl_mode(),
                SslMode::Disable,
                "{PG_ENV} 必须显式 sslmode=disable（测试库是本地/受信内网）"
            );
            let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let name = format!("rb_d3_alerts_{tag}_{}_{nanos}_{seq}", std::process::id());
            assert!(
                name.len() <= 63,
                "测试库名超过 PostgreSQL 标识符上限：{name}"
            );
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "测试库名只允许小写字母/数字/下划线：{name}"
            );

            let mut admin = base.clone();
            admin.dbname("postgres");
            let mut client = admin
                .connect(NoTls)
                .unwrap_or_else(|err| panic!("连接 postgres 维护库失败（检查 {PG_ENV}）：{err}"));
            client
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .unwrap_or_else(|err| {
                    panic!("CREATE DATABASE {name} 失败（角色需要 CREATEDB 权限）：{err}")
                });
            drop(client);

            let dsn = replace_database(&dsn, &name);
            eprintln!("[d3-alerts] 创建测试数据库 {name}（tag={tag}）");
            Some(Self { name, admin, dsn })
        }

        fn open(&self) -> PostgresStorage {
            let storage = PostgresStorage::open(PostgresOptions {
                dsn: self.dsn.clone(),
                pool_size: 2,
                connect_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(30),
                sslrootcert: None,
            })
            .expect("打开 PostgreSQL 测试库失败");
            storage.apply_schema().expect("应用 PostgreSQL schema 失败");
            storage
        }
    }

    impl Drop for TestPg {
        fn drop(&mut self) {
            let mut client = match self.admin.connect(NoTls) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "[d3-alerts] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{err}",
                        self.name
                    );
                    return;
                }
            };
            if let Err(err) = client.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            )) {
                eprintln!(
                    "[d3-alerts] 清理失败：DROP DATABASE {} 出错（请手工清理）：{err}",
                    self.name
                );
            }
        }
    }

    /// 把 URL 形式的 DSN 的数据库名替换成 `dbname`，保留 query。
    fn replace_database(dsn: &str, dbname: &str) -> String {
        let (base, query) = match dsn.split_once('?') {
            Some((base, query)) => (base, Some(query)),
            None => (dsn, None),
        };
        let slash = base
            .rfind('/')
            .expect("RUSTBOARD_TEST_PG 必须包含数据库名（postgres://user@host/db）");
        let prefix = &base[..slash];
        match query {
            Some(query) => format!("{prefix}/{dbname}?{query}"),
            None => format!("{prefix}/{dbname}"),
        }
    }

    /// 一条合法的自定义规则；测试按需覆盖字段。
    fn custom_rule(id: &str, name: &str) -> AlertRule {
        AlertRule {
            id: id.to_string(),
            name: name.to_string(),
            enabled: true,
            source: AlertSource::Metric,
            metric: "cpu.usage".to_string(),
            comparator: Comparator::Gt,
            threshold: 80.0,
            duration_secs: 0,
            cooldown_secs: 60,
            filter_agent_id: None,
            filter_labels: Labels::new(),
            channel_ids: Vec::new(),
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "tester".to_string(),
            created_at: 1_000,
            updated_at: 2_000,
        }
    }

    /// 一条告警状态；`value` 为 `None` 时模拟非有限值。
    fn state(
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        kind: AlertStateKind,
        since: i64,
        last_eval_at: i64,
        value: Option<f64>,
    ) -> AlertState {
        AlertState {
            rule_id: rule_id.to_string(),
            agent_id: agent_id.to_string(),
            series_key: series_key.to_string(),
            state: kind,
            since,
            last_eval_at,
            last_value: value,
            last_notified_at: None,
        }
    }

    /// 一条告警事件；`id` 由存储层生成。
    fn event(
        ts: i64,
        rule_id: &str,
        kind: AlertStateKind,
        notified: bool,
        silenced: bool,
        message: &str,
    ) -> AlertEvent {
        AlertEvent {
            id: 0,
            ts,
            rule_id: rule_id.to_string(),
            rule_name: "测试规则".to_string(),
            agent_id: "agent-1".to_string(),
            series_key: "cpu{host=a}".to_string(),
            state: kind,
            value: Some(1.0),
            message: message.to_string(),
            notified,
            notify_error: String::new(),
            silenced,
        }
    }

    /// 一条合法的企业微信渠道。
    fn channel(id: &str, name: &str) -> NotificationChannel {
        NotificationChannel {
            id: id.to_string(),
            name: name.to_string(),
            kind: ChannelKind::Wecom,
            config: ChannelConfig::Wecom {
                webhook_key: Secret::new("webhook-key-for-tests"),
            },
            enabled: true,
            updated_by: "tester".to_string(),
            created_at: 1_000,
            updated_at: 2_000,
        }
    }

    /// 向 `samples` 写一条 raw 样本；避免依赖并行开发的 Core 域方法。
    fn insert_sample(storage: &PostgresStorage, agent: &str, labels: &str, ts: i64, value: f64) {
        storage
            .with_client(|client| {
                client
                    .execute(
                        "INSERT INTO samples (agent_id, metric, labels, ts, value) \
                         VALUES ($1, $2, $3, $4, $5)",
                        &[&agent, &"cpu.usage", &labels, &ts, &value],
                    )
                    .context("插入测试采样失败")?;
                Ok(())
            })
            .expect("插入测试采样失败");
    }

    #[test]
    fn seed_builtin_rules_is_idempotent_and_keeps_user_edits() {
        const NAME: &str = "seed_builtin_rules_is_idempotent_and_keeps_user_edits";
        let Some(db) = TestPg::create("seed") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let now = 1_700_000_000_000i64;
        let rules = builtin_rules(now, 300, 72);
        assert_eq!(
            storage.seed_builtin_alert_rules(&rules, now).unwrap(),
            rules.len()
        );
        assert_eq!(storage.alert_rule_count().unwrap(), rules.len());

        let mut edited = storage
            .get_alert_rule(BUILTIN_DISK_PERCENT)
            .unwrap()
            .unwrap();
        assert!(!edited.enabled, "内置规则初始应禁用");
        edited.enabled = true;
        edited.threshold = 42.5;
        edited.updated_at = now + 1;
        edited.updated_by = "ops".to_string();
        storage.update_alert_rule(&edited).unwrap();

        assert_eq!(
            storage.seed_builtin_alert_rules(&rules, now + 2).unwrap(),
            0,
            "重复 seed 必须幂等"
        );
        let reloaded = storage
            .get_alert_rule(BUILTIN_DISK_PERCENT)
            .unwrap()
            .unwrap();
        assert!(reloaded.enabled, "seed 不得覆盖用户启停");
        assert_eq!(reloaded.threshold, 42.5);
        assert_eq!(reloaded.updated_at, now + 1);

        let offline = storage
            .get_alert_rule(BUILTIN_AGENT_OFFLINE)
            .unwrap()
            .unwrap();
        assert!(offline.is_builtin);
        assert!(offline.notify_on_resolve);
        assert!(!offline.enabled);

        storage
            .create_alert_rule(&custom_rule("custom-order", "自定义规则"))
            .unwrap();
        let listed = storage.list_alert_rules().unwrap();
        assert_eq!(listed.len(), rules.len() + 1);
        assert!(listed[..rules.len()].iter().all(|rule| rule.is_builtin));
        assert!(!listed.last().unwrap().is_builtin);

        let enabled = storage.list_enabled_alert_rules().unwrap();
        assert!(enabled.iter().all(|rule| rule.enabled));
        assert!(enabled.iter().any(|rule| rule.id == BUILTIN_DISK_PERCENT));
        assert!(enabled.iter().any(|rule| rule.id == "custom-order"));
        assert!(!enabled.iter().any(|rule| rule.id == BUILTIN_AGENT_OFFLINE));
    }

    #[test]
    fn seed_name_conflict_fails_whole_batch_and_rolls_back() {
        const NAME: &str = "seed_name_conflict_fails_whole_batch_and_rolls_back";
        let Some(db) = TestPg::create("seed_conflict") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let now = 1_700_000_000_000i64;
        // 与最后一条内置规则同名：前四条即使先插入，也必须随整批回滚。
        storage
            .create_alert_rule(&custom_rule("custom-conflict", "缓冲积压"))
            .unwrap();
        let err = storage
            .seed_builtin_alert_rules(&builtin_rules(now, 300, 72), now)
            .expect_err("名称冲突必须让整批种子失败");
        let message = format!("{err:#}");
        assert!(
            message.contains("名称已被其它规则占用"),
            "错误信息应指出名称冲突：{message}"
        );
        assert_eq!(
            storage.alert_rule_count().unwrap(),
            1,
            "冲突必须回滚整批种子，不能留下半批"
        );
        for id in [BUILTIN_AGENT_OFFLINE, BUILTIN_DISK_PERCENT] {
            assert!(
                storage.get_alert_rule(id).unwrap().is_none(),
                "冲突后不得留下半批种子：{id}"
            );
        }
    }

    #[test]
    fn alert_rule_crud_maps_domain_errors_and_booleans() {
        const NAME: &str = "alert_rule_crud_maps_domain_errors_and_booleans";
        let Some(db) = TestPg::create("rules") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let mut rule = custom_rule("rule-1", "自定义规则");
        rule.enabled = true;
        rule.notify_on_resolve = false;
        rule.filter_agent_id = Some("agent-1".to_string());
        rule.filter_labels
            .insert("host".to_string(), "web-1".to_string());
        rule.channel_ids = vec!["chan-a".to_string()];
        storage.create_alert_rule(&rule).unwrap();

        let loaded = storage.get_alert_rule("rule-1").unwrap().unwrap();
        assert_eq!(loaded, rule);
        assert!(loaded.enabled);
        assert!(!loaded.notify_on_resolve);
        assert!(!loaded.is_builtin);
        assert_eq!(
            loaded.filter_labels.get("host").map(String::as_str),
            Some("web-1")
        );
        assert_eq!(loaded.channel_ids, vec!["chan-a".to_string()]);
        assert_eq!(storage.alert_rule_count().unwrap(), 1);

        let err = storage
            .create_alert_rule(&custom_rule("rule-2", "自定义规则"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::NameExists),
            "并发唯一冲突必须映射成领域错误：{err:#}"
        );

        let err = storage
            .update_alert_rule(&custom_rule("missing", "不存在"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::NotFound)
        );

        storage
            .create_alert_rule(&custom_rule("rule-2", "规则二"))
            .unwrap();
        let mut renamed = loaded.clone();
        renamed.name = "规则二".to_string();
        let err = storage.update_alert_rule(&renamed).unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::NameExists)
        );

        let mut builtin_like = custom_rule("rule-builtin", "内置样规则");
        builtin_like.is_builtin = true;
        storage.create_alert_rule(&builtin_like).unwrap();
        let err = storage.delete_alert_rule("rule-builtin").unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::BuiltinRule)
        );
        let err = storage.delete_alert_rule("missing").unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::NotFound)
        );

        storage
            .upsert_alert_state(&state(
                "rule-1",
                "agent-1",
                "cpu{host=a}",
                AlertStateKind::Firing,
                1,
                1,
                Some(1.0),
            ))
            .unwrap();
        let mut disabled = loaded.clone();
        disabled.enabled = false;
        disabled.updated_at = 9_999;
        storage
            .update_alert_rule_and_clear_states(&disabled)
            .unwrap();
        assert!(storage
            .get_alert_state("rule-1", "agent-1", "cpu{host=a}")
            .unwrap()
            .is_none());
        let after = storage.get_alert_rule("rule-1").unwrap().unwrap();
        assert!(!after.enabled);
        assert_eq!(after.created_at, loaded.created_at);
        assert_eq!(after.is_builtin, loaded.is_builtin);

        storage
            .upsert_alert_state(&state(
                "rule-1",
                "agent-1",
                "cpu{host=a}",
                AlertStateKind::Firing,
                2,
                2,
                None,
            ))
            .unwrap();
        storage
            .delete_alert_rule_and_clear_states("rule-1")
            .unwrap();
        assert!(storage.get_alert_rule("rule-1").unwrap().is_none());
        assert!(storage
            .get_alert_state("rule-1", "agent-1", "cpu{host=a}")
            .unwrap()
            .is_none());
    }

    #[test]
    fn alert_states_upsert_prune_and_per_rule_cap() {
        const NAME: &str = "alert_states_upsert_prune_and_per_rule_cap";
        let Some(db) = TestPg::create("states") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let rule = "rule-state";
        storage
            .create_alert_rule(&custom_rule(rule, "状态规则"))
            .unwrap();

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-1",
                "cpu{host=a}",
                AlertStateKind::Firing,
                1_000,
                1_000,
                Some(90.0),
            ))
            .unwrap();
        let loaded = storage
            .get_alert_state(rule, "agent-1", "cpu{host=a}")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, AlertStateKind::Firing);
        assert_eq!(loaded.last_value, Some(90.0));

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-1",
                "cpu{host=a}",
                AlertStateKind::Resolved,
                2_000,
                2_000,
                None,
            ))
            .unwrap();
        let loaded = storage
            .get_alert_state(rule, "agent-1", "cpu{host=a}")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.state, AlertStateKind::Resolved);
        assert_eq!(loaded.since, 2_000);
        assert_eq!(loaded.last_value, None);

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-2",
                "cpu{host=b}",
                AlertStateKind::Pending,
                3_000,
                3_000,
                Some(1.0),
            ))
            .unwrap();
        let all = storage.list_alert_states().unwrap();
        assert_eq!(
            all.iter()
                .map(|state| state.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["agent-1", "agent-2"]
        );

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-old",
                "k",
                AlertStateKind::Resolved,
                100,
                100,
                None,
            ))
            .unwrap();
        assert_eq!(
            storage.prune_alert_states(2_000).unwrap(),
            1,
            "只删 last_eval_at 严格早于边界的 resolved"
        );
        assert!(storage
            .get_alert_state(rule, "agent-1", "cpu{host=a}")
            .unwrap()
            .is_some());
        assert!(storage
            .get_alert_state(rule, "agent-old", "k")
            .unwrap()
            .is_none());

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-old-1",
                "k1",
                AlertStateKind::Firing,
                50,
                50,
                None,
            ))
            .unwrap();
        storage
            .upsert_alert_state(&state(
                rule,
                "agent-old-2",
                "k2",
                AlertStateKind::Pending,
                60,
                60,
                None,
            ))
            .unwrap();
        assert_eq!(storage.list_alert_states().unwrap().len(), 4);
        assert_eq!(storage.prune_stale_alert_states(1_000, 1).unwrap(), 1);
        assert_eq!(storage.list_alert_states().unwrap().len(), 3);
        assert_eq!(storage.prune_stale_alert_states(1_000, 10).unwrap(), 1);
        assert_eq!(storage.prune_stale_alert_states(1_000, 10).unwrap(), 0);

        let recent = storage.list_alert_states_for_rule(rule, 1).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].agent_id, "agent-2");
        assert!(storage
            .list_alert_states_for_rule(rule, 0)
            .unwrap()
            .is_empty());

        let events = vec![event(
            5_000,
            rule,
            AlertStateKind::Firing,
            false,
            false,
            "触发",
        )];
        let states = vec![
            state(
                rule,
                "agent-eval-1",
                "k1",
                AlertStateKind::Firing,
                5_000,
                5_000,
                Some(1.0),
            ),
            state(
                rule,
                "agent-eval-2",
                "k2",
                AlertStateKind::Firing,
                5_001,
                5_001,
                Some(2.0),
            ),
            state(
                rule,
                "agent-eval-3",
                "k3",
                AlertStateKind::Firing,
                5_002,
                5_002,
                Some(3.0),
            ),
        ];
        assert_eq!(
            storage
                .apply_alert_evaluation(rule, &events, &states, 2)
                .unwrap(),
            3
        );
        let kept = storage.list_alert_states_for_rule(rule, 10).unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept
            .iter()
            .all(|state| state.agent_id.starts_with("agent-eval")));
        assert!(storage
            .list_alert_events(10, None)
            .unwrap()
            .iter()
            .any(|event| event.ts == 5_000));

        storage
            .apply_alert_transitions(
                &[event(
                    6_000,
                    rule,
                    AlertStateKind::Firing,
                    false,
                    false,
                    "tx",
                )],
                &[state(
                    rule,
                    "agent-tx",
                    "k",
                    AlertStateKind::Firing,
                    6_000,
                    6_000,
                    Some(1.5),
                )],
            )
            .unwrap();
        assert!(storage
            .get_alert_state(rule, "agent-tx", "k")
            .unwrap()
            .is_some());
        storage.apply_alert_transitions(&[], &[]).unwrap();

        assert_eq!(
            storage.delete_alert_state(rule, "agent-tx", "k").unwrap(),
            1
        );
        assert_eq!(
            storage.delete_alert_state(rule, "agent-tx", "k").unwrap(),
            0
        );

        // 保留优先级：非 resolved 优先于 resolved，即使 resolved 更新。
        let priority_rule = "rule-priority";
        storage
            .create_alert_rule(&custom_rule(priority_rule, "优先级规则"))
            .unwrap();
        storage
            .upsert_alert_state(&state(
                priority_rule,
                "agent-resolved",
                "r",
                AlertStateKind::Resolved,
                9_000,
                9_000,
                None,
            ))
            .unwrap();
        storage
            .upsert_alert_state(&state(
                priority_rule,
                "agent-firing",
                "f",
                AlertStateKind::Firing,
                8_000,
                8_000,
                None,
            ))
            .unwrap();
        assert_eq!(
            storage
                .prune_alert_states_for_rule(priority_rule, 1)
                .unwrap(),
            1
        );
        let priority_left = storage
            .list_alert_states_for_rule(priority_rule, 10)
            .unwrap();
        assert_eq!(priority_left.len(), 1);
        assert_eq!(priority_left[0].agent_id, "agent-firing");
        assert_eq!(priority_left[0].state, AlertStateKind::Firing);

        // keep == 0 清空该规则全部状态。
        assert_eq!(storage.prune_alert_states_for_rule(rule, 0).unwrap(), 2);
        assert!(storage
            .list_alert_states_for_rule(rule, 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn alert_events_pagination_pending_cursor_and_prune() {
        const NAME: &str = "alert_events_pagination_pending_cursor_and_prune";
        let Some(db) = TestPg::create("events") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let rule = "rule-event";
        storage
            .create_alert_rule(&custom_rule(rule, "事件规则"))
            .unwrap();
        assert_eq!(storage.max_alert_event_id().unwrap(), 0);

        let first = storage
            .insert_alert_event(&event(
                100,
                rule,
                AlertStateKind::Firing,
                false,
                false,
                "e1",
            ))
            .unwrap();
        let second = storage
            .insert_alert_event(&event(
                200,
                rule,
                AlertStateKind::Resolved,
                false,
                true,
                "e2",
            ))
            .unwrap();
        let third = storage
            .insert_alert_event(&event(300, rule, AlertStateKind::Firing, true, false, "e3"))
            .unwrap();
        let fourth = storage
            .insert_alert_event(&event(
                400,
                rule,
                AlertStateKind::Resolved,
                false,
                false,
                "e4",
            ))
            .unwrap();
        assert!(first < second && second < third && third < fourth);
        assert_eq!(storage.max_alert_event_id().unwrap(), fourth);
        assert!(storage.list_alert_events(0, None).unwrap().is_empty());

        let page = storage.list_alert_events(2, None).unwrap();
        assert_eq!(
            page.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );
        let page = storage.list_alert_events(2, Some(fourth)).unwrap();
        assert_eq!(
            page.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![third, second]
        );

        let all = storage.list_alert_events(10, None).unwrap();
        let by_id = |id: i64| all.iter().find(|event| event.id == id).unwrap().clone();
        assert!(by_id(third).notified);
        assert!(!by_id(third).silenced);
        assert!(by_id(second).silenced);
        assert!(!by_id(second).notified);

        let pending = storage.list_pending_notification_events(10).unwrap();
        assert_eq!(
            pending.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![first, fourth],
            "已通知 / 已静默的事件不能进入待通知队列"
        );
        assert!(storage
            .list_pending_notification_events(0)
            .unwrap()
            .is_empty());
        let after = storage
            .list_pending_notification_events_after(first, 10)
            .unwrap();
        assert_eq!(
            after.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![fourth]
        );
        assert!(storage
            .list_pending_notification_events_after(fourth, 10)
            .unwrap()
            .is_empty());

        assert!(storage
            .mark_notification_processed(fourth, "no_channel")
            .unwrap());
        assert!(!storage.mark_notification_processed(999_999, "x").unwrap());
        let processed = storage
            .list_alert_events(10, None)
            .unwrap()
            .into_iter()
            .find(|event| event.id == fourth)
            .unwrap();
        assert!(processed.notified);
        assert_eq!(processed.notify_error, "no_channel");
        assert!(storage
            .list_pending_notification_events(10)
            .unwrap()
            .iter()
            .all(|event| event.id != fourth));

        assert!(storage
            .mark_notification_result(first, true, "should-be-cleared")
            .unwrap());
        let success = storage
            .list_alert_events(10, None)
            .unwrap()
            .into_iter()
            .find(|event| event.id == first)
            .unwrap();
        assert!(success.notified);
        assert_eq!(success.notify_error, "");

        // 多字节错误摘要按 UTF-8 边界截断到 512 字节（每个汉字 3 字节）。
        let long_error = "错".repeat(400);
        assert!(storage
            .mark_notification_result(second, false, &long_error)
            .unwrap());
        let failed = storage
            .list_alert_events(10, None)
            .unwrap()
            .into_iter()
            .find(|event| event.id == second)
            .unwrap();
        assert!(!failed.notified);
        assert_eq!(failed.notify_error.len(), 510);

        storage
            .upsert_alert_state(&state(
                rule,
                "agent-n",
                "k",
                AlertStateKind::Firing,
                1,
                1,
                None,
            ))
            .unwrap();
        assert!(storage
            .update_alert_state_notified(rule, "agent-n", "k", 12_345)
            .unwrap());
        assert_eq!(
            storage
                .get_alert_state(rule, "agent-n", "k")
                .unwrap()
                .unwrap()
                .last_notified_at,
            Some(12_345)
        );
        assert!(!storage
            .update_alert_state_notified(rule, "agent-n", "missing", 1)
            .unwrap());

        // ts < 250 删除 first/second；再按 max_rows=1 从旧到新删掉 third。
        assert_eq!(storage.prune_alert_events(250, 1).unwrap(), 3);
        let remaining = storage.list_alert_events(10, None).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, fourth);
    }

    #[test]
    fn alert_silences_active_expiry_and_delete() {
        const NAME: &str = "alert_silences_active_expiry_and_delete";
        let Some(db) = TestPg::create("silences") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let now = 1_000_000i64;
        let active = AlertSilence {
            id: 0,
            rule_id: Some("rule-1".to_string()),
            agent_id: None,
            until_ts: now + 1_000,
            created_by: "admin".to_string(),
            created_at: now,
        };
        let active_id = storage.create_alert_silence(&active).unwrap();
        assert!(active_id > 0, "静默 id 必须由数据库生成");

        let expired = AlertSilence {
            id: 999,
            rule_id: None,
            agent_id: Some("agent-1".to_string()),
            until_ts: now,
            created_by: "admin".to_string(),
            created_at: now - 10,
        };
        let expired_id = storage.create_alert_silence(&expired).unwrap();
        assert!(expired_id > active_id);

        let listed = storage.list_active_silences(now).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, active_id);
        assert_eq!(listed[0].rule_id.as_deref(), Some("rule-1"));
        assert!(listed[0].agent_id.is_none());
        assert!(
            storage
                .list_active_silences(now + 1_000)
                .unwrap()
                .is_empty(),
            "until_ts == now 不生效（严格大于）"
        );

        assert!(storage.delete_alert_silence(active_id).unwrap());
        assert!(!storage.delete_alert_silence(active_id).unwrap());

        assert_eq!(storage.prune_alert_silences(now).unwrap(), 1);
        assert_eq!(storage.prune_alert_silences(now).unwrap(), 0);
    }

    #[test]
    fn notification_channels_crud_boolean_and_reference_guard() {
        const NAME: &str = "notification_channels_crud_boolean_and_reference_guard";
        let Some(db) = TestPg::create("channels") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        let channel_one = channel("chan-1", "渠道一");
        storage.create_notification_channel(&channel_one).unwrap();
        assert_eq!(storage.notification_channel_count().unwrap(), 1);
        let loaded = storage.get_notification_channel("chan-1").unwrap().unwrap();
        assert_eq!(loaded, channel_one);
        assert!(loaded.enabled);
        assert_eq!(
            storage.list_notification_channels().unwrap(),
            vec![loaded.clone()]
        );

        let err = storage
            .create_notification_channel(&channel("chan-2", "渠道一"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::NameExists)
        );

        let err = storage
            .update_notification_channel(&channel("missing", "渠道X"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::NotFound)
        );

        let channel_two = channel("chan-2", "渠道二");
        storage.create_notification_channel(&channel_two).unwrap();
        let mut renamed = loaded.clone();
        renamed.name = "渠道二".to_string();
        let err = storage.update_notification_channel(&renamed).unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::NameExists)
        );

        let mut updated = loaded.clone();
        updated.name = "渠道一改".to_string();
        updated.enabled = false;
        updated.updated_by = "ops".to_string();
        updated.updated_at = 9_999;
        updated.created_at = 1;
        storage.update_notification_channel(&updated).unwrap();
        let reloaded = storage.get_notification_channel("chan-1").unwrap().unwrap();
        assert!(!reloaded.enabled, "enabled 必须按 BOOLEAN 读回");
        assert_eq!(reloaded.name, "渠道一改");
        assert_eq!(
            reloaded.created_at, channel_one.created_at,
            "更新不得改写 created_at"
        );

        let mut invalid = channel("chan-bad", "坏渠道");
        invalid.kind = ChannelKind::Telegram;
        let err = storage.create_notification_channel(&invalid).unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::Invalid("通知渠道配置不合法"))
        );

        let mut rule = custom_rule("rule-chan", "引用渠道");
        rule.channel_ids = vec!["chan-1".to_string()];
        storage.create_alert_rule(&rule).unwrap();
        let err = storage.delete_notification_channel("chan-1").unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::InUse),
            "被规则引用的渠道不能删除：{err:#}"
        );
        assert!(storage
            .get_notification_channel("chan-1")
            .unwrap()
            .is_some());

        storage.delete_notification_channel("chan-2").unwrap();
        let err = storage.delete_notification_channel("chan-2").unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::NotFound)
        );
    }

    #[test]
    fn latest_alert_series_uses_id_desc_for_same_ts_and_truncates() {
        const NAME: &str = "latest_alert_series_uses_id_desc_for_same_ts_and_truncates";
        let Some(db) = TestPg::create("series") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        // 同一序列、同一 ts 的两次上报：id 更大的（后写入）必须胜出。
        insert_sample(&storage, "agent-a", r#"{"host":"a"}"#, 100, 1.0);
        insert_sample(&storage, "agent-a", r#"{"host":"a"}"#, 100, 2.0);
        insert_sample(&storage, "agent-a", r#"{"host":"b"}"#, 90, 5.0);
        insert_sample(&storage, "agent-b", r#"{"host":"a"}"#, 80, 7.0);

        let snapshot = storage
            .latest_alert_series("cpu.usage", 0, None, &Labels::new(), 10)
            .unwrap();
        assert!(!snapshot.truncated);
        assert_eq!(
            snapshot
                .rows
                .iter()
                .map(|row| (row.agent_id.as_str(), row.ts))
                .collect::<Vec<_>>(),
            vec![("agent-a", 100), ("agent-a", 90), ("agent-b", 80)],
            "按 (agent_id, labels) 做 C 字节序排序"
        );
        assert_eq!(
            snapshot.rows[0].value, 2.0,
            "同 ts 必须取 samples.id 更大的后写入值"
        );
        assert_eq!(
            snapshot.rows[0].labels.get("host").map(String::as_str),
            Some("a")
        );

        let scoped = storage
            .latest_alert_series("cpu.usage", 0, Some("agent-a"), &Labels::new(), 10)
            .unwrap();
        assert_eq!(scoped.rows.len(), 2);
        assert!(scoped.rows.iter().all(|row| row.agent_id == "agent-a"));

        let truncated = storage
            .latest_alert_series("cpu.usage", 0, None, &Labels::new(), 2)
            .unwrap();
        assert!(truncated.truncated);
        assert_eq!(truncated.rows.len(), 2);

        let empty = storage
            .latest_alert_series("cpu.usage", 0, None, &Labels::new(), 0)
            .unwrap();
        assert!(empty.truncated);
        assert!(empty.rows.is_empty());

        let windowed = storage
            .latest_alert_series("cpu.usage", 95, None, &Labels::new(), 10)
            .unwrap();
        assert_eq!(windowed.rows.len(), 1);
        assert_eq!(windowed.rows[0].agent_id, "agent-a");

        // 标签过滤在 LIMIT 之前生效：host=b 只匹配 1 条序列。
        let mut host_b = Labels::new();
        host_b.insert("host".into(), "b".into());
        let filtered = storage
            .latest_alert_series("cpu.usage", 0, None, &host_b, 1)
            .unwrap();
        assert!(!filtered.truncated);
        assert_eq!(filtered.rows.len(), 1);
        assert_eq!(
            filtered.rows[0].labels.get("host").map(String::as_str),
            Some("b")
        );

        // 多标签 / 无匹配 / 特殊键都走参数化 JSONB 包含判断。
        let mut multi = host_b.clone();
        multi.insert("__proto__".into(), "x".into());
        let no_match = storage
            .latest_alert_series("cpu.usage", 0, None, &multi, 10)
            .unwrap();
        assert!(!no_match.truncated);
        assert!(no_match.rows.is_empty());

        let missing = storage
            .latest_alert_series("disk.used_percent", 0, None, &Labels::new(), 10)
            .unwrap();
        assert!(!missing.truncated);
        assert!(missing.rows.is_empty());
    }

    #[test]
    fn alert_limits_map_to_domain_errors() {
        const NAME: &str = "alert_limits_map_to_domain_errors";
        let Some(db) = TestPg::create("limits") else {
            skip(NAME);
            return;
        };
        let storage = db.open();
        // 直接用 SQL 把三张表填到上限，避免几百次往返；上限检查发生在读取
        // 这些行之前，内容不参与校验。
        storage
            .with_client(|client| {
                client
                    .batch_execute(
                        "INSERT INTO alert_rules (id, name, is_builtin, created_at, updated_at) \
                         SELECT 'bulk-rule-' || g, '批量规则 ' || g, FALSE, 0, 0 \
                         FROM generate_series(1, 200) AS g; \
                         INSERT INTO notification_channels \
                             (id, name, kind, config_json, enabled, created_at, updated_at) \
                         SELECT 'bulk-chan-' || g, '批量渠道 ' || g, 'wecom', \
                                '{\"kind\":\"wecom\",\"webhook_key\":\"webhook-key-bulk\"}', \
                                TRUE, 0, 0 \
                         FROM generate_series(1, 50) AS g; \
                         INSERT INTO alert_silences \
                             (rule_id, agent_id, until_ts, created_by, created_at) \
                         SELECT NULL, NULL, 1000, 'bulk', 0 \
                         FROM generate_series(1, 1000) AS g",
                    )
                    .context("填充告警上限测试数据失败")?;
                Ok(())
            })
            .unwrap();

        let err = storage
            .create_alert_rule(&custom_rule("limit-rule", "超限规则"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertRuleStoreError>(),
            Some(&AlertRuleStoreError::LimitReached)
        );

        let err = storage
            .create_notification_channel(&channel("limit-chan", "超限渠道"))
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<ChannelStoreError>(),
            Some(&ChannelStoreError::LimitReached)
        );

        let silence = AlertSilence {
            id: 0,
            rule_id: None,
            agent_id: None,
            until_ts: 1_000,
            created_by: "admin".to_string(),
            created_at: 0,
        };
        let err = storage.create_alert_silence(&silence).unwrap_err();
        assert_eq!(
            err.downcast_ref::<AlertSilenceStoreError>(),
            Some(&AlertSilenceStoreError::LimitReached)
        );
    }
}
