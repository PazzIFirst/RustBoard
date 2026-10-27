//! 活跃会话注册表。
//!
//! 同一个 agent 允许同时存在多条连接（例如重连风暴期间旧连接还没完全断开）。
//! 注册表按 `agent_id -> {conn_id -> 取消信号}` 保存全部活跃连接：
//!
//! - 只有最后一条连接注销时才执行状态回调（`unregister_last_and_run`），调用方
//!   据此把状态置为 offline；因此旧连接关闭不会覆盖新连接，也不会在仍有连接时误判离线。
//! - 状态回调在 per-agent slot 锁内执行：同一 agent 的新连接 `register` 要拿同一把
//!   slot 锁，因此它会等这次单行写库完成后才插入连接，调用方随后写 online。
//!   「旧 offline」不可能落在「新 online」之后。
//! - 控制能力（KI-24）随连接保存：只有**最新连接**（`conn_id` 最大）的 Hello 才写库，
//!   旧连接晚到的 Hello 只更新自己；最新连接断开且仍有剩余连接时，回退到剩余连接中
//!   已登记的能力；最后一条连接断开时保留历史能力，不做能力写入。
//! - `shutdown` / `reconfigure` 对该 agent 的全部连接发取消信号，传播不依赖
//!   「哪条是最新连接」。
//!
//! 锁顺序固定为 **全局 map → per-agent slot**：
//!
//! 1. 先锁全局 map，取出 `Arc<AgentSlot>`（必要时创建），**立即释放全局锁**；
//! 2. 再锁 slot 做连接表的增删查。
//!
//! 全局 map 锁不会跨数据库写入；持有 slot 锁时禁止调用会再次获取全局 map 锁的
//! 方法（例如 `active_agents` / 其它 agent 上的操作），否则就是反向获取。
//!
//! 关闭原因用 [`ShutdownReason`] 区分：吊销（Revoke）回 `revoked` Problem，
//! 采样间隔变更（Reconfigure）回 WebSocket `Close(1000)` 正常关闭，让 agent
//! 立即重连并拿到新的 Welcome。两者都不改变「最后一条连接才 offline」的语义。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};

use crate::control::{ControlCommand, CONTROL_COMMAND_BUFFER};

/// 活跃连接注册表。通过 `Arc` 在会话任务与吊销轮询任务之间共享。
///
/// 两级结构：
/// - `inner`：`agent_id -> Arc<AgentSlot>`，只在查找 / 创建 slot 时短暂持有；
/// - `AgentSlot`：每个 agent 一把锁，保护该 agent 的连接表与状态回调临界区。
pub struct SessionRegistry {
    inner: Mutex<HashMap<String, Arc<AgentSlot>>>,
    next_conn_id: AtomicU64,
}

/// 单个 agent 的连接槽。
///
/// 连接清空后 slot 仍保留在全局 map 里（agent 数量有界）：删除 slot 会引入
/// 「刚删完又被 register 创建」的 ABA 竞态，而保留空 slot 没有这个问题。
/// 所有查询都按「空 slot 等于不在线」处理。
pub(crate) struct AgentSlot {
    state: Mutex<SlotState>,
    /// 串行化 `register` 与 blocking 线程上的会话清理。
    ///
    /// 旧实现让 cleanup 在 slot 锁内做 PG `is_revoked + set_status`；重连风暴时
    /// 新会话的 async `register` 会同步抢 slot 锁，把 tokio worker 卡在数据库
    /// 往返上。这把异步 gate 让 register 只 await（不阻塞 worker），cleanup 在
    /// blocking 线程上 `blocking_lock` 后再进入 slot 锁做原有的短临界区写入。
    cleanup_gate: AsyncMutex<()>,
}

/// slot 锁保护的状态：该 agent 当前的全部连接。
struct SlotState {
    connections: HashMap<u64, ConnectionEntry>,
}

/// 单条连接持有的信号：关闭原因 + 控制命令队列 + 已登记的控制能力。
struct ConnectionEntry {
    shutdown: watch::Sender<ShutdownReason>,
    /// M3：管理 API 通过它把控制命令投递给该连接所属的会话任务。
    control: mpsc::Sender<ControlCommand>,
    /// KI-24：该连接 Hello 上报并清洗后的能力。
    ///
    /// `None` 表示这条连接**尚未登记** Hello 能力（刚 `register`，Hello 还在路上）；
    /// `Some(vec![])` 表示已登记且确实没有任何能力。两者语义不同：前者不能用来
    /// 回退写库，否则「新连接刚注册、旧连接断开」会误清空数据库里的历史能力。
    capabilities: Option<Vec<String>>,
}

/// 会话关闭原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// agent 已被吊销：会话回 `revoked` Problem 后关闭。
    Revoke,
    /// 配置变化（采样间隔）：回 `Close(1000)` 正常关闭，agent 随后重连。
    Reconfigure,
}

/// [`SessionRegistry::unregister_with_fallback`] 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnregisterOutcome {
    /// 连接不在注册表里（重复注销、未知 `conn_id` 或 agent 从未注册）。
    NotRegistered,
    /// 连接已注销，但它不是最新连接，未触发能力回退。
    Removed,
    /// 连接已注销；它是最新连接，且剩余连接里有已登记的能力，
    /// `on_latest_removed` 已收到该能力（回调内已尝试写库）。
    LatestRemoved,
    /// 连接已注销；它是最新连接，但剩余连接都没登记能力。
    /// 不写库，保留数据库里的历史能力。
    LatestRemovedWithoutFallback,
    /// 连接已注销且是该 agent 的最后一条连接，`on_empty` 已执行。
    Empty,
}

/// 一次注册的凭据：连接编号 + 取消信号接收端 + 控制命令接收端。
pub struct SessionHandle {
    pub conn_id: u64,
    pub shutdown: watch::Receiver<ShutdownReason>,
    /// 该连接专属的控制命令队列；会话循环 `select!` 从中取命令。
    pub control_rx: mpsc::Receiver<ControlCommand>,
}

impl AgentSlot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState {
                connections: HashMap::new(),
            }),
            cleanup_gate: AsyncMutex::new(()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        lock(&self.state)
    }

    /// async register 侧等待清理结束；只 await gate，不在 worker 上做 DB。
    pub(crate) async fn acquire_cleanup_gate(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.cleanup_gate.lock().await
    }

    /// blocking 清理侧取得同一把 gate；只能在 blocking 线程 / 非 async 上下文调用。
    pub(crate) fn acquire_cleanup_gate_blocking(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.cleanup_gate.blocking_lock()
    }
}

/// 取互斥锁；锁中毒说明之前的持有者 panic 过，但受保护的数据结构仍可继续使用。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
        })
    }

    fn lock_map(&self) -> MutexGuard<'_, HashMap<String, Arc<AgentSlot>>> {
        lock(&self.inner)
    }

    /// 取 agent 的 slot；不存在返回 `None`。返回时全局 map 锁已释放。
    fn agent_slot(&self, agent_id: &str) -> Option<Arc<AgentSlot>> {
        self.lock_map().get(agent_id).cloned()
    }

    /// 供 blocking 清理路径取得 per-agent gate；slot 不存在时返回 `None`。
    pub(crate) fn cleanup_slot(&self, agent_id: &str) -> Option<Arc<AgentSlot>> {
        self.agent_slot(agent_id)
    }

    /// 取 agent 的 slot，不存在则创建。返回时全局 map 锁已释放。
    fn agent_slot_or_create(&self, agent_id: &str) -> Arc<AgentSlot> {
        let mut inner = self.lock_map();
        inner
            .entry(agent_id.to_owned())
            .or_insert_with(|| Arc::new(AgentSlot::new()))
            .clone()
    }

    /// 注册一条新连接，返回连接编号与取消信号接收端。
    ///
    /// 锁顺序：先取 slot（释放全局 map 锁）→ await per-agent cleanup gate →
    /// 短暂持有 slot 锁插入连接。旧连接的清理在 blocking 线程持有 gate 并写
    /// offline/revoked；本函数只 await gate（不阻塞 tokio worker），等清理结束
    /// 才插入新连接。调用方随后写 online，因此新 online 一定晚于旧 offline。
    pub async fn register(&self, agent_id: &str) -> SessionHandle {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        // 初始值不会触发 `changed()`；真正的关闭原因只由 shutdown/reconfigure 写入。
        let (shutdown, receiver) = watch::channel(ShutdownReason::Revoke);
        // 容量 16：控制 API 自身限速 10/min，正常情况下队列不会堆积；
        // 堆积时 `try_send` 直接回 429，绝不阻塞会话的采集 / ACK 路径。
        let (control, control_rx) = mpsc::channel(CONTROL_COMMAND_BUFFER);

        let slot = self.agent_slot_or_create(agent_id);
        let _gate = slot.acquire_cleanup_gate().await;
        let active = {
            let mut state = slot.lock();
            state.connections.insert(
                conn_id,
                ConnectionEntry {
                    shutdown,
                    control,
                    // 注册时能力未知：Hello 能力由 `set_capabilities` 在握手时登记。
                    capabilities: None,
                },
            );
            state.connections.len()
        };
        tracing::debug!(agent = %agent_id, conn_id, active, "agent 会话已注册");
        SessionHandle {
            conn_id,
            shutdown: receiver,
            control_rx,
        }
    }

    /// 测试用同步入口：内部建 current-thread runtime 执行 [`Self::register`]。
    ///
    /// 仅在 `#[cfg(test)]` 且当前测试没有 tokio runtime 时使用；已有 runtime 的
    /// 异步测试应直接 `register(...).await`，避免嵌套 runtime。
    #[cfg(test)]
    pub(crate) fn register_blocking(&self, agent_id: &str) -> SessionHandle {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("测试 runtime 初始化失败")
            .block_on(self.register(agent_id))
    }

    /// 取该 agent **最新一条连接**的控制命令发送端。
    ///
    /// 重连风暴期间旧连接可能还没清理干净：控制命令只投给 conn_id 最大的那条，
    /// 避免把命令送给即将关闭的会话。agent 不在线（slot 不存在或已清空）时返回 `None`。
    pub fn control_sender(&self, agent_id: &str) -> Option<mpsc::Sender<ControlCommand>> {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        let slot = self.agent_slot(agent_id)?;
        let state = slot.lock();
        state
            .connections
            .iter()
            .max_by_key(|(conn_id, _)| **conn_id)
            .map(|(_, connection)| connection.control.clone())
    }

    /// 登记某条连接 Hello 上报的控制能力（KI-24）。
    ///
    /// 能力总是记录到该连接自己的 [`ConnectionEntry`]；只有它仍是该 agent 的
    /// **最新连接**（`conn_id` 最大）时才调用 `persist` 写库。`persist` 在 per-agent
    /// slot 锁内执行：`register` 与清理回调都要拿同一把锁，因此不存在
    /// 「旧连接读到自己是最大 → 新连接注册并写库 → 旧连接再写库」的覆盖窗口。
    ///
    /// 返回值：
    /// - `Ok(true)`：连接存在且是最新连接，`persist` 已成功执行；
    /// - `Ok(false)`：连接不存在，或它不是最新连接（能力只记录、不写库）；
    /// - `Err(_)`：最新连接的能力已记录，但 `persist` 写库失败；调用方应视为
    ///   握手失败并关闭会话（随后的清理回退会尝试恢复剩余连接的能力）。
    pub fn set_capabilities<F>(
        &self,
        agent_id: &str,
        conn_id: u64,
        capabilities: Vec<String>,
        persist: F,
    ) -> anyhow::Result<bool>
    where
        F: FnOnce(&[String]) -> anyhow::Result<()>,
    {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        let Some(slot) = self.agent_slot(agent_id) else {
            return Ok(false);
        };
        let mut state = slot.lock();
        let is_latest = state.connections.keys().max().copied() == Some(conn_id);
        let Some(entry) = state.connections.get_mut(&conn_id) else {
            return Ok(false);
        };
        entry.capabilities = Some(capabilities);
        if !is_latest {
            // 旧连接晚到的 Hello：记录到该连接即可，绝不覆盖最新连接的库值。
            return Ok(false);
        }
        let Some(capabilities) = entry.capabilities.as_deref() else {
            // 不可达：上面刚写入 `Some`；保守地按「未登记」处理，不写库。
            return Ok(false);
        };
        // 仍持有 slot 锁：新连接插不进来，旧写不可能落在新写之后。
        persist(capabilities)?;
        Ok(true)
    }

    /// 当前**最新连接**已登记的能力（KI-24）。
    ///
    /// 无连接、或最新连接尚未登记 Hello 能力时返回 `None`（不会用旧连接的能力
    /// 冒充最新连接）；已登记但没有任何能力时返回 `Some(vec![])`。
    ///
    /// 生产路径目前只登记能力（`set_capabilities`），查询由测试使用；保留公共入口
    /// 供后续管理面直接读内存态，避免为「查看能力」再查一次库。
    #[allow(dead_code)]
    pub fn latest_capabilities(&self, agent_id: &str) -> Option<Vec<String>> {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        let slot = self.agent_slot(agent_id)?;
        let state = slot.lock();
        state
            .connections
            .iter()
            .max_by_key(|(conn_id, _)| **conn_id)
            .and_then(|(_, entry)| entry.capabilities.clone())
    }

    /// 指定连接是否存在且是该 agent 的当前最新连接。
    ///
    /// 与 `latest_capabilities` 一样目前主要供测试断言；保留为公共查询入口。
    #[allow(dead_code)]
    pub fn is_latest(&self, agent_id: &str, conn_id: u64) -> bool {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        let Some(slot) = self.agent_slot(agent_id) else {
            return false;
        };
        let state = slot.lock();
        state.connections.contains_key(&conn_id)
            && state.connections.keys().max().copied() == Some(conn_id)
    }

    /// 注销连接，并在「这是该 agent 最后一条连接」时**在 slot 锁内**执行一次回调。
    ///
    /// 返回值：
    /// - `true`：连接存在且注销后该 agent 已无连接，`callback` 已执行一次；
    /// - `false`：连接不存在或仍有其他连接，`callback` 未执行。
    ///
    /// 回调在 slot 锁内运行，因此同一 agent 的 `register` 会等回调结束才插入新连接，
    /// 调用方随后写 online；旧连接的状态写入不可能覆盖新连接。回调必须是短临界区：
    /// **只做单行状态更新**，不得调用本注册表的任何方法（会破坏锁顺序），
    /// 也不得做网络 / 文件 I/O。
    pub fn unregister_last_and_run<F>(&self, agent_id: &str, conn_id: u64, callback: F) -> bool
    where
        F: FnOnce(),
    {
        // 兼容入口：不做能力回退，回调只在最后一条连接时执行（与旧语义一致）。
        self.unregister_with_fallback(agent_id, conn_id, callback, |_| {})
            == UnregisterOutcome::Empty
    }

    /// 注销连接，并按「是否最新连接」决定是否回退控制能力（KI-24）。
    ///
    /// - 已无剩余连接：在 slot 锁内执行 `on_empty`（现有 offline/revoked 原子逻辑），
    ///   不写能力，保留数据库里的最后能力作为历史；
    /// - 被移除的是最新连接且仍有剩余连接：取剩余连接中 `conn_id` 最大且已登记
    ///   能力的那条，在 slot 锁内执行 `on_latest_removed(&capabilities)`；剩余连接
    ///   都没登记能力时不写库；
    /// - 被移除的不是最新连接：不做任何能力写入。
    ///
    /// 两个回调都在 slot 锁内运行，必须是短临界区且**不得再调用本注册表**
    /// （会反向获取同一把锁而死锁）。`on_latest_removed` 的写库失败由调用方
    /// best-effort 处理，不影响连接清理本身。
    ///
    /// 生产清理路径由 [`SessionRegistry::cleanup_slot`] 先取得并持有 per-agent
    /// cleanup gate；本方法只保证 slot 锁内的原子性，不负责串行化 `register`。
    pub fn unregister_with_fallback<F, G>(
        &self,
        agent_id: &str,
        conn_id: u64,
        on_empty: F,
        on_latest_removed: G,
    ) -> UnregisterOutcome
    where
        F: FnOnce(),
        G: FnOnce(&[String]),
    {
        // 锁顺序：先取 slot（此时全局 map 锁已释放），再锁 slot。
        let Some(slot) = self.agent_slot(agent_id) else {
            return UnregisterOutcome::NotRegistered;
        };
        let mut state = slot.lock();
        if state.connections.remove(&conn_id).is_none() {
            return UnregisterOutcome::NotRegistered;
        }
        if state.connections.is_empty() {
            // 仍持有 slot 锁：新连接插不进来，直到回调写完状态。
            on_empty();
            return UnregisterOutcome::Empty;
        }
        // conn_id 全局递增：没有剩余连接的编号更大，才说明被移除的是最新连接。
        if state.connections.keys().any(|latest| *latest > conn_id) {
            return UnregisterOutcome::Removed;
        }
        // 剩余连接里 conn_id 最大、且已登记过能力的那条，才是应回退的能力来源。
        // 先克隆再回调，避免在回调期间继续借用连接表。
        let fallback = state
            .connections
            .iter()
            .filter_map(|(remaining_id, entry)| {
                entry
                    .capabilities
                    .as_ref()
                    .map(|capabilities| (*remaining_id, capabilities.clone()))
            })
            .max_by_key(|(remaining_id, _)| *remaining_id);
        match fallback {
            Some((_, capabilities)) => {
                on_latest_removed(&capabilities);
                UnregisterOutcome::LatestRemoved
            }
            None => UnregisterOutcome::LatestRemovedWithoutFallback,
        }
    }

    /// 注销连接：仅当这是该 agent 的**最后一条**连接时返回 `true`。
    ///
    /// 兼容方法，不执行状态回调；需要原子写 offline/revoked 的调用方应使用
    /// [`Self::unregister_last_and_run`]。
    ///
    /// 生产清理路径已改用 `unregister_last_and_run`，这里保留旧语义给测试与后续
    /// 调用方，属有意保留的兼容入口。
    #[allow(dead_code)]
    pub fn unregister(&self, agent_id: &str, conn_id: u64) -> bool {
        self.unregister_last_and_run(agent_id, conn_id, || {})
    }

    /// 取消某个 agent 的全部活跃连接（吊销语义）。连接不存在时返回 `false`。
    pub fn shutdown(&self, agent_id: &str) -> bool {
        self.signal(agent_id, ShutdownReason::Revoke)
    }

    /// 通知某个 agent 的全部活跃连接：采样间隔已变更，正常关闭后重连。
    ///
    /// 返回 `false` 表示当前没有活跃连接——配置已落库，下次 Welcome 自然生效。
    pub fn reconfigure(&self, agent_id: &str) -> bool {
        self.signal(agent_id, ShutdownReason::Reconfigure)
    }

    fn signal(&self, agent_id: &str, reason: ShutdownReason) -> bool {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        let Some(slot) = self.agent_slot(agent_id) else {
            return false;
        };
        let state = slot.lock();
        if state.connections.is_empty() {
            return false;
        }
        for connection in state.connections.values() {
            let _ = connection.shutdown.send(reason);
        }
        true
    }

    /// 批量取消（吊销轮询任务使用）。
    pub fn shutdown_all(&self, agent_ids: &[String]) {
        for agent_id in agent_ids {
            self.shutdown(agent_id);
        }
    }

    /// 当前是否还有该 agent 的活跃连接。
    pub fn has_active(&self, agent_id: &str) -> bool {
        // 锁顺序：先取 slot（释放全局 map 锁），再锁 slot。
        self.agent_slot(agent_id)
            .is_some_and(|slot| !slot.lock().connections.is_empty())
    }

    /// 当前注册表中的 agent_id 快照，供吊销轮询逐个检查。
    ///
    /// 空 slot（最后一条连接已注销但节点保留）必须被过滤掉。先拷贝 id 并释放全局
    /// map 锁，再逐个检查 slot，避免全局锁跨 slot 锁。
    pub fn active_agents(&self) -> Vec<String> {
        let agent_ids: Vec<String> = self.lock_map().keys().cloned().collect();
        agent_ids
            .into_iter()
            .filter(|agent_id| self.has_active(agent_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustboard_common::control::ControlOp;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn only_last_connection_marks_agent_offline() {
        let registry = SessionRegistry::new();
        let first = registry.register_blocking("a");
        let second = registry.register_blocking("a");
        assert_ne!(first.conn_id, second.conn_id);
        // 旧连接先断开：还有新连接，不能置 offline。
        assert!(!registry.unregister("a", first.conn_id));
        assert!(registry.active_agents().contains(&"a".to_string()));
        // 最后一条连接断开：可以置 offline。
        assert!(registry.unregister("a", second.conn_id));
        assert!(registry.active_agents().is_empty());
        // 重复注销不再返回 true。
        assert!(!registry.unregister("a", second.conn_id));
    }

    /// 回调只在「最后一条连接」注销时执行；旧 conn_id / 重复注销都不能触发。
    #[test]
    fn unregister_last_and_run_only_fires_for_last_connection() {
        let registry = SessionRegistry::new();
        let first = registry.register_blocking("a");
        let second = registry.register_blocking("a");
        let calls = Arc::new(AtomicUsize::new(0));

        let first_calls = calls.clone();
        assert!(
            !registry.unregister_last_and_run("a", first.conn_id, move || {
                first_calls.fetch_add(1, Ordering::SeqCst);
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0, "仍有连接时不得执行回调");

        // 旧 conn_id 重复注销：连接已不存在，回调也不得执行。
        let stale_calls = calls.clone();
        assert!(
            !registry.unregister_last_and_run("a", first.conn_id, move || {
                stale_calls.fetch_add(1, Ordering::SeqCst);
            })
        );

        let last_calls = calls.clone();
        assert!(
            registry.unregister_last_and_run("a", second.conn_id, move || {
                last_calls.fetch_add(1, Ordering::SeqCst);
            })
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "最后一条连接必须执行且只执行一次回调"
        );

        let repeat_calls = calls.clone();
        assert!(
            !registry.unregister_last_and_run("a", second.conn_id, move || {
                repeat_calls.fetch_add(1, Ordering::SeqCst);
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// #14 核心：旧清理回调停在 slot 锁内时，同一 agent 的新 register 必须等它
    /// 执行完才能完成；释放后连接表恢复活跃。
    #[test]
    fn cleanup_callback_blocks_register_until_it_returns() {
        let registry = SessionRegistry::new();
        let old = registry.register_blocking("a");
        let old_id = old.conn_id;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let callback_finished = Arc::new(AtomicBool::new(false));

        let cleanup_registry = registry.clone();
        let cleanup_finished = callback_finished.clone();
        let cleanup_thread = std::thread::spawn(move || {
            // 生产清理会先拿 per-agent cleanup gate；这里复现同一顺序。
            let slot = cleanup_registry.cleanup_slot("a").expect("slot 必须存在");
            let _gate = slot.acquire_cleanup_gate_blocking();
            cleanup_registry.unregister_last_and_run("a", old_id, || {
                entered_tx.send(()).expect("测试线程必须存活");
                release_rx.recv().expect("等待测试线程释放临界区");
                cleanup_finished.store(true, Ordering::SeqCst);
            })
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("旧连接清理必须进入回调（slot 锁已持有）");

        let (started_tx, started_rx) = mpsc::channel();
        let (registered_tx, registered_rx) = mpsc::channel();
        let register_registry = registry.clone();
        let register_observed = callback_finished.clone();
        let register_thread = std::thread::spawn(move || {
            started_tx.send(()).expect("测试线程必须存活");
            let handle = register_registry.register_blocking("a");
            registered_tx
                .send((handle.conn_id, register_observed.load(Ordering::SeqCst)))
                .expect("测试线程必须存活");
        });

        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("注册线程必须启动");
        assert!(
            registered_rx
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "旧清理回调持有 slot 锁期间，新 register 不得完成"
        );

        release_tx.send(()).expect("cleanup 线程必须存活");
        let (new_id, observed_finished) = registered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("释放临界区后 register 必须完成");
        assert!(
            observed_finished,
            "register 必须等清理回调执行完之后才插入连接"
        );
        assert!(cleanup_thread.join().expect("cleanup 线程不得 panic"));
        register_thread.join().expect("register 线程不得 panic");
        assert!(new_id > old_id);
        assert!(registry.has_active("a"));
    }

    /// 不同 agent 使用不同 slot 锁：一个 agent 的慢回调不能阻塞另一个 agent 的
    /// register（全局 map 锁不得跨 slot 锁 / 数据库写入）。
    #[test]
    fn cleanup_callback_on_one_agent_does_not_block_another() {
        let registry = SessionRegistry::new();
        let old = registry.register_blocking("slow");
        let old_id = old.conn_id;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let cleanup_registry = registry.clone();
        let cleanup_thread = std::thread::spawn(move || {
            cleanup_registry.unregister_last_and_run("slow", old_id, || {
                entered_tx.send(()).expect("测试线程必须存活");
                release_rx.recv().expect("等待测试线程释放临界区");
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("慢 agent 的清理必须进入回调");

        let (done_tx, done_rx) = mpsc::channel();
        let register_registry = registry.clone();
        let register_thread = std::thread::spawn(move || {
            let handle = register_registry.register_blocking("fast");
            done_tx.send(handle.conn_id).expect("测试线程必须存活");
        });
        let fast_id = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("不同 agent 的 register 不得被慢回调阻塞");
        register_thread.join().expect("register 线程不得 panic");
        assert!(registry.has_active("fast"));

        release_tx.send(()).expect("cleanup 线程必须存活");
        assert!(cleanup_thread.join().expect("cleanup 线程不得 panic"));
        assert!(!registry.has_active("slow"));
        assert!(registry.has_active("fast"));
        assert_eq!(fast_id, 1, "conn_id 保持全局递增");
    }

    /// 空 slot 保留但所有查询都按「不在线」处理；再次 register 仍能正常复用。
    #[test]
    fn empty_slot_is_hidden_and_reusable() {
        let registry = SessionRegistry::new();
        let first = registry.register_blocking("a");
        assert!(registry.unregister("a", first.conn_id));

        assert!(!registry.has_active("a"));
        assert!(registry.active_agents().is_empty());
        assert!(registry.control_sender("a").is_none());
        assert!(!registry.shutdown("a"));
        assert!(!registry.reconfigure("a"));

        let second = registry.register_blocking("a");
        assert!(second.conn_id > first.conn_id, "conn_id 必须继续递增");
        assert!(registry.has_active("a"));
        assert_eq!(registry.active_agents(), vec!["a".to_string()]);
        assert!(registry.shutdown("a"));
        assert_eq!(*second.shutdown.borrow(), ShutdownReason::Revoke);
    }

    #[test]
    fn shutdown_targets_every_connection_of_agent() {
        let registry = SessionRegistry::new();
        let first = registry.register_blocking("a");
        let second = registry.register_blocking("a");
        assert!(registry.shutdown("a"));
        assert_eq!(*first.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*second.shutdown.borrow(), ShutdownReason::Revoke);
        assert!(!registry.shutdown("missing"));
    }

    #[test]
    fn shutdown_all_covers_every_listed_agent() {
        let registry = SessionRegistry::new();
        let a = registry.register_blocking("a");
        let b = registry.register_blocking("b");
        registry.shutdown_all(&["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(*a.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*b.shutdown.borrow(), ShutdownReason::Revoke);
    }

    /// 吊销只影响目标 agent，其他 agent 的会话不能被误伤（issue #5）。
    #[test]
    fn shutdown_does_not_signal_other_agents() {
        let registry = SessionRegistry::new();
        let a = registry.register_blocking("a");
        let b = registry.register_blocking("b");

        assert!(registry.shutdown("a"));
        assert_eq!(*a.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*b.shutdown.borrow(), ShutdownReason::Revoke);
        assert!(registry.has_active("b"));
    }

    /// 重连后，旧连接迟到的注销不能把新连接从注册表里删掉。
    #[test]
    fn stale_conn_id_does_not_remove_replacement_connection() {
        let registry = SessionRegistry::new();
        let old = registry.register_blocking("a");
        assert!(registry.unregister("a", old.conn_id));

        let new = registry.register_blocking("a");
        assert_ne!(old.conn_id, new.conn_id);
        assert!(!registry.unregister("a", old.conn_id));
        assert!(registry.has_active("a"));

        // 新连接仍然能收到吊销信号。
        assert!(registry.shutdown("a"));
        assert_eq!(*new.shutdown.borrow(), ShutdownReason::Revoke);
    }

    /// cleanup gate 被持有时，register 只 await、不占 tokio worker；释放后正常插入。
    ///
    /// current-thread runtime 上若 register 同步抢 slot 锁/阻塞 worker，下面的
    /// `timeout` 无法按时返回；这里同时验证 release 后连接号递增。
    #[tokio::test]
    async fn register_awaits_cleanup_gate_without_blocking_runtime() {
        let registry = SessionRegistry::new();
        let old = registry.register("a").await;
        let slot = registry.cleanup_slot("a").expect("slot 必须存在");
        let gate = slot.acquire_cleanup_gate().await;

        let register_registry = registry.clone();
        let mut register = tokio::spawn(async move { register_registry.register("a").await });

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut register)
                .await
                .is_err(),
            "cleanup gate 持有期间 register 不得完成"
        );

        drop(gate);
        let handle = tokio::time::timeout(Duration::from_secs(1), register)
            .await
            .expect("释放 gate 后 register 必须完成")
            .expect("register 任务不得 panic");
        assert!(handle.conn_id > old.conn_id);
        assert!(registry.has_active("a"));
    }

    /// 会话循环用 `watch::Receiver::changed()` 等待吊销；这里验证信号真的能唤醒它。
    #[tokio::test]
    async fn shutdown_wakes_handle_waiting_for_signal() {
        let registry = SessionRegistry::new();
        let mut handle = registry.register("a").await;
        let waiter = tokio::spawn(async move {
            handle.shutdown.changed().await.ok();
            *handle.shutdown.borrow()
        });
        tokio::task::yield_now().await;

        assert!(registry.shutdown("a"));
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("shutdown 信号未在 1s 内送达")
            .unwrap();
        assert_eq!(received, ShutdownReason::Revoke);
    }

    /// M3：控制命令只投给最新连接；旧连接（即便还没注销）不能收到。
    #[test]
    fn control_sender_prefers_latest_connection() {
        let registry = SessionRegistry::new();
        let mut old = registry.register_blocking("a");
        let mut new = registry.register_blocking("a");

        // 先投一条：只有新连接能收到。
        let sender = registry
            .control_sender("a")
            .expect("在线 agent 应有控制发送端");
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        sender
            .try_send(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
                deadline: Instant::now() + Duration::from_secs(30),
            })
            .expect("新连接队列应可写");
        assert!(old.control_rx.try_recv().is_err(), "旧连接不得收到控制命令");
        let received = new.control_rx.try_recv().expect("最新连接应收到控制命令");
        assert_eq!(received.op, ControlOp::SystemdList);

        // 旧连接注销后，发送端仍然指向新连接。
        assert!(!registry.unregister("a", old.conn_id));
        assert!(registry.control_sender("a").is_some());
        assert!(registry.unregister("a", new.conn_id));
        assert!(
            registry.control_sender("a").is_none(),
            "最后一条连接注销后必须报告不在线"
        );
        assert!(registry.control_sender("missing").is_none());
    }

    /// 会话结束（接收端 drop）后 `try_send` 必须失败，API 据此回 agent_offline。
    #[test]
    fn closed_control_channel_is_reported_as_offline() {
        let registry = SessionRegistry::new();
        let handle = registry.register_blocking("a");
        let sender = registry.control_sender("a").expect("应取得发送端");
        drop(handle.control_rx);
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        assert!(
            sender
                .try_send(ControlCommand {
                    op: ControlOp::ProcessList,
                    reply,
                    deadline: Instant::now() + Duration::from_secs(30),
                })
                .is_err(),
            "会话结束后 try_send 必须失败"
        );
    }

    /// 配置变更走 Reconfigure，不能混成吊销；多连接都要收到。
    #[test]
    fn reconfigure_signals_every_connection_with_reconfigure() {
        let registry = SessionRegistry::new();
        let first = registry.register_blocking("a");
        let second = registry.register_blocking("a");
        let other = registry.register_blocking("b");

        assert!(registry.reconfigure("a"));
        assert_eq!(*first.shutdown.borrow(), ShutdownReason::Reconfigure);
        assert_eq!(*second.shutdown.borrow(), ShutdownReason::Reconfigure);
        assert_eq!(
            *other.shutdown.borrow(),
            ShutdownReason::Revoke,
            "初始值不得被误读为 Reconfigure，且不能影响其他 agent"
        );

        // 没有活跃连接时返回 false，但不影响已落库的配置。
        assert!(!registry.reconfigure("missing"));

        // 同一连接随后收到吊销，原因必须是 Revoke。
        assert!(registry.shutdown("a"));
        assert_eq!(*first.shutdown.borrow(), ShutdownReason::Revoke);
    }

    // ------------------------------------------------------------------
    // KI-24：多连接能力缓存
    // ------------------------------------------------------------------

    fn caps(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    /// 能力只跟随最新连接：旧连接晚到的 Hello 只记录到自己，返回 false 且不写库。
    #[test]
    fn capabilities_follow_latest_connection_only() {
        let registry = SessionRegistry::new();
        let persisted = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));

        // 旧连接登记时仍是最新连接：正常写库。
        let old = registry.register_blocking("a");
        let record = persisted.clone();
        assert!(
            registry
                .set_capabilities("a", old.conn_id, caps(&["docker"]), move |capabilities| {
                    record
                        .lock()
                        .expect("persist 计数锁不得中毒")
                        .push(capabilities.to_vec());
                    Ok(())
                })
                .expect("写库回调成功"),
            "最新连接登记必须返回 true"
        );
        assert_eq!(registry.latest_capabilities("a"), Some(caps(&["docker"])));
        assert!(registry.is_latest("a", old.conn_id));

        // 新连接登记后成为最新连接，写库成功。
        let new = registry.register_blocking("a");
        let record = persisted.clone();
        assert!(
            registry
                .set_capabilities(
                    "a",
                    new.conn_id,
                    caps(&["systemd", "logs"]),
                    move |capabilities| {
                        record
                            .lock()
                            .expect("persist 计数锁不得中毒")
                            .push(capabilities.to_vec());
                        Ok(())
                    },
                )
                .expect("写库回调成功"),
            "新连接登记必须返回 true"
        );
        assert!(registry.is_latest("a", new.conn_id));
        assert!(!registry.is_latest("a", old.conn_id));
        assert_eq!(
            registry.latest_capabilities("a"),
            Some(caps(&["systemd", "logs"]))
        );

        // 旧连接晚到的 Hello：记录到该连接，但返回 false、不触发 persist。
        let record = persisted.clone();
        assert!(
            !registry
                .set_capabilities("a", old.conn_id, caps(&["process"]), move |capabilities| {
                    record
                        .lock()
                        .expect("persist 计数锁不得中毒")
                        .push(capabilities.to_vec());
                    Ok(())
                })
                .expect("非最新连接不是错误"),
            "旧连接晚到的 Hello 必须返回 false"
        );
        assert_eq!(
            registry.latest_capabilities("a"),
            Some(caps(&["systemd", "logs"])),
            "旧连接不得覆盖最新连接的能力"
        );
        assert_eq!(
            *persisted.lock().expect("persist 计数锁不得中毒"),
            vec![caps(&["docker"]), caps(&["systemd", "logs"])],
            "persist 只应看到最新连接的两次登记"
        );
    }

    /// 最新连接断开：剩余连接仍有能力时在锁内回退，控制命令也重新指向旧连接。
    #[test]
    fn latest_disconnect_falls_back_to_remaining_capabilities() {
        let registry = SessionRegistry::new();

        let old = registry.register_blocking("a");
        let old_sender = registry.control_sender("a").expect("旧连接在线");
        assert!(registry
            .set_capabilities("a", old.conn_id, caps(&["docker"]), |_| Ok(()))
            .expect("登记旧连接能力"));

        let new = registry.register_blocking("a");
        assert!(registry
            .set_capabilities("a", new.conn_id, caps(&["systemd"]), |_| Ok(()))
            .expect("登记新连接能力"));

        let fallback = Arc::new(Mutex::new(None::<Vec<String>>));
        let captured = fallback.clone();
        let outcome = registry.unregister_with_fallback(
            "a",
            new.conn_id,
            || panic!("仍有旧连接，不能走 empty 分支"),
            move |capabilities| {
                *captured.lock().expect("回退锁不得中毒") = Some(capabilities.to_vec());
            },
        );
        assert_eq!(outcome, UnregisterOutcome::LatestRemoved);
        assert_eq!(
            *fallback.lock().expect("回退锁不得中毒"),
            Some(caps(&["docker"])),
            "回退回调必须收到剩余最新连接的能力"
        );
        assert_eq!(registry.latest_capabilities("a"), Some(caps(&["docker"])));
        let sender = registry.control_sender("a").expect("旧连接仍在线");
        assert!(
            sender.same_channel(&old_sender),
            "最新连接断开后控制命令必须指向旧连接"
        );

        // 最后一条连接断开：只执行 empty 回调，不再触发能力回退。
        let empty_calls = Arc::new(AtomicUsize::new(0));
        let calls = empty_calls.clone();
        let outcome = registry.unregister_with_fallback(
            "a",
            old.conn_id,
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
            },
            |_| panic!("无剩余连接时不得写能力"),
        );
        assert_eq!(outcome, UnregisterOutcome::Empty);
        assert_eq!(empty_calls.load(Ordering::SeqCst), 1);
        assert!(registry.latest_capabilities("a").is_none());
        assert!(!registry.has_active("a"));
    }

    /// 新连接已注册但尚未登记能力（None）时，旧连接断开不得写库或清空历史能力。
    #[test]
    fn unregistered_new_connection_does_not_clear_capabilities() {
        let registry = SessionRegistry::new();
        let persisted = Arc::new(AtomicUsize::new(0));

        let old = registry.register_blocking("a");
        let count = persisted.clone();
        assert!(registry
            .set_capabilities("a", old.conn_id, caps(&["docker"]), move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("登记旧连接能力"));
        assert_eq!(persisted.load(Ordering::SeqCst), 1);

        // 新连接已注册但还没 Hello：latest_capabilities 必须是 None，不能冒充空能力。
        let new = registry.register_blocking("a");
        assert_eq!(registry.latest_capabilities("a"), None);

        // 旧连接（曾经的最新连接）断开：不是最新连接，不做能力回退。
        let outcome = registry.unregister_with_fallback(
            "a",
            old.conn_id,
            || panic!("仍有新连接"),
            |_| panic!("非最新连接断开不得写能力"),
        );
        assert_eq!(outcome, UnregisterOutcome::Removed);
        assert_eq!(
            persisted.load(Ordering::SeqCst),
            1,
            "未登记能力的新连接不得触发写库"
        );

        // 最后一条（未登记能力的）连接断开：empty 分支，不写能力。
        let empty_calls = Arc::new(AtomicUsize::new(0));
        let calls = empty_calls.clone();
        let outcome = registry.unregister_with_fallback(
            "a",
            new.conn_id,
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
            },
            |_| panic!("无剩余连接时不得写能力"),
        );
        assert_eq!(outcome, UnregisterOutcome::Empty);
        assert_eq!(empty_calls.load(Ordering::SeqCst), 1);
        assert_eq!(persisted.load(Ordering::SeqCst), 1);

        // 反过来：最新连接尚未 Hello 就断开，旧连接有能力时必须回退，而不是写空。
        let old = registry.register_blocking("b");
        assert!(registry
            .set_capabilities("b", old.conn_id, caps(&["docker"]), |_| Ok(()))
            .expect("登记旧连接能力"));
        let unregistered = registry.register_blocking("b");
        let fallback = Arc::new(Mutex::new(None::<Vec<String>>));
        let captured = fallback.clone();
        let outcome = registry.unregister_with_fallback(
            "b",
            unregistered.conn_id,
            || panic!("仍有旧连接"),
            move |capabilities| {
                *captured.lock().expect("回退锁不得中毒") = Some(capabilities.to_vec());
            },
        );
        assert_eq!(outcome, UnregisterOutcome::LatestRemoved);
        assert_eq!(
            *fallback.lock().expect("回退锁不得中毒"),
            Some(caps(&["docker"])),
            "未登记能力的最新连接断开不得清空旧连接的能力"
        );
    }

    /// 最新连接断开、但剩余连接都没登记能力：不写库，保留历史能力。
    #[test]
    fn latest_disconnect_without_registered_fallback_keeps_history() {
        let registry = SessionRegistry::new();
        let old = registry.register_blocking("a");
        let latest = registry.register_blocking("a");

        let outcome = registry.unregister_with_fallback(
            "a",
            latest.conn_id,
            || panic!("仍有旧连接"),
            |_| panic!("剩余连接都没有能力，不得写库"),
        );
        assert_eq!(outcome, UnregisterOutcome::LatestRemovedWithoutFallback);
        assert!(registry.has_active("a"));
        assert_eq!(registry.latest_capabilities("a"), None);
        assert!(!registry.is_latest("a", latest.conn_id));
        assert!(registry.is_latest("a", old.conn_id));
    }

    /// persist 写库错误必须传给调用方，便于握手失败并触发清理回退。
    #[test]
    fn set_capabilities_propagates_persist_error() {
        let registry = SessionRegistry::new();
        let handle = registry.register_blocking("a");
        let result = registry.set_capabilities("a", handle.conn_id, caps(&["docker"]), |_| {
            anyhow::bail!("模拟写库失败")
        });
        assert!(result.is_err(), "persist 错误必须传给调用方");
        assert_eq!(
            registry.latest_capabilities("a"),
            Some(caps(&["docker"])),
            "能力应已记录到连接，便于清理时回退"
        );
    }

    /// 未知连接 / agent 的登记与查询都是安全 no-op，不触发写库。
    #[test]
    fn capabilities_for_unknown_connection_are_ignored() {
        let registry = SessionRegistry::new();
        let persisted = Arc::new(AtomicUsize::new(0));
        let count = persisted.clone();
        assert!(!registry
            .set_capabilities("a", 42, caps(&["docker"]), move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("未知连接不是错误"));
        assert_eq!(persisted.load(Ordering::SeqCst), 0);
        assert_eq!(registry.latest_capabilities("a"), None);
        assert!(!registry.is_latest("a", 42));
        assert_eq!(
            registry.unregister_with_fallback(
                "a",
                42,
                || panic!("不得回调"),
                |_| panic!("不得回调")
            ),
            UnregisterOutcome::NotRegistered
        );
    }
}
