//! `Storage` trait 到 PostgreSQL 固有方法的统一转发层。
//!
//! D3 的 `core` / `admin` / `alerts` / `archive` 四个域只写固有方法；本文件
//! 一次性实现 `impl Storage for PostgresStorage`，每个方法都用 UFCS
//! （`PostgresStorage::method(self, ..)`）转发，避免 `self.method(..)` 在
//! trait 方法体内解析成 trait 方法本身而无限递归。
//!
//! 方法顺序、参数名与返回类型照抄 [`Storage`](crate::storage::Storage)，
//! 共 97 个；dyn 化的注册只在这里发生，域实现保持不变。

use anyhow::Result;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

use super::PostgresStorage;
use crate::alerts::{AlertEvaluationOutcome, AlertEvent, AlertRule, AlertSilence, AlertState};
use crate::archive::{ArchiveObject, ArchiveStatus};
use crate::channels::NotificationChannel;
use crate::storage::sqlite::{AlertSeriesSnapshot, ArchiveRawRow};
use crate::storage::{
    AgentControlRecord, AgentSeriesRow, ApiTokenRecord, AuditEntry, DownsampleDeltaResult,
    DownsampleHourResult, DownsampleRangeResult, IngestOutcome, MaintenanceStateEntry,
    NewAuditEntry, PruneResult, SampleTier, Storage, TierStats,
};

impl Storage for PostgresStorage {
    fn upsert_agent(&self, agent: &AgentRecord) -> Result<()> {
        PostgresStorage::upsert_agent(self, agent)
    }

    fn mark_seen(&self, agent_id: &str, ts: i64) -> Result<()> {
        PostgresStorage::mark_seen(self, agent_id, ts)
    }

    fn set_status(&self, agent_id: &str, status: &str, ts: i64) -> Result<()> {
        PostgresStorage::set_status(self, agent_id, status, ts)
    }

    fn reset_online_status(&self) -> Result<usize> {
        PostgresStorage::reset_online_status(self)
    }

    fn insert_batch(&self, batch: &SampleBatch) -> Result<IngestOutcome> {
        PostgresStorage::insert_batch(self, batch)
    }

    fn list_agents(&self) -> Result<Vec<AgentRecord>> {
        PostgresStorage::list_agents(self)
    }

    fn get_agent(&self, agent_id: &str) -> Result<Option<AgentRecord>> {
        PostgresStorage::get_agent(self, agent_id)
    }

    fn query_series(&self, query: &SeriesQuery) -> Result<Vec<SeriesRow>> {
        PostgresStorage::query_series(self, query)
    }

    fn query_series_bucketed(&self, query: &SeriesQuery, bucket_ms: i64) -> Result<Vec<SeriesRow>> {
        PostgresStorage::query_series_bucketed(self, query, bucket_ms)
    }

    fn query_series_tiered(
        &self,
        query: &SeriesQuery,
        bucket_ms: i64,
        tier: SampleTier,
    ) -> Result<Vec<SeriesRow>> {
        PostgresStorage::query_series_tiered(self, query, bucket_ms, tier)
    }

    fn latest_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        PostgresStorage::latest_samples(self, since, metrics, agent)
    }

    fn get_sample_interval(&self, agent_id: &str) -> Result<Option<u64>> {
        PostgresStorage::get_sample_interval(self, agent_id)
    }

    fn set_sample_interval(&self, agent_id: &str, ms: u64, now: i64) -> Result<()> {
        PostgresStorage::set_sample_interval(self, agent_id, ms, now)
    }

    fn list_sample_intervals(&self) -> Result<Vec<(String, u64)>> {
        PostgresStorage::list_sample_intervals(self)
    }

    fn sample_count(&self, agent_id: &str) -> Result<i64> {
        PostgresStorage::sample_count(self, agent_id)
    }

    fn create_enroll_token(
        &self,
        token_hash: &str,
        name: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        PostgresStorage::create_enroll_token(self, token_hash, name, created_at, expires_at)
    }

    fn consume_enroll_token(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        PostgresStorage::consume_enroll_token(self, token_hash, now)
    }

    fn set_agent_secret(&self, agent_id: &str, secret_hash: &str, created_at: i64) -> Result<()> {
        PostgresStorage::set_agent_secret(self, agent_id, secret_hash, created_at)
    }

    fn verify_agent_secret(&self, agent_id: &str, secret_hash: &str) -> Result<bool> {
        PostgresStorage::verify_agent_secret(self, agent_id, secret_hash)
    }

    fn revoke_agent(&self, agent_id: &str, ts: i64) -> Result<()> {
        PostgresStorage::revoke_agent(self, agent_id, ts)
    }

    fn is_revoked(&self, agent_id: &str) -> Result<bool> {
        PostgresStorage::is_revoked(self, agent_id)
    }

    fn upsert_agent_control(
        &self,
        agent_id: &str,
        capabilities: &[String],
        updated_at: i64,
    ) -> Result<()> {
        PostgresStorage::upsert_agent_control(self, agent_id, capabilities, updated_at)
    }

    fn get_agent_control(&self, agent_id: &str) -> Result<Option<AgentControlRecord>> {
        PostgresStorage::get_agent_control(self, agent_id)
    }

    fn insert_audit(&self, entry: &NewAuditEntry) -> Result<i64> {
        PostgresStorage::insert_audit(self, entry)
    }

    fn list_audit(
        &self,
        limit: usize,
        before_id: Option<i64>,
        agent_id: Option<&str>,
        capability: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        PostgresStorage::list_audit(self, limit, before_id, agent_id, capability)
    }

    fn prune_audit(&self, before_ts: i64) -> Result<usize> {
        PostgresStorage::prune_audit(self, before_ts)
    }

    fn get_maintenance_state(&self, key: &str) -> Result<Option<String>> {
        PostgresStorage::get_maintenance_state(self, key)
    }

    fn set_maintenance_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        PostgresStorage::set_maintenance_state(self, key, value, updated_at)
    }

    fn list_maintenance_state(&self) -> Result<Vec<MaintenanceStateEntry>> {
        PostgresStorage::list_maintenance_state(self)
    }

    fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize> {
        PostgresStorage::seed_builtin_alert_rules(self, rules, now)
    }

    fn get_alert_rule(&self, id: &str) -> Result<Option<AlertRule>> {
        PostgresStorage::get_alert_rule(self, id)
    }

    fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        PostgresStorage::list_alert_rules(self)
    }

    fn alert_rule_count(&self) -> Result<usize> {
        PostgresStorage::alert_rule_count(self)
    }

    fn create_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        PostgresStorage::create_alert_rule(self, rule)
    }

    fn update_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        PostgresStorage::update_alert_rule(self, rule)
    }

    fn update_alert_rule_and_clear_states(&self, rule: &AlertRule) -> Result<()> {
        PostgresStorage::update_alert_rule_and_clear_states(self, rule)
    }

    fn delete_alert_rule(&self, id: &str) -> Result<()> {
        PostgresStorage::delete_alert_rule(self, id)
    }

    fn delete_alert_rule_and_clear_states(&self, id: &str) -> Result<()> {
        PostgresStorage::delete_alert_rule_and_clear_states(self, id)
    }

    fn list_alert_states(&self) -> Result<Vec<AlertState>> {
        PostgresStorage::list_alert_states(self)
    }

    fn get_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<Option<AlertState>> {
        PostgresStorage::get_alert_state(self, rule_id, agent_id, series_key)
    }

    fn upsert_alert_state(&self, state: &AlertState) -> Result<()> {
        PostgresStorage::upsert_alert_state(self, state)
    }

    fn delete_alert_state(&self, rule_id: &str, agent_id: &str, series_key: &str) -> Result<usize> {
        PostgresStorage::delete_alert_state(self, rule_id, agent_id, series_key)
    }

    fn prune_alert_states(&self, resolved_before: i64) -> Result<usize> {
        PostgresStorage::prune_alert_states(self, resolved_before)
    }

    fn prune_stale_alert_states(&self, stale_before: i64, max_rows: usize) -> Result<usize> {
        PostgresStorage::prune_stale_alert_states(self, stale_before, max_rows)
    }

    fn insert_alert_event(&self, event: &AlertEvent) -> Result<i64> {
        PostgresStorage::insert_alert_event(self, event)
    }

    fn list_alert_events(&self, limit: usize, before_id: Option<i64>) -> Result<Vec<AlertEvent>> {
        PostgresStorage::list_alert_events(self, limit, before_id)
    }

    fn prune_alert_events(&self, before_ts: i64, max_rows: usize) -> Result<usize> {
        PostgresStorage::prune_alert_events(self, before_ts, max_rows)
    }

    fn create_alert_silence(&self, silence: &AlertSilence) -> Result<i64> {
        PostgresStorage::create_alert_silence(self, silence)
    }

    fn list_active_silences(&self, now: i64) -> Result<Vec<AlertSilence>> {
        PostgresStorage::list_active_silences(self, now)
    }

    fn delete_alert_silence(&self, id: i64) -> Result<bool> {
        PostgresStorage::delete_alert_silence(self, id)
    }

    fn prune_alert_silences(&self, before_ts: i64) -> Result<usize> {
        PostgresStorage::prune_alert_silences(self, before_ts)
    }

    fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRule>> {
        PostgresStorage::list_enabled_alert_rules(self)
    }

    fn list_alert_states_for_rule(&self, rule_id: &str, limit: usize) -> Result<Vec<AlertState>> {
        PostgresStorage::list_alert_states_for_rule(self, rule_id, limit)
    }

    fn prune_alert_states_for_rule(&self, rule_id: &str, keep: usize) -> Result<usize> {
        PostgresStorage::prune_alert_states_for_rule(self, rule_id, keep)
    }

    fn latest_alert_series(
        &self,
        metric: &str,
        since: i64,
        agent: Option<&str>,
        filter_labels: &Labels,
        limit: usize,
    ) -> Result<AlertSeriesSnapshot> {
        PostgresStorage::latest_alert_series(self, metric, since, agent, filter_labels, limit)
    }

    fn apply_alert_transitions(&self, events: &[AlertEvent], states: &[AlertState]) -> Result<()> {
        PostgresStorage::apply_alert_transitions(self, events, states)
    }

    fn apply_alert_evaluation(
        &self,
        rule_id: &str,
        expected_revision: i64,
        events: &[AlertEvent],
        states: &[AlertState],
        keep_states: usize,
    ) -> Result<AlertEvaluationOutcome> {
        PostgresStorage::apply_alert_evaluation(
            self,
            rule_id,
            expected_revision,
            events,
            states,
            keep_states,
        )
    }

    fn max_alert_event_id(&self) -> Result<i64> {
        PostgresStorage::max_alert_event_id(self)
    }

    fn list_pending_notification_events_after(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>> {
        PostgresStorage::list_pending_notification_events_after(self, after_id, limit)
    }

    fn mark_notification_processed(&self, id: i64, notify_error: &str) -> Result<bool> {
        PostgresStorage::mark_notification_processed(self, id, notify_error)
    }

    fn list_pending_notification_events(&self, limit: usize) -> Result<Vec<AlertEvent>> {
        PostgresStorage::list_pending_notification_events(self, limit)
    }

    fn mark_notification_result(
        &self,
        id: i64,
        notified: bool,
        notify_error: &str,
    ) -> Result<bool> {
        PostgresStorage::mark_notification_result(self, id, notified, notify_error)
    }

    fn update_alert_state_notified(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: i64,
    ) -> Result<bool> {
        PostgresStorage::update_alert_state_notified(
            self,
            rule_id,
            agent_id,
            series_key,
            last_notified_at,
        )
    }

    fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        PostgresStorage::list_notification_channels(self)
    }

    fn get_notification_channel(&self, id: &str) -> Result<Option<NotificationChannel>> {
        PostgresStorage::get_notification_channel(self, id)
    }

    fn notification_channel_count(&self) -> Result<usize> {
        PostgresStorage::notification_channel_count(self)
    }

    fn create_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        PostgresStorage::create_notification_channel(self, channel)
    }

    fn update_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        PostgresStorage::update_notification_channel(self, channel)
    }

    fn delete_notification_channel(&self, id: &str) -> Result<()> {
        PostgresStorage::delete_notification_channel(self, id)
    }

    fn create_api_token(
        &self,
        name: &str,
        token_hash: &str,
        scope: &str,
        created_at: i64,
    ) -> Result<ApiTokenRecord> {
        PostgresStorage::create_api_token(self, name, token_hash, scope, created_at)
    }

    fn list_api_tokens(&self) -> Result<Vec<ApiTokenRecord>> {
        PostgresStorage::list_api_tokens(self)
    }

    fn rotate_api_token(&self, name: &str, token_hash: &str, now: i64) -> Result<ApiTokenRecord> {
        PostgresStorage::rotate_api_token(self, name, token_hash, now)
    }

    fn revoke_api_token(&self, name: &str, now: i64) -> Result<()> {
        PostgresStorage::revoke_api_token(self, name, now)
    }

    fn authenticate_api_token(&self, token_hash: &str, now: i64) -> Result<Option<ApiTokenRecord>> {
        PostgresStorage::authenticate_api_token(self, token_hash, now)
    }

    fn downsample_1m_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        PostgresStorage::downsample_1m_range(self, from_ts, to_ts)
    }

    fn downsample_1h_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        PostgresStorage::downsample_1h_range(self, from_ts, to_ts)
    }

    fn downsample_1m_delta(
        &self,
        closed_end: i64,
        max_rows: usize,
    ) -> Result<DownsampleDeltaResult> {
        PostgresStorage::downsample_1m_delta(self, closed_end, max_rows)
    }

    fn downsample_1h_hour(&self, closed_hour: i64) -> Result<Option<DownsampleHourResult>> {
        PostgresStorage::downsample_1h_hour(self, closed_hour)
    }

    fn count_unaggregated_raw_rows(&self) -> Result<i64> {
        PostgresStorage::count_unaggregated_raw_rows(self)
    }

    fn count_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<i64> {
        PostgresStorage::count_raw_rows_outside(self, min_ts, max_ts)
    }

    fn count_unaggregated_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<i64> {
        PostgresStorage::count_unaggregated_raw_rows_outside(self, min_ts, max_ts)
    }

    fn count_unaggregated_raw_rows_before(&self, before_ts: i64) -> Result<i64> {
        PostgresStorage::count_unaggregated_raw_rows_before(self, before_ts)
    }

    fn isolate_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<usize> {
        PostgresStorage::isolate_raw_rows_outside(self, min_ts, max_ts)
    }

    fn raw_stats(&self) -> Result<TierStats> {
        PostgresStorage::raw_stats(self)
    }

    fn samples_1m_stats(&self) -> Result<TierStats> {
        PostgresStorage::samples_1m_stats(self)
    }

    fn samples_1h_stats(&self) -> Result<TierStats> {
        PostgresStorage::samples_1h_stats(self)
    }

    fn raw_ts_at_offset(&self, from_ts: i64, to_ts: i64, offset: usize) -> Result<Option<i64>> {
        PostgresStorage::raw_ts_at_offset(self, from_ts, to_ts, offset)
    }

    fn samples_1m_ts_at_offset(
        &self,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        PostgresStorage::samples_1m_ts_at_offset(self, from_ts, to_ts, offset)
    }

    fn raw_new_rows(&self, after_rowid: Option<i64>) -> Result<(Option<i64>, Option<i64>)> {
        PostgresStorage::raw_new_rows(self, after_rowid)
    }

    fn samples_1m_oldest_ts(&self) -> Result<Option<i64>> {
        PostgresStorage::samples_1m_oldest_ts(self)
    }

    fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        PostgresStorage::prune_samples_before(self, cutoff)
    }

    fn prune_archived_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        PostgresStorage::prune_archived_samples_before(self, cutoff)
    }

    fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult> {
        PostgresStorage::prune_samples_1m_before(self, cutoff)
    }

    fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult> {
        PostgresStorage::prune_samples_1h_before(self, cutoff)
    }

    fn claim_raw_rowid_if_unchanged(
        &self,
        expected_rowid: Option<i64>,
        expected_generation: i64,
        new_max: i64,
    ) -> Result<bool> {
        PostgresStorage::claim_raw_rowid_if_unchanged(
            self,
            expected_rowid,
            expected_generation,
            new_max,
        )
    }

    fn insert_archive_object(&self, object: &ArchiveObject) -> Result<i64> {
        PostgresStorage::insert_archive_object(self, object)
    }

    fn get_archive_object(&self, id: i64) -> Result<Option<ArchiveObject>> {
        PostgresStorage::get_archive_object(self, id)
    }

    fn find_archive_object_by_key(&self, object_key: &str) -> Result<Option<ArchiveObject>> {
        PostgresStorage::find_archive_object_by_key(self, object_key)
    }

    fn list_archive_objects(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        PostgresStorage::list_archive_objects(self, limit, before_id)
    }

    fn list_retryable_archive_objects(
        &self,
        limit: usize,
        after_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        PostgresStorage::list_retryable_archive_objects(self, limit, after_id)
    }

    fn update_archive_object_status(
        &self,
        id: i64,
        status: ArchiveStatus,
        error: &str,
        uploaded_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<()> {
        PostgresStorage::update_archive_object_status(
            self,
            id,
            status,
            error,
            uploaded_at,
            deleted_at,
        )
    }

    fn get_archive_state(&self, key: &str) -> Result<Option<String>> {
        PostgresStorage::get_archive_state(self, key)
    }

    fn set_archive_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        PostgresStorage::set_archive_state(self, key, value, updated_at)
    }

    fn list_archive_objects_in_range(
        &self,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<Vec<ArchiveObject>> {
        PostgresStorage::list_archive_objects_in_range(self, from_ts, to_ts)
    }

    fn scan_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        after_rowid: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        PostgresStorage::scan_archive_rows(self, from_ts, to_ts, after_rowid, limit)
    }

    fn list_unclaimed_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        PostgresStorage::list_unclaimed_archive_rows(self, from_ts, to_ts, limit)
    }

    fn claim_archive_rows(&self, object: &ArchiveObject, rows: &[ArchiveRawRow]) -> Result<i64> {
        PostgresStorage::claim_archive_rows(self, object, rows)
    }

    fn archive_rows_for_object(&self, object_id: i64) -> Result<Vec<ArchiveRawRow>> {
        PostgresStorage::archive_rows_for_object(self, object_id)
    }

    fn record_archive_object_failure(&self, id: i64, error: &str) -> Result<()> {
        PostgresStorage::record_archive_object_failure(self, id, error)
    }

    fn update_archive_object_metadata(&self, id: i64, bytes: u64, sha256: &str) -> Result<()> {
        PostgresStorage::update_archive_object_metadata(self, id, bytes, sha256)
    }

    fn count_invalid_archive_raw_rows(&self) -> Result<i64> {
        PostgresStorage::count_invalid_archive_raw_rows(self)
    }

    fn record_archive_attempt(&self, id: i64) -> Result<i64> {
        PostgresStorage::record_archive_attempt(self, id)
    }

    fn count_archive_objects(&self) -> Result<i64> {
        PostgresStorage::count_archive_objects(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageHandle;

    /// 编译期证明：`PostgresStorage` 可直接放进 `Arc<dyn Storage>`，
    /// 且 `StorageHandle::postgres` 的构造签名与句柄一致。
    #[test]
    fn postgres_storage_implements_storage_trait() {
        fn assert_storage<T: Storage + Send + Sync + 'static>() {}
        assert_storage::<PostgresStorage>();
        let _ctor: fn(PostgresStorage) -> StorageHandle = StorageHandle::postgres;
    }
}
