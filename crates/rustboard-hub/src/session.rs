//! 活跃会话注册表。
//!
//! 同一个 agent 允许同时存在多条连接（例如重连风暴期间旧连接还没完全断开）。
//! 注册表按 `agent_id -> {conn_id -> 取消信号}` 保存全部活跃连接：
//!
//! - 只有最后一条连接调用 `unregister` 时返回 `true`，调用方才把状态置为 offline；
//!   因此旧连接关闭不会覆盖新连接，也不会在仍有连接时误判离线。
//! - `shutdown` / `reconfigure` 对该 agent 的全部连接发取消信号，传播不依赖
//!   「哪条是最新连接」。
//!
//! 关闭原因用 [`ShutdownReason`] 区分：吊销（Revoke）回 `revoked` Problem，
//! 采样间隔变更（Reconfigure）回 WebSocket `Close(1000)` 正常关闭，让 agent
//! 立即重连并拿到新的 Welcome。两者都不改变「最后一条连接才 offline」的语义。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{mpsc, watch};

use crate::control::{ControlCommand, CONTROL_COMMAND_BUFFER};

/// 活跃连接注册表。通过 `Arc` 在会话任务与吊销轮询任务之间共享。
pub struct SessionRegistry {
    inner: Mutex<HashMap<String, SessionEntry>>,
    next_conn_id: AtomicU64,
}

struct SessionEntry {
    connections: HashMap<u64, ConnectionEntry>,
}

/// 单条连接持有的信号：关闭原因 + 控制命令队列。
struct ConnectionEntry {
    shutdown: watch::Sender<ShutdownReason>,
    /// M3：管理 API 通过它把控制命令投递给该连接所属的会话任务。
    control: mpsc::Sender<ControlCommand>,
}

/// 会话关闭原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// agent 已被吊销：会话回 `revoked` Problem 后关闭。
    Revoke,
    /// 配置变化（采样间隔）：回 `Close(1000)` 正常关闭，agent 随后重连。
    Reconfigure,
}

/// 一次注册的凭据：连接编号 + 取消信号接收端 + 控制命令接收端。
pub struct SessionHandle {
    pub conn_id: u64,
    pub shutdown: watch::Receiver<ShutdownReason>,
    /// 该连接专属的控制命令队列；会话循环 `select!` 从中取命令。
    pub control_rx: mpsc::Receiver<ControlCommand>,
}

impl SessionRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, SessionEntry>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// 注册一条新连接，返回连接编号与取消信号接收端。
    pub fn register(&self, agent_id: &str) -> SessionHandle {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        // 初始值不会触发 `changed()`；真正的关闭原因只由 shutdown/reconfigure 写入。
        let (shutdown, receiver) = watch::channel(ShutdownReason::Revoke);
        // 容量 16：控制 API 自身限速 10/min，正常情况下队列不会堆积；
        // 堆积时 `try_send` 直接回 429，绝不阻塞会话的采集 / ACK 路径。
        let (control, control_rx) = mpsc::channel(CONTROL_COMMAND_BUFFER);
        let active = {
            let mut inner = self.lock();
            let entry = inner
                .entry(agent_id.to_owned())
                .or_insert_with(|| SessionEntry {
                    connections: HashMap::new(),
                });
            entry
                .connections
                .insert(conn_id, ConnectionEntry { shutdown, control });
            entry.connections.len()
        };
        tracing::debug!(agent = %agent_id, conn_id, active, "agent 会话已注册");
        SessionHandle {
            conn_id,
            shutdown: receiver,
            control_rx,
        }
    }

    /// 取该 agent **最新一条连接**的控制命令发送端。
    ///
    /// 重连风暴期间旧连接可能还没清理干净：控制命令只投给 conn_id 最大的那条，
    /// 避免把命令送给即将关闭的会话。agent 不在线时返回 `None`。
    pub fn control_sender(&self, agent_id: &str) -> Option<mpsc::Sender<ControlCommand>> {
        let inner = self.lock();
        let entry = inner.get(agent_id)?;
        entry
            .connections
            .iter()
            .max_by_key(|(conn_id, _)| **conn_id)
            .map(|(_, connection)| connection.control.clone())
    }

    /// 注销连接：仅当这是该 agent 的**最后一条**连接时返回 `true`。
    ///
    /// 返回 `false` 表示还有其他活跃连接（或该连接已经不在注册表里），
    /// 调用方不得把状态改成 offline。
    pub fn unregister(&self, agent_id: &str, conn_id: u64) -> bool {
        let mut inner = self.lock();
        let Some(entry) = inner.get_mut(agent_id) else {
            return false;
        };
        if entry.connections.remove(&conn_id).is_none() {
            return false;
        }
        if entry.connections.is_empty() {
            inner.remove(agent_id);
            true
        } else {
            false
        }
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
        let inner = self.lock();
        match inner.get(agent_id) {
            Some(entry) => {
                for connection in entry.connections.values() {
                    let _ = connection.shutdown.send(reason);
                }
                true
            }
            None => false,
        }
    }

    /// 批量取消（吊销轮询任务使用）。
    pub fn shutdown_all(&self, agent_ids: &[String]) {
        for agent_id in agent_ids {
            self.shutdown(agent_id);
        }
    }

    /// 当前是否还有该 agent 的活跃连接。
    pub fn has_active(&self, agent_id: &str) -> bool {
        self.lock()
            .get(agent_id)
            .is_some_and(|entry| !entry.connections.is_empty())
    }

    /// 当前注册表中的 agent_id 快照，供吊销轮询逐个检查。
    pub fn active_agents(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustboard_common::control::ControlOp;

    #[test]
    fn only_last_connection_marks_agent_offline() {
        let registry = SessionRegistry::new();
        let first = registry.register("a");
        let second = registry.register("a");
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

    #[test]
    fn shutdown_targets_every_connection_of_agent() {
        let registry = SessionRegistry::new();
        let first = registry.register("a");
        let second = registry.register("a");
        assert!(registry.shutdown("a"));
        assert_eq!(*first.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*second.shutdown.borrow(), ShutdownReason::Revoke);
        assert!(!registry.shutdown("missing"));
    }

    #[test]
    fn shutdown_all_covers_every_listed_agent() {
        let registry = SessionRegistry::new();
        let a = registry.register("a");
        let b = registry.register("b");
        registry.shutdown_all(&["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(*a.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*b.shutdown.borrow(), ShutdownReason::Revoke);
    }

    /// 吊销只影响目标 agent，其他 agent 的会话不能被误伤（issue #5）。
    #[test]
    fn shutdown_does_not_signal_other_agents() {
        let registry = SessionRegistry::new();
        let a = registry.register("a");
        let b = registry.register("b");

        assert!(registry.shutdown("a"));
        assert_eq!(*a.shutdown.borrow(), ShutdownReason::Revoke);
        assert_eq!(*b.shutdown.borrow(), ShutdownReason::Revoke);
        assert!(registry.has_active("b"));
    }

    /// 重连后，旧连接迟到的注销不能把新连接从注册表里删掉。
    #[test]
    fn stale_conn_id_does_not_remove_replacement_connection() {
        let registry = SessionRegistry::new();
        let old = registry.register("a");
        assert!(registry.unregister("a", old.conn_id));

        let new = registry.register("a");
        assert_ne!(old.conn_id, new.conn_id);
        assert!(!registry.unregister("a", old.conn_id));
        assert!(registry.has_active("a"));

        // 新连接仍然能收到吊销信号。
        assert!(registry.shutdown("a"));
        assert_eq!(*new.shutdown.borrow(), ShutdownReason::Revoke);
    }

    /// 会话循环用 `watch::Receiver::changed()` 等待吊销；这里验证信号真的能唤醒它。
    #[tokio::test]
    async fn shutdown_wakes_handle_waiting_for_signal() {
        let registry = SessionRegistry::new();
        let mut handle = registry.register("a");
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
        let mut old = registry.register("a");
        let mut new = registry.register("a");

        // 先投一条：只有新连接能收到。
        let sender = registry
            .control_sender("a")
            .expect("在线 agent 应有控制发送端");
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        sender
            .try_send(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
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
        let handle = registry.register("a");
        let sender = registry.control_sender("a").expect("应取得发送端");
        drop(handle.control_rx);
        let (reply, _reply_rx) = tokio::sync::oneshot::channel();
        assert!(
            sender
                .try_send(ControlCommand {
                    op: ControlOp::ProcessList,
                    reply,
                })
                .is_err(),
            "会话结束后 try_send 必须失败"
        );
    }

    /// 配置变更走 Reconfigure，不能混成吊销；多连接都要收到。
    #[test]
    fn reconfigure_signals_every_connection_with_reconfigure() {
        let registry = SessionRegistry::new();
        let first = registry.register("a");
        let second = registry.register("a");
        let other = registry.register("b");

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
}
