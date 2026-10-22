//! 活跃会话注册表。
//!
//! 同一个 agent 允许同时存在多条连接（例如重连风暴期间旧连接还没完全断开）。
//! 注册表按 `agent_id -> {conn_id -> 取消信号}` 保存全部活跃连接：
//!
//! - 只有最后一条连接调用 `unregister` 时返回 `true`，调用方才把状态置为 offline；
//!   因此旧连接关闭不会覆盖新连接，也不会在仍有连接时误判离线。
//! - `shutdown` 对该 agent 的全部连接发取消信号，吊销传播不依赖「哪条是最新连接」。
//!
//! 吊销传播依赖这里的 `shutdown` 信号：管理侧写入 `revoked_agents` 后，
//! hub 的轮询任务对仍在注册表里的 agent 发送取消信号，会话循环随即关闭。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::watch;

/// 活跃连接注册表。通过 `Arc` 在会话任务与吊销轮询任务之间共享。
pub struct SessionRegistry {
    inner: Mutex<HashMap<String, SessionEntry>>,
    next_conn_id: AtomicU64,
}

struct SessionEntry {
    connections: HashMap<u64, watch::Sender<bool>>,
}

/// 一次注册的凭据：连接编号 + 取消信号接收端。
pub struct SessionHandle {
    pub conn_id: u64,
    pub shutdown: watch::Receiver<bool>,
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
        let (shutdown, receiver) = watch::channel(false);
        let active = {
            let mut inner = self.lock();
            let entry = inner
                .entry(agent_id.to_owned())
                .or_insert_with(|| SessionEntry {
                    connections: HashMap::new(),
                });
            entry.connections.insert(conn_id, shutdown);
            entry.connections.len()
        };
        tracing::debug!(agent = %agent_id, conn_id, active, "agent 会话已注册");
        SessionHandle {
            conn_id,
            shutdown: receiver,
        }
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

    /// 取消某个 agent 的全部活跃连接。连接不存在时返回 `false`。
    pub fn shutdown(&self, agent_id: &str) -> bool {
        let inner = self.lock();
        match inner.get(agent_id) {
            Some(entry) => {
                for shutdown in entry.connections.values() {
                    let _ = shutdown.send(true);
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
        assert!(*first.shutdown.borrow());
        assert!(*second.shutdown.borrow());
        assert!(!registry.shutdown("missing"));
    }

    #[test]
    fn shutdown_all_covers_every_listed_agent() {
        let registry = SessionRegistry::new();
        let a = registry.register("a");
        let b = registry.register("b");
        registry.shutdown_all(&["a".to_string(), "b".to_string(), "c".to_string()]);
        assert!(*a.shutdown.borrow());
        assert!(*b.shutdown.borrow());
    }

    /// 吊销只影响目标 agent，其他 agent 的会话不能被误伤（issue #5）。
    #[test]
    fn shutdown_does_not_signal_other_agents() {
        let registry = SessionRegistry::new();
        let a = registry.register("a");
        let b = registry.register("b");

        assert!(registry.shutdown("a"));
        assert!(*a.shutdown.borrow());
        assert!(!*b.shutdown.borrow());
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
        assert!(*new.shutdown.borrow());
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
        assert!(received);
    }
}
