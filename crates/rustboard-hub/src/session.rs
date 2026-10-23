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

use tokio::sync::{mpsc, watch};

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
struct AgentSlot {
    state: Mutex<SlotState>,
}

/// slot 锁保护的状态：该 agent 当前的全部连接。
struct SlotState {
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

impl AgentSlot {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState {
                connections: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState> {
        lock(&self.state)
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
    /// 锁顺序：先取 slot（释放全局 map 锁），再锁 slot 插入连接。若旧连接的清理
    /// 回调正持有同一把 slot 锁写 offline/revoked，这里会等它结束才插入；调用方
    /// 随后写 online，因此新 online 一定晚于旧 offline。
    pub fn register(&self, agent_id: &str) -> SessionHandle {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        // 初始值不会触发 `changed()`；真正的关闭原因只由 shutdown/reconfigure 写入。
        let (shutdown, receiver) = watch::channel(ShutdownReason::Revoke);
        // 容量 16：控制 API 自身限速 10/min，正常情况下队列不会堆积；
        // 堆积时 `try_send` 直接回 429，绝不阻塞会话的采集 / ACK 路径。
        let (control, control_rx) = mpsc::channel(CONTROL_COMMAND_BUFFER);

        let slot = self.agent_slot_or_create(agent_id);
        let active = {
            let mut state = slot.lock();
            state
                .connections
                .insert(conn_id, ConnectionEntry { shutdown, control });
            state.connections.len()
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
        // 锁顺序：先取 slot（此时全局 map 锁已释放），再锁 slot。
        let Some(slot) = self.agent_slot(agent_id) else {
            return false;
        };
        let mut state = slot.lock();
        if state.connections.remove(&conn_id).is_none() {
            return false;
        }
        if !state.connections.is_empty() {
            return false;
        }
        // 仍持有 slot 锁：新连接插不进来，直到回调写完状态。
        callback();
        true
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
    use std::time::Duration;

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

    /// 回调只在「最后一条连接」注销时执行；旧 conn_id / 重复注销都不能触发。
    #[test]
    fn unregister_last_and_run_only_fires_for_last_connection() {
        let registry = SessionRegistry::new();
        let first = registry.register("a");
        let second = registry.register("a");
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
        let old = registry.register("a");
        let old_id = old.conn_id;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let callback_finished = Arc::new(AtomicBool::new(false));

        let cleanup_registry = registry.clone();
        let cleanup_finished = callback_finished.clone();
        let cleanup_thread = std::thread::spawn(move || {
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
            let handle = register_registry.register("a");
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
        let old = registry.register("slow");
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
            let handle = register_registry.register("fast");
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
        let first = registry.register("a");
        assert!(registry.unregister("a", first.conn_id));

        assert!(!registry.has_active("a"));
        assert!(registry.active_agents().is_empty());
        assert!(registry.control_sender("a").is_none());
        assert!(!registry.shutdown("a"));
        assert!(!registry.reconfigure("a"));

        let second = registry.register("a");
        assert!(second.conn_id > first.conn_id, "conn_id 必须继续递增");
        assert!(registry.has_active("a"));
        assert_eq!(registry.active_agents(), vec!["a".to_string()]);
        assert!(registry.shutdown("a"));
        assert_eq!(*second.shutdown.borrow(), ShutdownReason::Revoke);
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
