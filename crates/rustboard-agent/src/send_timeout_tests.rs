//! #12 / A3 独立测试：`send_frame_with_timeout` 的 WebSocket 写超时行为。
//!
//! 依据 `docs/plans/2026-10-23-v0.3.1-hardening.md` §3.3 / §5.3 与接口契约编写，
//! 只通过父模块公开的 helper 观察行为，不依赖生产实现细节；假 hub 仅使用
//! `127.0.0.1` 回环，不访问外部网络。

use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Instant;

use rustboard_common::model::Sample;
use rustboard_common::wire::Welcome;

use super::*;

/// 测试 Sink 的返回类型。显式写 `std::result::Result`，避免被父模块的
/// `anyhow::Result` 别名覆盖。
type SinkResult = std::result::Result<(), WsError>;

/// `poll_ready` 永远返回 `Pending`、且不注册 waker 的 Sink。
///
/// 唤醒只能依赖外层的 `tokio::time::timeout`，用来验证 helper 的超时确实
/// 独立生效，而不是等 Sink 自己就绪。
#[derive(Default)]
struct PendingSink {
    sent: Vec<Message>,
}

impl Sink<Message> for PendingSink {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Pending
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> SinkResult {
        self.get_mut().sent.push(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }
}

/// `poll_ready` 在约 `delay` 内持续 `Pending`（由 tokio 定时器唤醒），之后进入
/// Ready；其余操作立即成功的 Sink。用来模拟“慢但仍在持续读取”的正常连接。
struct SlowSink {
    delay: Pin<Box<tokio::time::Sleep>>,
    ready: bool,
    sent: Vec<Message>,
}

impl SlowSink {
    fn new(delay: Duration) -> Self {
        Self {
            delay: Box::pin(tokio::time::sleep(delay)),
            ready: false,
            sent: Vec::new(),
        }
    }
}

impl Sink<Message> for SlowSink {
    type Error = WsError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        if self.ready {
            return Poll::Ready(Ok(()));
        }

        let this = self.as_mut().get_mut();
        match this.delay.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                this.ready = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> SinkResult {
        self.get_mut().sent.push(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }
}

/// `poll_ready` 立即返回底层写错误，用来验证错误分类不会被误判为超时。
struct FailingSink;

impl Sink<Message> for FailingSink {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Err(WsError::Io(std::io::Error::other("boom"))))
    }

    fn start_send(self: Pin<&mut Self>, _item: Message) -> SinkResult {
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<SinkResult> {
        Poll::Ready(Ok(()))
    }
}

/// 取出 Sink 记录的二进制帧并解码，用于断言发送内容没有损坏。
fn decode_sent(message: &Message) -> Frame {
    match message {
        Message::Binary(bytes) => Frame::decode(bytes.as_slice()).expect("已发送帧应能解码"),
        other => panic!("帧必须以二进制形式发送，实际为 {other:?}"),
    }
}

/// 1. `poll_ready` 永不就绪：helper 必须在自身超时内返回可识别的超时错误，
///    文本只含“发送超时”和帧类型，不含 payload。
#[tokio::test]
async fn send_timeout_pending_ready_sink_returns_timeout_error() {
    const TS: i64 = 987_654_321;

    let mut sink = PendingSink::default();
    let frame = Frame::Ping { ts: TS };

    let err = tokio::time::timeout(
        Duration::from_secs(2),
        send_frame_with_timeout(&mut sink, &frame, Duration::from_millis(50)),
    )
    .await
    .expect("send_frame_with_timeout 必须在外层 2s 防护内返回，不能挂死")
    .expect_err("poll_ready 永不就绪时必须返回 Err");

    assert!(
        is_send_timeout_error(&err),
        "该错误必须被识别为发送超时: {err:#}"
    );
    let text = err.to_string();
    assert!(
        text.contains("发送超时"),
        "超时文本必须包含「发送超时」: {text}"
    );
    assert!(text.contains("Ping"), "超时文本必须包含帧类型 Ping: {text}");
    assert!(
        !text.contains("987654321"),
        "超时文本不得包含帧 payload: {text}"
    );
    assert!(sink.sent.is_empty(), "poll_ready 未就绪时不应写入任何帧");
}

/// 2. 慢但持续读取：约 100ms 后才就绪的 Sink 在 1s 超时下必须成功，不能被误杀。
#[tokio::test]
async fn send_timeout_slow_progressing_sink_succeeds() {
    let mut sink = SlowSink::new(Duration::from_millis(100));
    let frame = Frame::Ping { ts: 1 };
    let started = Instant::now();

    tokio::time::timeout(
        Duration::from_secs(2),
        send_frame_with_timeout(&mut sink, &frame, Duration::from_secs(1)),
    )
    .await
    .expect("外层 2s 防护超时：慢速读取不应挂死")
    .expect("服务端持续读取时不应触发发送超时");

    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "Sink 应确实阻塞约 100ms 才就绪，实际耗时 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(900),
        "正常慢速发送不应耗到 1s 超时，实际耗时 {elapsed:?}"
    );
    assert_eq!(sink.sent.len(), 1, "应恰好发送一帧");
    match decode_sent(&sink.sent[0]) {
        Frame::Ping { ts } => assert_eq!(ts, 1, "发送内容必须与原帧一致"),
        other => panic!("发送帧类型不符: {other:?}"),
    }
}

/// 3. 底层写错误原样上抛：必须返回 Err，但不能被分类成发送超时。
#[tokio::test]
async fn send_timeout_preserves_underlying_sink_error() {
    let mut sink = FailingSink;
    let frame = Frame::Ping { ts: 42 };

    // helper 超时 5s；底层错误应立即返回，若被误判成超时则会被外层 2s 防护打断。
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        send_frame_with_timeout(&mut sink, &frame, Duration::from_secs(5)),
    )
    .await
    .expect("底层写错误必须立即返回，不能挂到超时")
    .expect_err("Sink 写错误必须向上返回 Err");

    assert!(
        !is_send_timeout_error(&err),
        "底层写错误不能被误判为发送超时: {err:#}"
    );
    let text = err.to_string();
    assert!(text.contains("Ping"), "错误文本必须带帧类型 Ping: {text}");
    assert!(
        !text.contains("发送超时"),
        "底层写错误不应伪装成超时: {text}"
    );
}

/// 4. 超时只影响当前帧：同一个 Sink 先因极短超时失败，之后仍能正常发送。
#[tokio::test]
async fn send_timeout_only_affects_current_frame() {
    let mut sink = SlowSink::new(Duration::from_millis(100));

    let first = Frame::Ping { ts: 11 };
    let err = tokio::time::timeout(
        Duration::from_secs(1),
        send_frame_with_timeout(&mut sink, &first, Duration::from_millis(10)),
    )
    .await
    .expect("短超时必须立即返回")
    .expect_err("10ms 超时应让第一帧发送失败");
    assert!(
        is_send_timeout_error(&err),
        "第一帧必须是发送超时错误: {err:#}"
    );
    assert!(sink.sent.is_empty(), "第一帧超时时不应产生已发送帧");

    let second = Frame::Ping { ts: 22 };
    tokio::time::timeout(
        Duration::from_secs(2),
        send_frame_with_timeout(&mut sink, &second, Duration::from_secs(1)),
    )
    .await
    .expect("第二次调用不应挂死")
    .expect("超时后同一个 Sink 仍必须能继续发送");

    assert_eq!(sink.sent.len(), 1, "第二次发送应成功写入一帧");
    match decode_sent(&sink.sent[0]) {
        Frame::Ping { ts } => assert_eq!(ts, 22, "恢复后发送的必须是第二帧"),
        other => panic!("恢复后发送的帧类型不符: {other:?}"),
    }
}

/// 5. 超时错误对 `ControlResponse` 这类复合帧同样报告帧类型，且不泄露内容。
#[tokio::test]
async fn send_timeout_reports_control_response_kind() {
    let mut sink = PendingSink::default();
    let frame = Frame::ControlResponse(ControlResponse {
        id: 7_777_777,
        result: None,
        error: None,
    });

    let err = tokio::time::timeout(
        Duration::from_secs(2),
        send_frame_with_timeout(&mut sink, &frame, Duration::from_millis(50)),
    )
    .await
    .expect("send_frame_with_timeout 必须在外层 2s 防护内返回")
    .expect_err("poll_ready 永不就绪时必须返回 Err");

    assert!(
        is_send_timeout_error(&err),
        "ControlResponse 发送超时也必须可识别: {err:#}"
    );
    let text = err.to_string();
    assert!(
        text.contains("发送超时"),
        "超时文本必须包含「发送超时」: {text}"
    );
    assert!(
        text.contains("ControlResponse"),
        "超时文本必须包含帧类型 ControlResponse: {text}"
    );
    assert!(
        !text.contains("7777777"),
        "超时文本不得包含帧 payload（control id）: {text}"
    );
    assert!(sink.sent.is_empty(), "poll_ready 未就绪时不应写入任何帧");
}

/// 测试结束（包括 panic 展开）时递归删除临时数据目录。
struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 6. 真实会话路径：`session_max_hours = 0` 时没有外层会话 deadline，假 hub 在
///    Welcome 后彻底停止读取，`session()` 必须在 1s 发送超时内返回 Err，
///    而不是卡到 20s ACK 超时或永久挂起。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_send_timeout_exits_when_server_stops_reading_with_session_max_hours_zero() {
    // 假 hub：WS 握手 -> 读第一条 Hello -> 发 Welcome -> 不再 poll socket。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑定假 hub 失败");
    let addr = listener.local_addr().expect("读取假 hub 监听地址失败");

    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("假 hub 接受连接失败");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("假 hub WebSocket 握手失败");

        let hello = ws
            .next()
            .await
            .expect("agent 未发送 Hello")
            .expect("读取 Hello 失败");
        assert!(matches!(hello, Message::Binary(_)), "Hello 必须是二进制帧");

        let welcome = Frame::Welcome(Welcome {
            agent_id: "a".into(),
            server_version: "test".into(),
            protocol: PROTOCOL_VERSION,
            sample_interval_ms: 1000,
            server_time: now_ms(),
        })
        .encode()
        .expect("Welcome 编码失败");
        ws.send(Message::Binary(welcome))
            .await
            .expect("发送 Welcome 失败");

        // 关键：不再 poll 这个 socket，但保持连接对象存活；内核接收缓冲填满后，
        // agent 的 16MiB 单帧写入必然阻塞，只能由发送超时结束。
        std::future::pending::<()>().await;
    });

    let data_dir = std::env::temp_dir().join(format!(
        "rustboard-agent-send-timeout-{}-{}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&data_dir).expect("创建临时数据目录失败");
    let _guard = TempDirGuard(data_dir.clone());
    std::fs::write(data_dir.join("agent.secret"), b"test-secret").expect("写入 agent.secret 失败");

    // 单帧 16MiB，远大于回环内核发送/接收缓冲，保证服务端停读后写操作真的阻塞。
    let mut buffer =
        DiskBuffer::open(&data_dir, 64 * 1024 * 1024, 0).expect("打开 DiskBuffer 失败");
    let batch = SampleBatch {
        agent_id: "a".into(),
        epoch: 1,
        seq: 1,
        boot_id: "b".into(),
        sent_at: now_ms(),
        samples: vec![Sample::new("m".repeat(16 * 1024 * 1024), now_ms(), 1.0)],
    };
    buffer.push(&batch).expect("写入超大 Batch 失败");
    let buffer = Arc::new(Mutex::new(buffer));

    let cfg = AgentConfig {
        data_dir: data_dir.clone(),
        send_timeout_secs: 1,
        session_max_hours: 0,
        ..Default::default()
    };
    let sample_interval = Arc::new(AtomicU64::new(1000));
    let ctx = SessionContext {
        cfg: &cfg,
        agent_id: "a",
        epoch: 1,
        boot: "b",
        jitter_seed_ms: 0,
        sample_interval: &sample_interval,
    };
    let notify = Arc::new(tokio::sync::Notify::new());

    let (ws, _response) = tokio_tungstenite::connect_async(format!("ws://{addr}/agent/ws"))
        .await
        .expect("连接假 hub 失败");

    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), session(ws, &ctx, &buffer, &notify))
        .await
        .expect("session() 必须在 10s 内退出；session_max_hours=0 不能让它永久挂起");
    let elapsed = started.elapsed();

    server.abort();
    let _ = server.await;

    let err = result.expect_err("服务端停止读取时 session() 必须返回 Err");
    println!("session() 在 {elapsed:?} 内退出，错误: {err:#}");
    assert!(
        is_send_timeout_error(&err) || err.to_string().contains("发送超时"),
        "错误必须体现发送超时: {err:#}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "必须在发送超时（1s）附近退出，而不是 20s ACK 超时；实际耗时 {elapsed:?}"
    );
}
