use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{ready, Context, Poll};

use futures::FutureExt;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{Mutex, Notify, OwnedMutexGuard};

use bytes::Bytes;

use super::ChannelMsg;
use crate::ChannelId;
use crate::channels::{WindowSizeRef, closed_channel_io_error};

type BoxedThreadsafeFuture<T> = Pin<Box<dyn Sync + Send + std::future::Future<Output = T>>>;
type OwnedPermitFuture<S> =
    BoxedThreadsafeFuture<Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>>;

struct WatchNotification(Pin<Box<dyn Sync + Send + Future<Output = ()>>>);

/// A `Send`/`Sync` future that resolves when the mpsc receiver (the session)
/// is dropped. It owns a `Sender` clone so it can outlive the borrowed
/// `Sender::closed()` future.
fn session_closed_future<S>(sender: mpsc::Sender<S>) -> BoxedThreadsafeFuture<()>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    Box::pin(async move {
        sender.closed().await;
    })
}

/// A single future that becomes ready once the window size
/// changes to a positive value
impl WatchNotification {
    fn new(n: Arc<Notify>) -> Self {
        Self(Box::pin(async move { n.notified().await }))
    }
}

impl Future for WatchNotification {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.deref_mut().0.as_mut();
        ready!(inner.poll(cx));
        Poll::Ready(())
    }
}

pub struct ChannelTx<S> {
    sender: mpsc::Sender<S>,
    send_fut: Option<OwnedPermitFuture<S>>,
    id: ChannelId,
    window_size_fut: Option<BoxedThreadsafeFuture<OwnedMutexGuard<u32>>>,
    window_size: Arc<Mutex<u32>>,
    notify: Arc<Notify>,
    window_size_notication: WatchNotification,
    /// Shared with the session-side `ChannelRef`; set when the channel is
    /// closed (peer `CHANNEL_CLOSE`, open failure, session shutdown).
    window_closed: Option<Arc<AtomicBool>>,
    /// Owned clone of `sender` plus `Sender::closed()`: keeps a waiter
    /// registered for session shutdown between polls without borrowing the
    /// sender (which would make the struct self-referential).
    session_closed: BoxedThreadsafeFuture<()>,
    max_packet_size: u32,
    ext: Option<u32>,
}

impl<S> ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    pub fn new(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window_size: Arc<Mutex<u32>>,
        window_size_notification: Arc<Notify>,
        max_packet_size: u32,
        ext: Option<u32>,
    ) -> Self {
        let session_closed = session_closed_future(sender.clone());
        Self {
            sender,
            send_fut: None,
            id,
            notify: Arc::clone(&window_size_notification),
            window_size_notication: WatchNotification::new(window_size_notification),
            window_size,
            window_closed: None,
            session_closed,
            window_size_fut: None,
            max_packet_size,
            ext,
        }
    }

    /// Build a writer that also observes the channel-close flag shared with
    /// the session (`ChannelRef` drop). Used by
    /// [`ChannelWriteHalf::make_writer_ext`](crate::channels::ChannelWriteHalf::make_writer_ext).
    pub(crate) fn new_with_window(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window: WindowSizeRef,
        max_packet_size: u32,
        ext: Option<u32>,
    ) -> Self {
        let session_closed = session_closed_future(sender.clone());
        Self {
            sender,
            send_fut: None,
            id,
            notify: window.subscribe(),
            window_size_notication: WatchNotification::new(window.subscribe()),
            window_size: window.value_ref(),
            window_closed: Some(window.closed_ref()),
            session_closed,
            window_size_fut: None,
            max_packet_size,
            ext,
        }
    }

    /// Whether the channel/session is gone. All writes must fail with
    /// `BrokenPipe` once this is true.
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
            || self
                .window_closed
                .as_ref()
                .is_some_and(|closed| closed.load(Ordering::SeqCst))
    }

    /// Report whether the session is closed, keeping the session shutdown
    /// waiter registered between polls.
    fn watch_close(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.is_closed() {
            return Poll::Ready(());
        }
        ready!(self.session_closed.as_mut().poll(cx));
        Poll::Ready(())
    }

    fn poll_writable(
        &mut self,
        cx: &mut Context<'_>,
        buf_len: usize,
    ) -> Poll<io::Result<NonZeroUsize>> {
        loop {
            if self.is_closed() {
                return Poll::Ready(Err(closed_channel_io_error()));
            }

            let window_size = self.window_size.clone();
            let window_size_fut = self
                .window_size_fut
                .get_or_insert_with(|| Box::pin(window_size.lock_owned()));
            let mut window_size = match window_size_fut.poll_unpin(cx) {
                Poll::Ready(guard) => {
                    self.window_size_fut.take();
                    guard
                }
                Poll::Pending => {
                    // Wait for the window lock while still observing shutdown.
                    if self.window_size_notication.poll_unpin(cx).is_ready() {
                        self.window_size_notication =
                            WatchNotification::new(Arc::clone(&self.notify));
                        continue;
                    }
                    if self.watch_close(cx).is_ready() {
                        return Poll::Ready(Err(closed_channel_io_error()));
                    }
                    return Poll::Pending;
                }
            };

            let writable = (self.max_packet_size).min(*window_size).min(buf_len as u32) as usize;

            match NonZeroUsize::try_from(writable) {
                Ok(w) => {
                    *window_size -= writable as u32;
                    if *window_size > 0 {
                        self.notify.notify_one();
                    }
                    return Poll::Ready(Ok(w));
                }
                Err(_) => {
                    drop(window_size);
                    // Register for the window/close notification first, then
                    // re-check shutdown: `WindowSizeRef::close` uses
                    // `notify_waiters`, which has no permit, so the waiter has
                    // to be registered before the flag can be trusted.
                    if self.window_size_notication.poll_unpin(cx).is_ready() {
                        self.window_size_notication =
                            WatchNotification::new(Arc::clone(&self.notify));
                        // A window update raced with the zero-window check.
                        continue;
                    }
                    if self.watch_close(cx).is_ready() {
                        return Poll::Ready(Err(closed_channel_io_error()));
                    }
                    // No self-wake: we are woken by a window update, a channel
                    // close (`notify_waiters`) or the session shutdown.
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_mk_msg(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<(ChannelMsg, NonZeroUsize)>> {
        let writable = match ready!(self.poll_writable(cx, buf.len())) {
            Ok(writable) => writable,
            Err(err) => return Poll::Ready(Err(err)),
        };

        #[allow(clippy::indexing_slicing)] // Clamped to maximum `buf.len()` with `.poll_writable`
        let data = Bytes::copy_from_slice(&buf[..writable.into()]);

        let msg = match self.ext {
            None => ChannelMsg::Data { data },
            Some(ext) => ChannelMsg::ExtendedData { data, ext },
        };

        Poll::Ready(Ok((msg, writable)))
    }

    fn activate(&mut self, msg: ChannelMsg, writable: usize) -> &mut OwnedPermitFuture<S> {
        use futures::TryFutureExt;
        self.send_fut.insert(Box::pin(
            self.sender
                .clone()
                .reserve_owned()
                .map_ok(move |p| (p, msg, writable)),
        ))
    }

    fn handle_write_result(
        &mut self,
        r: Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>,
    ) -> Result<usize, io::Error> {
        self.send_fut = None;
        match r {
            Ok((permit, msg, writable)) => {
                permit.send((self.id, msg).into());
                Ok(writable)
            }
            Err(SendError(())) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
        }
    }
}

impl<S> AsyncWrite for ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    #[allow(clippy::too_many_lines)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "cannot send empty buffer",
            )));
        }
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            let (msg, writable) = match ready!(self.poll_mk_msg(cx, buf)) {
                Ok(msg) => msg,
                Err(err) => return Poll::Ready(Err(err)),
            };
            self.activate(msg, writable.into())
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx));
        Poll::Ready(self.handle_write_result(r))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            self.activate(ChannelMsg::Eof, 0)
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx)).map(|(p, _, _)| (p, ChannelMsg::Eof, 0));
        Poll::Ready(self.handle_write_result(r).map(drop))
    }
}

impl<S> Drop for ChannelTx<S> {
    fn drop(&mut self) {
        // Allow other writers to make progress
        self.notify.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::*;

    type TestMsg = (ChannelId, ChannelMsg);

    fn test_tx(window_size: WindowSizeRef) -> (ChannelTx<TestMsg>, mpsc::Receiver<TestMsg>) {
        let (sender, receiver) = mpsc::channel(8);
        (
            ChannelTx::new_with_window(sender, ChannelId(0), window_size, 4096, None),
            receiver,
        )
    }

    /// #97: a zero-window writer must return `BrokenPipe` on the next poll
    /// after the session receiver is dropped, instead of staying `Pending`.
    #[tokio::test]
    async fn zero_window_receiver_drop_returns_broken_pipe_on_repoll() {
        let (mut tx, receiver) = test_tx(WindowSizeRef::new(0));
        let mut write = Box::pin(poll_fn(|cx| Pin::new(&mut tx).poll_write(cx, b"data")));

        assert!(
            write.as_mut().now_or_never().is_none(),
            "zero-window write must wait for the window"
        );

        drop(receiver);

        let err = write
            .as_mut()
            .now_or_never()
            .expect("a closed session must make the writer ready")
            .expect_err("zero-window write on a closed session must fail");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// #97: the dropped session receiver must actively wake a writer that is
    /// already waiting for the window (the original bug left it pending
    /// forever and leaked the writer task).
    #[tokio::test]
    async fn zero_window_receiver_drop_wakes_blocked_writer() {
        let (mut tx, receiver) = test_tx(WindowSizeRef::new(0));
        let write = tokio::spawn(
            async move { poll_fn(|cx| Pin::new(&mut tx).poll_write(cx, b"data")).await },
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!write.is_finished());

        drop(receiver);

        let result = tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .expect("session close must wake the blocked writer")
            .expect("writer task must not panic");
        assert_eq!(
            result
                .expect_err("zero-window write on a closed session must fail")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// #97: a peer `CHANNEL_CLOSE` (session alive, channel gone) must also
    /// wake window waiters with `BrokenPipe`.
    #[tokio::test]
    async fn zero_window_channel_close_wakes_blocked_writer() {
        let window = WindowSizeRef::new(0);
        let (mut tx, _receiver) = test_tx(window.clone());
        let write = tokio::spawn(
            async move { poll_fn(|cx| Pin::new(&mut tx).poll_write(cx, b"data")).await },
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!write.is_finished());

        window.close();

        let result = tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .expect("channel close must wake the blocked writer")
            .expect("writer task must not panic");
        assert_eq!(
            result
                .expect_err("zero-window write on a closed channel must fail")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    /// #97: fixing the shutdown path must not break the normal window-update
    /// wakeup.
    #[tokio::test]
    async fn zero_window_update_still_wakes_blocked_writer() {
        let window = WindowSizeRef::new(0);
        let (mut tx, mut receiver) = test_tx(window.clone());
        let write = tokio::spawn(
            async move { poll_fn(|cx| Pin::new(&mut tx).poll_write(cx, b"data")).await },
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!write.is_finished());

        window.update(4096).await;

        let written = tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .expect("window update must wake the blocked writer")
            .expect("writer task must not panic")
            .expect("write must succeed after the window update");
        assert_eq!(written, 4);

        match receiver.recv().await.unwrap() {
            (ChannelId(0), ChannelMsg::Data { data }) => assert_eq!(&data[..], b"data"),
            msg => panic!("unexpected message: {msg:?}"),
        }
    }
}
