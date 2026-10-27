use std::borrow::BorrowMut;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::AsyncRead;

use super::{ChannelMsg, ChannelReadHalf};

#[derive(Debug)]
pub struct ChannelRx<R> {
    channel: R,
    buffer: Option<(ChannelMsg, usize)>,

    ext: Option<u32>,

    /// Set once a terminal message (`Eof`, `Close`) or the end of the channel
    /// queue has been observed. Later reads keep returning EOF instead of
    /// polling a closed receiver again.
    eof: bool,
}

impl<R> ChannelRx<R> {
    pub fn new(channel: R, ext: Option<u32>) -> Self {
        Self {
            channel,
            buffer: None,
            ext,
            eof: false,
        }
    }
}

impl<R: BorrowMut<ChannelReadHalf>> ChannelRx<R> {
    fn finish(&mut self) {
        self.eof = true;
        self.buffer = None;
        self.channel.borrow_mut().receiver.close();
    }
}

impl<R> AsyncRead for ChannelRx<R>
where
    R: BorrowMut<ChannelReadHalf> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-length read is not EOF and must not consume channel data.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.eof {
                return Poll::Ready(Ok(()));
            }

            let (msg, mut idx) = match self.buffer.take() {
                Some(msg) => msg,
                None => match ready!(self.channel.borrow_mut().receiver.poll_recv(cx)) {
                    Some(msg) => (msg, 0),
                    None => {
                        self.finish();
                        return Poll::Ready(Ok(()));
                    }
                },
            };

            match (&msg, self.ext) {
                (ChannelMsg::Data { data }, None) => {
                    // RFC 4251 §5 allows zero-length strings and RFC 4254
                    // §5.2 does not require CHANNEL_DATA to be non-empty.
                    // An empty frame is not EOF: skip it and keep polling.
                    if idx >= data.len() {
                        continue;
                    }
                    let readable = buf.remaining().min(data.len() - idx);

                    // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                    #[allow(clippy::indexing_slicing)]
                    buf.put_slice(&data[idx..idx + readable]);
                    idx += readable;

                    if idx != data.len() {
                        self.buffer = Some((msg, idx));
                    }

                    return Poll::Ready(Ok(()));
                }
                (ChannelMsg::ExtendedData { data, ext }, Some(target)) if *ext == target => {
                    if idx >= data.len() {
                        continue;
                    }
                    let readable = buf.remaining().min(data.len() - idx);

                    // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                    #[allow(clippy::indexing_slicing)]
                    buf.put_slice(&data[idx..idx + readable]);
                    idx += readable;

                    if idx != data.len() {
                        self.buffer = Some((msg, idx));
                    }

                    return Poll::Ready(Ok(()));
                }
                (ChannelMsg::Eof, _) | (ChannelMsg::Close, _) => {
                    self.finish();
                    return Poll::Ready(Ok(()));
                }
                // Everything else (channel requests/replies, window
                // adjustments, data for another extended-data stream, ...) is
                // not part of this reader's byte stream. Poll the channel
                // again instead of waking ourselves: the old `wake_by_ref`
                // turned a queued ignored message into a busy loop, and a
                // terminal frame behind it was never reached.
                _ => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use bytes::Bytes;
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    use super::*;

    fn plain_reader(ext: Option<u32>) -> (mpsc::Sender<ChannelMsg>, ChannelRx<ChannelReadHalf>) {
        let (sender, receiver) = mpsc::channel(16);
        (sender, ChannelRx::new(ChannelReadHalf { receiver }, ext))
    }

    #[derive(Default)]
    struct CountingWaker(AtomicUsize);

    impl Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// #96: RFC 4251 §5 permits zero-length strings, so an empty
    /// CHANNEL_DATA frame is a legal no-op, not EOF.
    #[tokio::test]
    async fn empty_data_frames_are_skipped_not_eof() {
        let (sender, mut reader) = plain_reader(None);
        for msg in [
            ChannelMsg::Data { data: Bytes::new() },
            ChannelMsg::Data {
                data: Bytes::from_static(b"first"),
            },
            ChannelMsg::Data { data: Bytes::new() },
            ChannelMsg::Data { data: Bytes::new() },
            ChannelMsg::Data {
                data: Bytes::from_static(b"second"),
            },
            ChannelMsg::Eof,
        ] {
            sender.send(msg).await.unwrap();
        }
        drop(sender);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"firstsecond");
    }

    /// #96: a SFTP read_u32/read_exact split across frames with an empty frame
    /// in the middle must still assemble the full packet.
    #[tokio::test]
    async fn empty_data_in_the_middle_of_a_framed_read() {
        let (sender, mut reader) = plain_reader(None);
        for data in [
            &b"\x00\x00"[..],
            &b""[..],
            &b"\x00\x05"[..],
            &b""[..],
            &b""[..],
            &b"hello"[..],
        ] {
            sender
                .send(ChannelMsg::Data {
                    data: Bytes::copy_from_slice(data),
                })
                .await
                .unwrap();
        }
        drop(sender);

        let mut prefix = [0u8; 4];
        reader.read_exact(&mut prefix).await.unwrap();
        assert_eq!(u32::from_be_bytes(prefix), 5);

        let mut payload = [0u8; 5];
        reader.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");

        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    /// #96: `Eof` alone must end the stream while the sender is still alive.
    /// Dropping the sender first would fall back to the "sender closed" EOF
    /// path and mask a broken `Eof` branch.
    #[tokio::test]
    async fn eof_after_data_is_normal_eof() {
        let (sender, mut reader) = plain_reader(None);
        sender
            .send(ChannelMsg::Data {
                data: Bytes::from_static(b"payload"),
            })
            .await
            .unwrap();
        sender.send(ChannelMsg::Eof).await.unwrap();
        // Keep the sender alive on purpose: only the Eof frame may end the read.

        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_to_end(&mut out),
        )
        .await
        .expect("Eof must end the stream while the sender is alive")
        .unwrap();
        assert_eq!(out, b"payload");

        let mut again = [0u8; 4];
        assert_eq!(reader.read(&mut again).await.unwrap(), 0);
        drop(sender);
    }

    /// #96: CHANNEL_CLOSE also terminates the reader (with the sender still
    /// alive) and stays EOF afterwards.
    #[tokio::test]
    async fn close_ends_the_reader_permanently() {
        let (sender, mut reader) = plain_reader(None);
        sender
            .send(ChannelMsg::Data {
                data: Bytes::from_static(b"tail"),
            })
            .await
            .unwrap();
        sender.send(ChannelMsg::Close).await.unwrap();
        // Keep the sender alive on purpose: only the Close frame may end the read.

        let mut out = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read_to_end(&mut out),
        )
        .await
        .expect("Close must end the stream while the sender is alive")
        .unwrap();
        assert_eq!(out, b"tail");

        let mut again = [0u8; 4];
        assert_eq!(reader.read(&mut again).await.unwrap(), 0);
        drop(sender);
    }

    /// #96: a zero-capacity read is neither EOF nor allowed to consume data.
    #[tokio::test]
    async fn zero_length_read_does_not_consume_or_eof() {
        let (sender, mut reader) = plain_reader(None);
        sender
            .send(ChannelMsg::Data {
                data: Bytes::from_static(b"abc"),
            })
            .await
            .unwrap();

        let mut empty = [0u8; 0];
        assert_eq!(reader.read(&mut empty).await.unwrap(), 0);

        // The queued data must still be readable and the channel still open.
        let mut data = [0u8; 8];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reader.read(&mut data),
        )
        .await
        .expect("a zero-length read must not turn the channel into EOF")
        .unwrap();
        assert_eq!(&data[..read], b"abc");
        drop(sender);
    }

    /// #96: a dropped channel queue (sender end) is EOF, even after only
    /// empty data frames.
    #[tokio::test]
    async fn dropped_sender_is_eof_after_empty_frames() {
        let (sender, mut reader) = plain_reader(None);
        sender
            .send(ChannelMsg::Data { data: Bytes::new() })
            .await
            .unwrap();
        drop(sender);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty());
    }

    /// #96: a plain reader skips extended data; an extended reader skips
    /// plain data and other extension codes; empty matching frames are skipped.
    #[tokio::test]
    async fn extended_data_routing_skips_non_matching_frames() {
        let (sender, mut stdout_reader) = plain_reader(None);
        let (sender_ext, mut stderr_reader) = plain_reader(Some(1));
        for msg in [
            ChannelMsg::ExtendedData {
                data: Bytes::from_static(b"noise"),
                ext: 2,
            },
            ChannelMsg::Data {
                data: Bytes::from_static(b"stdout"),
            },
            ChannelMsg::Eof,
        ] {
            sender.send(msg).await.unwrap();
        }
        for msg in [
            ChannelMsg::Data {
                data: Bytes::from_static(b"stdout"),
            },
            ChannelMsg::ExtendedData {
                data: Bytes::new(),
                ext: 1,
            },
            ChannelMsg::ExtendedData {
                data: Bytes::from_static(b"noise"),
                ext: 2,
            },
            ChannelMsg::ExtendedData {
                data: Bytes::from_static(b"stderr"),
                ext: 1,
            },
            ChannelMsg::Eof,
        ] {
            sender_ext.send(msg).await.unwrap();
        }
        drop(sender);
        drop(sender_ext);

        let mut out = Vec::new();
        stdout_reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"stdout");

        let mut err = Vec::new();
        stderr_reader.read_to_end(&mut err).await.unwrap();
        assert_eq!(err, b"stderr");
    }

    /// #96: skipping a queued ignored message must not self-wake. The old
    /// implementation called `wake_by_ref` and then returned `Pending`
    /// forever, which is a busy loop that starves the runtime.
    #[test]
    fn ignored_messages_do_not_self_wake() {
        let (sender, receiver) = mpsc::channel(8);
        sender
            .try_send(ChannelMsg::ExtendedData {
                data: Bytes::from_static(b"stderr"),
                ext: 2,
            })
            .unwrap();
        let mut reader = ChannelRx::new(ChannelReadHalf { receiver }, None);

        let counter = Arc::new(CountingWaker::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);
        let mut storage = [0u8; 16];
        let mut buf = tokio::io::ReadBuf::new(&mut storage);

        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Pending
        ));
        assert_eq!(
            counter.0.load(Ordering::SeqCst),
            0,
            "ignored messages must not schedule a self-wake"
        );
        // Keep the sender alive: the reader must be waiting, not EOF.
        drop(sender);
    }
}
