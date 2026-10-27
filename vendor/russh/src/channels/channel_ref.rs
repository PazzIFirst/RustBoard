use tokio::sync::mpsc::Sender;

use super::WindowSizeRef;
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
        }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}

impl Drop for ChannelRef {
    fn drop(&mut self) {
        // The session owns the only `ChannelRef` of a channel and drops it
        // when the channel is closed by the peer, fails to open, or the
        // session ends. Notify writers blocked on a zero-sized send window so
        // they observe `BrokenPipe` instead of waiting forever (#97).
        self.window_size.close();
    }
}
