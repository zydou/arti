//! This module contains a WIP relay tunnel reactor.
//!
//! The initial version will duplicate some of the logic from
//! the client tunnel from [`crate::client::reactor`].
//!
//! TODO(relay): refactor the relay tunnel
//! to share the same base tunnel implementation
//! as the client tunnel (to reduce code duplication).
//!
//! See the design notes at doc/dev/notes/relay-reactor.md

pub(crate) mod channel;
#[allow(unreachable_pub)] // TODO(relay): use in tor-chanmgr(?)
pub mod channel_provider;
pub(crate) mod reactor;

use futures::channel::mpsc;
use postage::broadcast;
use reactor::{RelayCtrlCmd, RelayCtrlMsg};

/// A handle for interacting with a [`RelayReactor`].
#[allow(unused)] // TODO(relay)
pub(crate) struct RelayReactorHandle {
    /// Sender for reactor control messages.
    control: mpsc::UnboundedSender<RelayCtrlMsg>,
    /// Sender for reactor control commands.
    command: mpsc::UnboundedSender<RelayCtrlCmd>,
    /// A broadcast receiver used to detect when the reactor is dropped.
    reactor_closed_rx: broadcast::Receiver<void::Void>,
}
