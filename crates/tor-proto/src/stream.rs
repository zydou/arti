//! Tor stream handling.
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.

pub(crate) mod cmdcheck;
pub(crate) mod flow_ctrl;

#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) mod incoming;

pub(crate) mod queue;

use tor_cell::relaycell::msg::End;
use tor_memquota::mq_queue::{self, MpscSpec};

/// MPSC queue relating to a stream (either inbound or outbound), sender
pub(crate) type StreamMpscSender<T> = mq_queue::Sender<T, MpscSpec>;
/// MPSC queue relating to a stream (either inbound or outbound), receiver
pub(crate) type StreamMpscReceiver<T> = mq_queue::Receiver<T, MpscSpec>;

/// A behavior to perform when closing a stream.
///
/// We don't use `Option<End>` here, since the behavior of `SendNothing` is so surprising
/// that we shouldn't let it pass unremarked.
#[derive(Clone, Debug)]
pub(crate) enum CloseStreamBehavior {
    /// Send nothing at all, so that the other side will not realize we have
    /// closed the stream.
    ///
    /// We should only do this for incoming onion service streams when we
    /// want to black-hole the client's requests.
    SendNothing,
    /// Send an End cell, if we haven't already sent one.
    SendEnd(End),
}

impl Default for CloseStreamBehavior {
    fn default() -> Self {
        Self::SendEnd(End::new_misc())
    }
}
