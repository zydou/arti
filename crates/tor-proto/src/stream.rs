//! Tor stream handling.
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.

pub(crate) mod cmdcheck;
pub(crate) mod flow_ctrl;

#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) mod incoming;

pub(crate) mod queue;

use tor_memquota::mq_queue::{self, MpscSpec};

/// MPSC queue relating to a stream (either inbound or outbound), sender
pub(crate) type StreamMpscSender<T> = mq_queue::Sender<T, MpscSpec>;
/// MPSC queue relating to a stream (either inbound or outbound), receiver
pub(crate) type StreamMpscReceiver<T> = mq_queue::Receiver<T, MpscSpec>;
