//! Tor stream handling.
//!
//! A stream is an anonymized conversation; multiple streams can be
//! multiplexed over a single circuit.

pub(crate) mod cmdcheck;
pub(crate) mod flow_ctrl;

#[cfg(any(feature = "hs-service", feature = "relay"))]
pub(crate) mod incoming;

pub(crate) mod queue;

use futures::SinkExt as _;
use oneshot_fused_workaround as oneshot;
use postage::watch;

use tor_async_utils::SinkCloseChannel as _;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_cell::relaycell::msg::{AnyRelayMsg, End};
use tor_cell::relaycell::{RelayCellFormat, StreamId};
use tor_memquota::mq_queue::{self, MpscSpec};

use flow_ctrl::state::StreamRateLimit;

use crate::{ClientTunnel, Error, HopLocation, Result};

use std::pin::Pin;
use std::sync::Arc;

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

/// Internal handle, used to implement a stream on a particular tunnel.
///
/// The reader and the writer for a stream should hold a `StreamTarget` for the stream;
/// the reader should additionally hold an `mpsc::Receiver` to get
/// relay messages for the stream.
///
/// When all the `StreamTarget`s for a stream are dropped, the Reactor will
/// close the stream by sending an END message to the other side.
/// You can close a stream earlier by using [`StreamTarget::close`]
/// or [`StreamTarget::close_pending`].
#[derive(Clone, Debug)]
pub(crate) struct StreamTarget {
    /// Which hop of the circuit this stream is with.
    pub(crate) hop: Option<HopLocation>,
    /// Reactor ID for this stream.
    pub(crate) stream_id: StreamId,
    /// Encoding to use for relay cells sent on this stream.
    ///
    /// This is mostly irrelevant, except when deciding
    /// how many bytes we can pack in a DATA message.
    pub(crate) relay_cell_format: RelayCellFormat,
    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    // TODO(arti#2068): we should consider making this an `Option`
    pub(crate) rate_limit_stream: watch::Receiver<StreamRateLimit>,
    /// Channel to send cells down.
    pub(crate) tx: StreamMpscSender<AnyRelayMsg>,
    /// Reference to the tunnel that this stream is on.
    pub(crate) tunnel: Tunnel,
}

/// A client or relay tunnel.
#[derive(Debug, Clone, derive_more::From)]
pub(crate) enum Tunnel {
    /// A client tunnel.
    Client(Arc<ClientTunnel>),
}

impl StreamTarget {
    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: AnyRelayMsg) -> Result<()> {
        self.tx.send(msg).await.map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Close the pending stream that owns this StreamTarget, delivering the specified
    /// END message (if any)
    ///
    /// The stream is closed by sending a [`CtrlMsg::ClosePendingStream`] message to the reactor.
    ///
    /// Returns a [`oneshot::Receiver`] that can be used to await the reactor's response.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    ///
    /// Note that in many cases, the actual contents of an END message can leak unwanted
    /// information. Please consider carefully before sending anything but an
    /// [`End::new_misc()`](tor_cell::relaycell::msg::End::new_misc) message over a `ClientTunnel`.
    /// (For onion services, we send [`DONE`](tor_cell::relaycell::msg::EndReason::DONE) )
    ///
    /// In addition to sending the END message, this function also ensures
    /// the state of the stream map entry of this stream is updated
    /// accordingly.
    ///
    /// Normally, you shouldn't need to call this function, as streams are implicitly closed by the
    /// reactor when their corresponding `StreamTarget` is dropped. The only valid use of this
    /// function is for closing pending incoming streams (a stream is said to be pending if we have
    /// received the message initiating the stream but have not responded to it yet).
    ///
    /// **NOTE**: This function should be called at most once per request.
    /// Calling it twice is an error.
    #[cfg(feature = "hs-service")]
    pub(crate) fn close_pending(
        &self,
        message: crate::stream::CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        match &self.tunnel {
            Tunnel::Client(t) => t.close_pending(self.stream_id, self.hop, message),
        }
    }

    /// Queue a "close" for the stream corresponding to this StreamTarget.
    ///
    /// Unlike `close_pending`, this method does not allow the caller to provide an `END` message.
    ///
    /// Once this method has been called, no more messages may be sent with [`StreamTarget::send`],
    /// on this `StreamTarget`` or any clone of it.
    /// The reactor *will* try to flush any already-send messages before it closes the stream.
    ///
    /// You don't need to call this method if the stream is closing because all of its StreamTargets
    /// have been dropped.
    pub(crate) fn close(&mut self) {
        Pin::new(&mut self.tx).close_channel();
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// tunnel needs to shut down.
    pub(crate) fn protocol_error(&mut self) {
        match &self.tunnel {
            Tunnel::Client(t) => t.terminate(),
        }
    }

    /// Request to send a SENDME cell for this stream.
    ///
    /// This sends a request to the circuit reactor to send a stream-level SENDME, but it does not
    /// block or wait for a response from the circuit reactor.
    /// An error is only returned if we are unable to send the request.
    /// This means that if the circuit reactor is unable to send the SENDME, we are not notified of
    /// this here and an error will not be returned.
    pub(crate) fn send_sendme(&mut self) -> Result<()> {
        match &self.tunnel {
            Tunnel::Client(t) => t.send_sendme(self.stream_id, self.hop),
        }
    }

    /// Inform the circuit reactor that there has been a change in the drain rate for this stream.
    ///
    /// Typically the circuit reactor would send this new rate in an XON message to the other end of
    /// the stream.
    /// But it may decide not to, and may discard this update.
    /// For example the stream may have a large amount of buffered data, and the reactor may not
    /// want to send an XON while the buffer is large.
    ///
    /// This sends a message to inform the circuit reactor of the new drain rate,
    /// but it does not block or wait for a response from the reactor.
    /// An error is only returned if we are unable to send the update.
    pub(crate) fn drain_rate_update(&mut self, rate: XonKbpsEwma) -> Result<()> {
        match &mut self.tunnel {
            Tunnel::Client(t) => t.drain_rate_update(self.stream_id, self.hop, rate),
        }
    }

    /// Return a reference to the tunnel that this `StreamTarget` is using.
    #[cfg(any(feature = "experimental-api", feature = "stream-ctrl"))]
    pub(crate) fn tunnel(&self) -> &Arc<ClientTunnel> {
        // TODO: this will need to change once we add a relay type
        match &self.tunnel {
            Tunnel::Client(t) => t,
        }
    }

    /// Return the kind of relay cell in use on this `StreamTarget`.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        self.relay_cell_format
    }

    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    pub(crate) fn rate_limit_stream(&self) -> &watch::Receiver<StreamRateLimit> {
        &self.rate_limit_stream
    }
}
