//! Tunnel module that will encompass a generic tunnel wrapping around a circuit reactor that can
//! be single or multi path.

pub mod circuit;
mod halfstream;
#[cfg(feature = "send-control-msg")]
pub(crate) mod msghandler;
pub(crate) mod reactor;
mod streammap;

use derive_deftly::Deftly;
use derive_more::Display;
use futures::SinkExt as _;
use oneshot_fused_workaround as oneshot;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::circuit::UniqId;
use crate::crypto::cell::HopNum;
use crate::stream::StreamRateLimit;
use crate::{Error, Result};
use circuit::ClientCirc;
use circuit::{handshake, StreamMpscSender};
use reactor::{CtrlMsg, FlowCtrlMsg};

use postage::watch;
use tor_async_utils::SinkCloseChannel as _;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{RelayCellFormat, StreamId};
use tor_memquota::derive_deftly_template_HasMemoryCost;

/// The unique identifier of a tunnel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("{}", _0)]
pub(crate) struct TunnelId(u64);

impl TunnelId {
    /// Create a new TunnelId.
    ///
    /// # Panics
    ///
    /// Panics if we have exhausted the possible space of u64 IDs.
    pub(crate) fn next() -> TunnelId {
        /// The next unique tunnel ID.
        static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        assert!(id != 0, "Exhausted Tunnel ID space?!");
        TunnelId(id)
    }
}

/// The identifier of a circuit [`UniqId`] within a tunnel.
///
/// This type is only needed for logging purposes: a circuit's [`UniqId`] is
/// process-unique, but in the logs it's often useful to display the
/// owning tunnel's ID alongside the circuit identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Display)]
#[display("Circ {}.{}", tunnel_id, circ_id.display_chan_circ())]
pub(crate) struct TunnelScopedCircId {
    /// The identifier of the owning tunnel
    tunnel_id: TunnelId,
    /// The process-unique identifier of the circuit
    circ_id: UniqId,
}

impl TunnelScopedCircId {
    /// Create a new [`TunnelScopedCircId`] from the specified identifiers.
    pub(crate) fn new(tunnel_id: TunnelId, circ_id: UniqId) -> Self {
        Self { tunnel_id, circ_id }
    }

    /// Return the [`UniqId`].
    pub(crate) fn unique_id(&self) -> UniqId {
        self.circ_id
    }
}

/// A precise position in a tunnel.
#[derive(Debug, Deftly, Copy, Clone, PartialEq, Eq)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
pub enum HopLocation {
    /// A specific position in a tunnel.
    Hop((UniqId, HopNum)),
    /// The join point of a multi-path tunnel.
    JoinPoint,
}

/// A position in a tunnel.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetHop {
    /// A specific position in a tunnel.
    Hop(HopLocation),
    /// The last hop of a tunnel.
    ///
    /// This should be used only when you don't care about what specific hop is used.
    /// Some tunnels may be extended or truncated,
    /// which means that the "last hop" may change at any time.
    LastHop,
}

impl From<(UniqId, HopNum)> for HopLocation {
    fn from(v: (UniqId, HopNum)) -> Self {
        HopLocation::Hop(v)
    }
}

impl From<(UniqId, HopNum)> for TargetHop {
    fn from(v: (UniqId, HopNum)) -> Self {
        TargetHop::Hop(v.into())
    }
}

impl HopLocation {
    /// Return the hop number if not a JointPoint.
    pub fn hop_num(&self) -> Option<HopNum> {
        match self {
            Self::Hop((_, hop_num)) => Some(*hop_num),
            Self::JoinPoint => None,
        }
    }
}

/// Internal handle, used to implement a stream on a particular circuit.
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
    hop: HopLocation,
    /// Reactor ID for this stream.
    stream_id: StreamId,
    /// Encoding to use for relay cells sent on this stream.
    ///
    /// This is mostly irrelevant, except when deciding
    /// how many bytes we can pack in a DATA message.
    relay_cell_format: RelayCellFormat,
    /// A [`Stream`](futures::Stream) that provides updates to the rate limit for sending data.
    // TODO(arti#2068): we should consider making this an `Option`
    rate_limit_stream: watch::Receiver<StreamRateLimit>,
    /// Channel to send cells down.
    tx: StreamMpscSender<AnyRelayMsg>,
    /// Reference to the circuit that this stream is on.
    // TODO(conflux): this should be a ClientTunnel
    circ: Arc<ClientCirc>,
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
    /// [`End::new_misc()`](tor_cell::relaycell::msg::End::new_misc) message over a `ClientCirc`.
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
        message: reactor::CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::ClosePendingStream {
                stream_id: self.stream_id,
                hop: self.hop,
                message,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx)
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
    /// circuit needs to shut down.
    pub(crate) fn protocol_error(&mut self) {
        self.circ.protocol_error();
    }

    /// Request to send a SENDME cell for this stream.
    ///
    /// This sends a request to the circuit reactor to send a stream-level SENDME, but it does not
    /// block or wait for a response from the circuit reactor.
    /// An error is only returned if we are unable to send the request.
    /// This means that if the circuit reactor is unable to send the SENDME, we are not notified of
    /// this here and an error will not be returned.
    pub(crate) fn send_sendme(&mut self) -> Result<()> {
        self.circ
            .control
            .unbounded_send(CtrlMsg::FlowCtrlUpdate {
                msg: FlowCtrlMsg::Sendme,
                stream_id: self.stream_id,
                hop: self.hop,
            })
            .map_err(|_| Error::CircuitClosed)
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
        self.circ
            .control
            .unbounded_send(CtrlMsg::FlowCtrlUpdate {
                msg: FlowCtrlMsg::Xon(rate),
                stream_id: self.stream_id,
                hop: self.hop,
            })
            .map_err(|_| Error::CircuitClosed)
    }

    /// Return a reference to the circuit that this `StreamTarget` is using.
    #[cfg(any(feature = "experimental-api", feature = "stream-ctrl"))]
    pub(crate) fn circuit(&self) -> &Arc<ClientCirc> {
        &self.circ
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
