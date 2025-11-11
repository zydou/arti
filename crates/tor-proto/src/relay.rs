//! This module contains a WIP relay tunnel reactor.
//!
//! The initial version will duplicate some of the logic from
//! the client tunnel reactor.
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
use oneshot_fused_workaround as oneshot;

use tor_cell::relaycell::StreamId;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_rtcompat::DynTimeProvider;

use reactor::{RelayCtrlCmd, RelayCtrlMsg};

/// A handle for interacting with a relay circuit.
#[allow(unused)] // TODO(relay)
#[derive(Debug)]
pub struct RelayCirc {
    /// Sender for reactor control messages.
    control: mpsc::UnboundedSender<RelayCtrlMsg>,
    /// Sender for reactor control commands.
    command: mpsc::UnboundedSender<RelayCtrlCmd>,
    /// The time provider.
    time_provider: DynTimeProvider,
}

impl RelayCirc {
    /// Shut down this circuit, along with all streams that are using it.
    /// Happens asynchronously (i.e. the tunnel won't necessarily be done shutting down
    /// immediately after this function returns!).
    ///
    /// Note that other references to this tunnel may exist.
    /// If they do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done with a circuit:
    /// the circuit should close on its own once nothing is using it any more.
    pub fn terminate(&self) {
        let _ = self.command.unbounded_send(RelayCtrlCmd::Shutdown);
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.control.is_closed()
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
    //
    // TODO(relay): this duplicates the ClientTunnel API and docs. Do we care?
    pub(crate) fn drain_rate_update(
        &self,
        _stream_id: StreamId,
        _rate: XonKbpsEwma,
    ) -> crate::Result<()> {
        todo!()
    }

    /// Request to send a SENDME cell for this stream.
    ///
    /// This sends a request to the circuit reactor to send a stream-level SENDME, but it does not
    /// block or wait for a response from the circuit reactor.
    /// An error is only returned if we are unable to send the request.
    /// This means that if the circuit reactor is unable to send the SENDME, we are not notified of
    /// this here and an error will not be returned.
    //
    // TODO(relay): this duplicates the ClientTunnel API and docs. Do we care?
    pub(crate) fn send_sendme(&self, _stream_id: StreamId) -> crate::Result<()> {
        todo!()
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
    //
    // TODO(relay): this duplicates the ClientTunnel API and docs. Do we care?
    pub(crate) fn close_pending(
        &self,
        _stream_id: StreamId,
        _message: crate::stream::CloseStreamBehavior,
    ) -> crate::Result<oneshot::Receiver<crate::Result<()>>> {
        todo!()
    }
}
