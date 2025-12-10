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

use derive_deftly::Deftly;
use futures::channel::mpsc;
use oneshot_fused_workaround as oneshot;

use tor_cell::chancell::msg::{self as chanmsg};
use tor_cell::relaycell::StreamId;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_rtcompat::DynTimeProvider;

use reactor::{RelayCtrlCmd, RelayCtrlMsg};

use crate::circuit::celltypes::derive_deftly_template_RestrictedChanMsgSet;

/// A subclass of ChanMsg that can correctly arrive on a live relay
/// circuit (one where a CREATE* has been received).
#[derive(Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[derive_deftly(RestrictedChanMsgSet)]
#[deftly(usage = "on an open relay circuit")]
#[cfg(feature = "relay")]
#[cfg_attr(not(test), allow(unused))] // TODO(relay)
pub(crate) enum RelayCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A relay early cell that is allowed to contain a CREATE message.
    RelayEarly(chanmsg::RelayEarly),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    /// A cell telling us to enable/disable channel padding.
    PaddingNegotiate(chanmsg::PaddingNegotiate),
}

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
    /// The stream is closed by sending a control message (`ClosePendingStream`)
    /// to the reactor.
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

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    #[test]
    fn relay_circ_chan_msg() {
        use tor_cell::chancell::msg::{self, AnyChanMsg};
        fn good(m: AnyChanMsg) {
            use crate::relay::RelayCircChanMsg;
            assert!(RelayCircChanMsg::try_from(m).is_ok());
        }
        fn bad(m: AnyChanMsg) {
            use crate::relay::RelayCircChanMsg;
            assert!(RelayCircChanMsg::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        bad(msg::CreatedFast::new(&b"The great globular mass"[..]).into());
        bad(msg::Created2::new(&b"of protoplasmic slush"[..]).into());
        good(msg::Relay::new(&b"undulated slightly,"[..]).into());
        good(msg::AnyChanMsg::RelayEarly(
            msg::Relay::new(&b"as if aware of him"[..]).into(),
        ));
        bad(msg::Versions::new([1, 2, 3]).unwrap().into());
        good(msg::PaddingNegotiate::start_default().into());
        good(msg::RelayEarly::from(msg::Relay::new(b"snail-like unipedular organism")).into());
    }
}
