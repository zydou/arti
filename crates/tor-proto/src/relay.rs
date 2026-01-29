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
use either::Either;
use futures::StreamExt as _;
use oneshot_fused_workaround as oneshot;

use tor_cell::chancell::msg::{self as chanmsg};
use tor_cell::relaycell::StreamId;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_memquota::mq_queue::{ChannelSpec as _, MpscSpec};

use crate::Error;
use crate::circuit::celltypes::derive_deftly_template_RestrictedChanMsgSet;
use crate::circuit::reactor::CircReactorHandle;
use crate::circuit::reactor::{CtrlCmd, forward};
use crate::congestion::sendme::StreamRecvWindow;
use crate::memquota::SpecificAccount;
use crate::relay::reactor::backward::Backward;
use crate::relay::reactor::forward::Forward;
use crate::stream::flow_ctrl::xon_xoff::reader::XonXoffReaderCtrl;
use crate::stream::incoming::{
    IncomingCmdChecker, IncomingStream, IncomingStreamRequestFilter, StreamReqInfo,
};
use crate::stream::raw::StreamReceiver;
use crate::stream::{RECV_WINDOW_INIT, StreamComponents, StreamTarget, Tunnel};

use std::sync::Arc;

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

impl crate::util::msg::ToRelayMsg for RelayCircChanMsg {
    fn to_relay_msg(self) -> Either<chanmsg::Relay, Self> {
        use Either::*;
        use RelayCircChanMsg::*;

        match self {
            Relay(r) => Left(r),
            m => Right(m),
        }
    }
}

/// A handle for interacting with a relay circuit.
#[allow(unused)] // TODO(relay)
#[derive(Debug)]
pub struct RelayCirc(pub(crate) CircReactorHandle<Forward, Backward>);

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
        let _ = self.0.command.unbounded_send(CtrlCmd::Shutdown);
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.0.control.is_closed()
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

    /// Tell this reactor to begin allowing incoming stream requests,
    /// and to return those pending requests in an asynchronous stream.
    ///
    /// Ordinarily, these requests are rejected.
    ///
    /// Needed for exits. Middle relays should reject every incoming stream,
    /// either through the `filter` provided in `filter`,
    /// or by explicitly calling .reject() on each received stream.
    ///
    // TODO(relay): I think we will prefer using the .reject() approach
    // for this, because the filter is only meant for inexpensive quick
    // checks that are done immediately in the reactor (any blocking
    // in the filter will block the relay reactor main loop!).
    ///
    /// The user of the reactor **must** handle this stream
    /// (either by .accept()ing and opening and proxying the corresponding
    /// streams as appropriate, or by .reject()ing).
    ///
    // TODO: declare a type-alias for the return type when support for
    // impl in type aliases gets stabilized.
    //
    // See issue #63063 <https://github.com/rust-lang/rust/issues/63063>
    //
    /// There can only be one [`Stream`](futures::Stream) of this type created on a given reactor.
    /// If a such a [`Stream`](futures::Stream) already exists, this method will return
    /// an error.
    ///
    /// After this method has been called on a reactor, the reactor is expected
    /// to receive requests of this type indefinitely, until it is finally closed.
    /// If the `Stream` is dropped, the next request on this reactor will cause it to close.
    ///
    // TODO: Someday, we might want to allow a stream request handler to be
    // un-registered.  However, nothing in the Tor protocol requires it.
    //
    // TODO(DEDUP): *very* similar to ServiceOnionServiceDataTunnel::allow_stream_requests
    #[allow(unused)] // TODO(relay): call this from the task that creates the circ
    pub(crate) async fn allow_stream_requests<'a, FILT>(
        self: Arc<Self>,
        allow_commands: &'a [tor_cell::relaycell::RelayCmd],
        filter: FILT,
    ) -> crate::Result<impl futures::Stream<Item = IncomingStream> + use<'a, FILT>>
    where
        FILT: IncomingStreamRequestFilter,
    {
        let tunnel = Arc::clone(&self);
        /// The size of the channel receiving IncomingStreamRequestContexts.
        ///
        // TODO(relay-tuning): buffer size
        const INCOMING_BUFFER: usize = crate::stream::STREAM_READER_BUFFER;

        let (incoming_sender, incoming_receiver) = MpscSpec::new(INCOMING_BUFFER).new_mq(
            self.0.time_provider.clone(),
            tunnel.0.memquota.as_raw_account(),
        )?;

        let cmd_checker = IncomingCmdChecker::new_any(allow_commands);
        let (tx, rx) = oneshot::channel();
        let cmd = forward::CtrlCmd::AwaitStreamRequests {
            incoming_sender,
            cmd_checker,
            hop: None,
            filter: Box::new(filter),
            done: tx,
        };

        tunnel
            .0
            .command
            .unbounded_send(CtrlCmd::Forward(cmd))
            .map_err(|_| Error::CircuitClosed)?;

        // Check whether the AwaitStreamRequest was processed successfully.
        rx.await.map_err(|_| Error::CircuitClosed)??;

        // TODO(relay): this is more or less copy-pasta from client code
        let stream = incoming_receiver.map(move |req_ctx| {
            let StreamReqInfo {
                req,
                stream_id,
                hop,
                receiver,
                msg_tx,
                rate_limit_stream,
                drain_rate_request_stream,
                memquota,
                relay_cell_format,
            } = req_ctx;

            // There is no originating hop if we're a relay
            debug_assert!(hop.is_none());

            let target = StreamTarget {
                tunnel: Tunnel::Relay(Arc::clone(&tunnel)),
                tx: msg_tx,
                hop: None,
                stream_id,
                relay_cell_format,
                rate_limit_stream,
            };

            // can be used to build a reader that supports XON/XOFF flow control
            let xon_xoff_reader_ctrl =
                XonXoffReaderCtrl::new(drain_rate_request_stream, target.clone());

            let reader = StreamReceiver {
                target: target.clone(),
                receiver,
                recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
                ended: false,
            };

            let components = StreamComponents {
                stream_receiver: reader,
                target,
                memquota,
                xon_xoff_reader_ctrl,
            };

            IncomingStream::new(self.0.time_provider.clone(), req, components)
        });

        Ok(stream)
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
