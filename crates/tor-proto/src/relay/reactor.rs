//! Module exposing the relay circuit reactor subsystem.
//!
//! See [`reactor`](crate::circuit::reactor) for a description of the overall architecture.
//!
//! #### `ForwardReactor`
//!
//! It handles
//!
//!  * unrecognized RELAY cells, by moving them in the forward direction (towards the exit)
//!  * recognized RELAY cells, by splitting each cell into messages, and handling
//!    each message individually as described in the table below
//!    (Note: since prop340 is not yet implemented, in practice there is only 1 message per cell).
//!  * RELAY_EARLY cells (**not yet implemented**)
//!  * DESTROY cells (**not yet implemented**)
//!  * PADDING_NEGOTIATE cells (**not yet implemented**)
//!
//! ```text
//!
//! Legend: `F` = "forward reactor", `B` = "backward reactor", `S` = "stream reactor"
//!
//! | RELAY cmd         | Received in | Handled in | Description                            |
//! |-------------------|-------------|------------|----------------------------------------|
//! | DROP              | F           | F          | Passed to PaddingController for        |
//! |                   |             |            | validation                             |
//! |-------------------|-------------|------------|----------------------------------------|
//! | EXTEND2           | F           |            | Handled by instructing the channel     |
//! |                   |             |            | provider to launch a new channel, and  |
//! |                   |             |            | waiting for the new channel on its     |
//! |                   |             |            | outgoing_chan_rx receiver              |
//! |                   |             |            | (**not yet implemented**)              |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TRUNCATE          | F           | F          | (**not yet implemented**)              |
//! |                   |             |            |                                        |
//! |-------------------|-------------|------------|----------------------------------------|
//! | TODO              |             |            |                                        |
//! |                   |             |            |                                        |
//! ```

pub(crate) mod backward;
pub(crate) mod forward;

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use futures::channel::mpsc;

use tor_cell::chancell::CircId;
use tor_cell::relaycell::RelayCmd;
use tor_linkspec::OwnedChanTarget;
use tor_memquota::mq_queue::{ChannelSpec, MpscSpec};
use tor_rtcompat::{DynTimeProvider, Runtime};

use crate::channel::Channel;
use crate::circuit::circhop::ReactorStreamComponents;
use crate::circuit::circhop::{CircHopOutbound, HopSettings};
use crate::circuit::reactor::Reactor as BaseReactor;
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::circuit::reactor::stream;
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::congestion::sendme::StreamRecvWindow;
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::{CircuitAccount, SpecificAccount};
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::backward::Backward;
use crate::relay::reactor::forward::Forward;
use crate::stream::flow_ctrl::xon_xoff::reader::XonXoffReaderCtrl;
use crate::stream::incoming::{
    IncomingCmdChecker, IncomingStream, IncomingStreamRequestFilter, IncomingStreamRequestHandler,
    StreamReqInfo,
};
use crate::stream::raw::StreamReceiver;
use crate::stream::{RECV_WINDOW_INIT, StreamComponents, StreamTarget, Tunnel};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::{PaddingController, PaddingEventStream};

/// Type-alias for the relay base reactor type.
type RelayBaseReactor<R> = BaseReactor<R, Forward, Backward>;

/// The entry point of the circuit reactor subsystem.
#[allow(unused)] // TODO(relay)
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub(crate) struct Reactor<R: Runtime>(RelayBaseReactor<R>);

/// A handler customizing the relay stream reactor.
struct StreamHandler;

impl stream::StreamHandler for StreamHandler {
    fn halfstream_expiry(&self, hop: &CircHopOutbound) -> Duration {
        let ccontrol = hop.ccontrol();

        // Note: if we have no measurements for the RTT, this will be set to 0,
        // so the stream will be removed from the stream map immediately,
        // and any subsequent messages arriving on it will trigger
        // a proto violation causing the circuit to close.
        //
        // TODO(relay-tuning): we should make sure that this doesn't cause us to
        // wrongly close legitimate circuits that still have in-flight stream data
        ccontrol
            .lock()
            .expect("poisoned lock")
            .rtt()
            .max_rtt_usec()
            .map(|rtt| Duration::from_millis(u64::from(rtt)))
            // TODO(relay): we should fallback to a non-zero default here
            // if we don't have any RTT measurements yet
            .unwrap_or_default()
    }
}

#[allow(unused)] // TODO(relay)
impl<R: Runtime> Reactor<R> {
    /// Create a new circuit reactor.
    ///
    /// Returns the [`Reactor`], a [`RelayCirc`] handle to it,
    /// and a [`Stream`](futures::Stream) of `IncomingStream`s.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    ///
    /// The returned `IncomingStream`s are exit, dns, or directory streams.
    /// An incoming stream is automatically rejected by the reactor
    /// if the provided `IncomingStreamRequestFilter` rejects it.
    /// You can also explicitly reject a stream by calling [`IncomingStream::reject`].
    /// If the `Stream` is dropped, the next incoming stream request
    /// (`BEGIN`, `BEGIN_DIR`, or RESOLVE`)
    /// on this circuit will cause the stream reactor to shut down,
    /// which will trigger a shutdown of all the circuit reactors (FWD, BWD),
    /// which causing the circuit to close.
    ///
    /// The streams not rejected by the `IncomingStreamRequestFilter` will
    /// get an entry in the circuit's stream map.
    /// Rejecting such a stream using [`IncomingStream::reject`] will remove the entry.
    ///
    /// The `IncomingStreamRequestFilter` should only perform inexpensive checks
    /// that won't block the reactor.
    /// More expensive, or blocking checks, should be handled outside of the circuit reactor,
    /// when processing new `IncomingStream`s from the returned Rust stream.
    ///
    /// Data and directory streams can be accepted by calling [`IncomingStream::accept_data`].
    /// The caller is responsible for proxying data between the resulting `DataStream`
    /// and the local application stream.
    ///
    // TODO(relay): say how RESOLVE streams should be handled
    //
    // TODO: declare a type-alias for the impl futures::Stream return type
    // when support for impl in type aliases gets stabilized.
    //
    // See issue #63063 <https://github.com/rust-lang/rust/issues/63063>
    //
    // TODO(DEDUP): the incoming stream handling is *very* similar
    // to the impll from ServiceOnionServiceDataTunnel::allow_stream_requests.
    // We should dedupe these someday, when we rewrite the client reactor
    // to use the new multi-reactor architecture
    #[allow(clippy::too_many_arguments)] // TODO
    pub(crate) fn new(
        runtime: R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        crypto_in: Box<dyn InboundRelayLayer + Send>,
        crypto_out: Box<dyn OutboundRelayLayer + Send>,
        settings: &HopSettings,
        chan_provider: Arc<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
        padding_ctrl: PaddingController,
        padding_event_stream: PaddingEventStream,
        incoming_filter: Box<dyn IncomingStreamRequestFilter>,
        allowed_stream_cmds: &[RelayCmd],
        memquota: &CircuitAccount,
    ) -> crate::Result<(
        Self,
        Arc<RelayCirc>,
        impl futures::Stream<Item = IncomingStream> + use<R>,
    )> {
        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        #[allow(clippy::disallowed_methods)]
        let (stream_tx, stream_rx) = mpsc::channel(0);

        /// The size of the channel receiving IncomingStreamRequestContexts.
        ///
        // TODO(relay-tuning): buffer size
        //
        // This is currently set to 2x the initial receive window,
        // the same as the buffer size we use for onion services.
        // This value was picked arbitrarily,
        // and is not necessarily tuned for relay needs.
        const INCOMING_BUFFER: usize = crate::stream::STREAM_READER_BUFFER;

        let time_provider = DynTimeProvider::new(runtime.clone());
        let (incoming_sender, incoming_receiver) = MpscSpec::new(INCOMING_BUFFER)
            .new_mq(time_provider.clone(), memquota.as_raw_account())?;

        // Our IncomingCmdChecker does not reject BEGIN, BEGIN_DIR, RESOLVE cells,
        // but that doesn't necessarily mean the stream will be accepted.
        // An incoming stream can still be rejected at a later stage,
        // by the IncomingStreamRequestFilter, or directly by the consumer of the
        // futures::Stream<Item = IncomingStream> (by calling IncomingStream::reject()).
        let cmd_checker = IncomingCmdChecker::new_any(allowed_stream_cmds);
        let incoming_handler = IncomingStreamRequestHandler {
            incoming_sender,
            hop_num: None,
            cmd_checker,
            filter: incoming_filter,
        };
        let mut hop_mgr = HopMgr::new_with_incoming_handler(
            runtime.clone(),
            unique_id,
            circ_id,
            StreamHandler,
            stream_tx,
            incoming_handler,
            memquota.clone(),
        );

        // On the relay side, we always have one "hop" (ourselves).
        //
        // Clients will need to call this function in response to CtrlMsg::Create
        // (TODO: for clients, we probably will need to store a bunch more state here)
        hop_mgr.add_hop(settings.clone())?;

        // TODO(relay): currently we don't need buffering on this channel,
        // but we might need it if we start using it for more than just EXTENDED2 events
        #[allow(clippy::disallowed_methods)]
        let (fwd_ev_tx, fwd_ev_rx) = mpsc::channel(0);
        let forward = Forward::new(
            channel,
            circ_id,
            unique_id,
            crypto_out,
            chan_provider,
            fwd_ev_tx,
            memquota.clone(),
        );
        let backward = Backward::new(crypto_in);

        let (inner, handle) = BaseReactor::new(
            runtime,
            channel,
            circ_id,
            unique_id,
            input,
            forward,
            backward,
            hop_mgr,
            padding_ctrl,
            padding_event_stream,
            stream_rx,
            fwd_ev_rx,
            memquota,
        );

        let reactor = Self(inner);
        let handle = Arc::new(RelayCirc(handle));

        // Note: tunnel is a bit of a misnomer for relays
        let tunnel = Arc::clone(&handle);
        // TODO(relay): this is more or less copy-pasta from client code
        let stream = incoming_receiver.map(move |req_ctx| {
            let StreamReqInfo {
                req,
                stream_id,
                hop,
                stream_components:
                    ReactorStreamComponents {
                        stream_inbound_rx,
                        stream_outbound_tx,
                        rate_limit_rx,
                        drain_rate_request_rx,
                    },
                memquota,
                relay_cell_format,
            } = req_ctx;

            // There is no originating hop if we're a relay
            debug_assert!(hop.is_none());

            let target = StreamTarget {
                tunnel: Tunnel::Relay(Arc::clone(&tunnel)),
                tx: stream_outbound_tx,
                hop: None,
                stream_id,
                relay_cell_format,
                rate_limit_stream: rate_limit_rx,
            };

            // can be used to build a reader that supports XON/XOFF flow control
            let xon_xoff_reader_ctrl =
                XonXoffReaderCtrl::new(drain_rate_request_rx, target.clone());

            let reader = StreamReceiver {
                target: target.clone(),
                receiver: stream_inbound_rx,
                recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
                ended: false,
            };

            let components = StreamComponents {
                stream_receiver: reader,
                target,
                memquota,
                xon_xoff_reader_ctrl,
            };

            IncomingStream::new(time_provider.clone(), req, components)
        });

        Ok((reactor, handle, stream))
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub(crate) async fn run(mut self) -> crate::Result<()> {
        self.0.run().await
    }
}

#[cfg(test)]
pub(crate) mod test {
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::circuit::reactor::test::{AllowAllStreamsFilter, rmsg_to_ccmsg};
    use crate::circuit::test::fake_mpsc;
    use crate::circuit::{CircParameters, CircuitRxSender};
    use crate::client::circuit::padding::new_padding;
    use crate::congestion::test_utils::params::build_cc_vegas_params;
    use crate::crypto::cell::RelayCellBody;
    use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
    use crate::relay::channel::test::{DummyChan, DummyChanProvider, working_dummy_channel};
    use crate::stream::flow_ctrl::params::FlowCtrlParameters;
    use crate::stream::incoming::{IncomingStream, IncomingStreamRequest};

    use futures::AsyncReadExt as _;
    use tracing_test::traced_test;

    use tor_cell::chancell::{ChanCell, ChanCmd, msg as chanmsg};
    use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, StreamId, msg as relaymsg};
    use tor_linkspec::{EncodedLinkSpec, HasRelayIds, LinkSpec};
    use tor_protover::{Protocols, named};
    use tor_rtcompat::SpawnExt;
    use tor_rtcompat::{DynTimeProvider, Runtime};
    use tor_rtmock::MockRuntime;

    use chanmsg::{AnyChanMsg, Destroy, DestroyReason, HandshakeType};
    use relaymsg::SendmeTag;

    use std::net::IpAddr;
    use std::sync::{Arc, Mutex, mpsc};
    use std::task::{Context, Poll, Waker};

    // An inbound encryption layer that doesn't do any crypto.
    struct DummyInboundCrypto {}

    // An outbound encryption layer that doesn't do any crypto.
    struct DummyOutboundCrypto {
        /// Channel for controlling whether the current cell is meant for us or not.
        ///
        /// Useful for tests that check if recognized/unrecognized
        /// cells are handled/forwarded correctly.
        recognized_rx: mpsc::Receiver<Recognized>,
    }

    const DUMMY_TAG: [u8; 20] = [1; 20];

    impl InboundRelayLayer for DummyInboundCrypto {
        fn originate(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) -> SendmeTag {
            DUMMY_TAG.into()
        }

        fn encrypt_inbound(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) {}
    }

    impl OutboundRelayLayer for DummyOutboundCrypto {
        fn decrypt_outbound(
            &mut self,
            _cmd: ChanCmd,
            _cell: &mut RelayCellBody,
        ) -> Option<SendmeTag> {
            // Note: this should never block.
            let recognized = self.recognized_rx.recv().unwrap();

            match recognized {
                Recognized::Yes => Some(DUMMY_TAG.into()),
                Recognized::No => None,
            }
        }
    }

    struct ReactorTestCtrl {
        /// The relay circuit handle.
        relay_circ: Arc<RelayCirc>,
        /// Mock channel -> circuit reactor MPSC channel.
        circmsg_send: CircuitRxSender,
        /// The inbound channel ("towards the client").
        inbound_chan: DummyChan,
        /// The outbound channel ("away from the client"), if any.
        ///
        /// Shared with the DummyChanProvider, which initializes this
        /// when the relay reactor launches a channel to the next hop
        /// via `get_or_launch()`.
        outbound_chan: Arc<Mutex<Option<DummyChan>>>,
        /// MPSC channel for telling the DummyOutboundCrypto that the next
        /// cell we're about to send to the reactor should be "recognized".
        recognized_tx: mpsc::Sender<Recognized>,
    }

    /// Whether a forward cell to send should be "recognized"
    /// or "unrecognized" by the relay under test.
    enum Recognized {
        /// Recognized
        Yes,
        /// Unrecognized
        No,
    }

    impl ReactorTestCtrl {
        /// Spawn a relay circuit reactor, returning a `ReactorTestCtrl` for
        /// controlling it.
        fn spawn_reactor<R: Runtime>(
            rt: &R,
            allowed_stream_cmds: &[RelayCmd],
        ) -> (Self, impl futures::Stream<Item = IncomingStream>) {
            let inbound_chan = working_dummy_channel(rt);
            let circid = CircId::new(1337).unwrap();
            let unique_id = UniqId::new(8, 17);
            let (padding_ctrl, padding_stream) = new_padding(DynTimeProvider::new(rt.clone()));
            let (circmsg_send, circmsg_recv) = fake_mpsc(64);
            let params = CircParameters::new(
                true,
                build_cc_vegas_params(),
                FlowCtrlParameters::defaults_for_tests(),
            );
            let settings = HopSettings::from_params_and_caps(
                crate::circuit::circhop::HopNegotiationType::Full,
                &params,
                &[named::FLOWCTRL_CC].into_iter().collect::<Protocols>(),
            )
            .unwrap();

            let outbound_chan = Arc::new(Mutex::new(None));
            let (recognized_tx, recognized_rx) = mpsc::channel();
            let chan_provider = Arc::new(DummyChanProvider::new(
                rt.clone(),
                Arc::clone(&outbound_chan),
            ));

            let (reactor, relay_circ, incoming_streams) = Reactor::new(
                rt.clone(),
                &Arc::clone(&inbound_chan.channel),
                circid,
                unique_id,
                circmsg_recv,
                Box::new(DummyInboundCrypto {}),
                Box::new(DummyOutboundCrypto { recognized_rx }),
                &settings,
                chan_provider,
                padding_ctrl,
                padding_stream,
                Box::new(AllowAllStreamsFilter),
                allowed_stream_cmds,
                &CircuitAccount::new_noop(),
            )
            .unwrap();

            rt.spawn(async {
                let _ = reactor.run().await;
            })
            .unwrap();

            let ctrl = Self {
                relay_circ,
                circmsg_send,
                recognized_tx,
                inbound_chan,
                outbound_chan,
            };

            (ctrl, incoming_streams)
        }

        /// Simulate the sending of a forward relay message through our relay.
        async fn send_fwd(
            &mut self,
            id: Option<StreamId>,
            msg: relaymsg::AnyRelayMsg,
            recognized: Recognized,
            early: bool,
        ) {
            // This a bit janky, but for each forward cell we send to the reactor
            // we need to send a bit of metadata to the DummyOutboundLayer
            // specifying whether the cell should be treated as recognized
            // or unrecognized
            self.recognized_tx.send(recognized).unwrap();
            self.circmsg_send
                .send(rmsg_to_ccmsg(id, msg, early))
                .await
                .unwrap();
        }

        /// Simulate the sending of a forward channel message through our relay.
        async fn send_fwd_cmsg(&mut self, msg: chanmsg::AnyChanMsg) {
            self.circmsg_send.send(msg).await.unwrap();
        }

        /// Whether the reactor opened an outbound channel
        /// (i.e. a channel to the next relay in the circuit).
        fn outbound_chan_launched(&self) -> bool {
            self.outbound_chan.lock().unwrap().is_some()
        }

        /// Perform the CREATE2 handshake.
        async fn do_create2_handshake(
            &mut self,
            rt: &MockRuntime,
            expected_hs_type: HandshakeType,
        ) -> Option<CircId> {
            // First, check that the reactor actually sent a CREATE2 to the next hop...
            let (circid, msg) = self.read_outbound().into_circid_and_msg();
            let _create2 = match msg {
                chanmsg::AnyChanMsg::Create2(c) => {
                    assert_eq!(c.handshake_type(), expected_hs_type);
                    c
                }
                _ => panic!("unexpected forwarded {msg:?}"),
            };

            let handshake = vec![];
            let created2 = chanmsg::Created2::new(handshake.clone());
            // ...and then finalize the handshake by pretending to be
            // the responding relay
            self.write_outbound(circid, chanmsg::AnyChanMsg::Created2(created2));
            rt.advance_until_stalled().await;

            // Make sure we actually did send an EXTENDED2 towards the client
            let msg = self.read_inbound();
            let rmsg = match msg.msg() {
                chanmsg::AnyChanMsg::Relay(r) => AnyRelayMsgOuter::decode_singleton(
                    RelayCellFormat::V0,
                    r.clone().into_relay_body(),
                )
                .unwrap(),
                _ => panic!("unexpected forwarded {msg:?}"),
            };

            match rmsg.msg() {
                relaymsg::AnyRelayMsg::Extended2(e) => {
                    assert_eq!(e.clone().into_body(), handshake);
                }
                _ => panic!("unexpected relay message {rmsg:?}"),
            }

            circid
        }

        /// Whether the circuit is closing (e.g. due to a proto violation).
        fn is_closing(&self) -> bool {
            self.relay_circ.is_closing()
        }

        /// Read a cell from the inbound channel
        /// (moving towards the client).
        ///
        /// Panics if there are no ready cells on the inbound MPSC channel.
        fn read_inbound(&mut self) -> ChanCell<AnyChanMsg> {
            #[allow(deprecated)] // TODO(#2386)
            self.inbound_chan.rx.try_next().unwrap().unwrap()
        }

        /// Read a cell from the outbound channel
        /// (moving towards the next hop).
        ///
        /// Panics if there are no ready cells on the outbound MPSC channel.
        fn read_outbound(&mut self) -> ChanCell<AnyChanMsg> {
            let mut lock = self.outbound_chan.lock().unwrap();
            let chan = lock.as_mut().unwrap();
            #[allow(deprecated)] // TODO(#2386)
            chan.rx.try_next().unwrap().unwrap()
        }

        /// Write to the sending end of the outbound Tor channel.
        ///
        /// Simulates the receipt of a cell from the next hop.
        ///
        /// Panics if the outbound chan sender is full.
        fn write_outbound(&mut self, circid: Option<CircId>, msg: chanmsg::AnyChanMsg) {
            let mut lock = self.outbound_chan.lock().unwrap();
            let chan = lock.as_mut().unwrap();
            let cell = ChanCell::new(circid, msg);

            chan.tx.try_send(Ok(cell)).unwrap();
        }
    }

    fn dummy_linkspecs() -> Vec<EncodedLinkSpec> {
        vec![
            LinkSpec::Ed25519Id([43; 32].into()).encode().unwrap(),
            LinkSpec::RsaId([45; 20].into()).encode().unwrap(),
            LinkSpec::OrPort("127.0.0.1".parse::<IpAddr>().unwrap(), 999)
                .encode()
                .unwrap(),
        ]
    }

    /// Assert that we have sent a DESTROY cell with the specified `reason`
    /// both towards the "client" and towards the "next hop", if there is one,
    /// and that the relay circuit is shutting down.
    ///
    /// The test is expected to drain the inbound Tor "channel"
    /// of any non-ending cells it might be expecting before calling this function.
    fn assert_destroy_sent(ctrl: &mut ReactorTestCtrl, reason: DestroyReason) {
        assert!(ctrl.is_closing());

        macro_rules! assert_cell_is_destroy {
            ($cell:expr) => {{
                match $cell.msg() {
                    chanmsg::AnyChanMsg::Destroy(d) => {
                        assert_eq!(d.reason(), reason);
                    }
                    _ => panic!("unexpected ending {:?}", $cell),
                }
            }};
        }

        // We *always* send a DESTROY towards the client
        // when killing the circuit
        let cell = ctrl.read_inbound();
        assert_cell_is_destroy!(cell);

        // If there's an outbound channel, ensure we sent a DESTROY over it too.
        if ctrl.outbound_chan_launched() {
            let cell = ctrl.read_outbound();
            assert_cell_is_destroy!(cell);
        }
    }

    macro_rules! expect_cell {
        ($cell:expr, $chanmsg:tt, $relaymsg:tt) => {{
            let msg = match $cell.msg() {
                chanmsg::AnyChanMsg::$chanmsg(m) => {
                    let body = m.clone().into_relay_body();
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, body).unwrap()
                }
                _ => panic!("unexpected forwarded {:?}", $cell),
            };

            match msg.msg() {
                relaymsg::AnyRelayMsg::$relaymsg(m) => m.clone(),
                _ => panic!("unexpected cell {msg:?}"),
            }
        }};
    }

    #[traced_test]
    #[test]
    fn reject_extend2_relay() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            let linkspecs = dummy_linkspecs();
            let extend2 = relaymsg::Extend2::new(linkspecs, HandshakeType::NTOR_V3, vec![]).into();
            ctrl.send_fwd(None, extend2, Recognized::Yes, false).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain("got EXTEND2 in a RELAY cell?!"));
            assert!(!ctrl.outbound_chan_launched());
            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn reject_extend2_previous_hop() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // No outbound circuits yet
            assert!(!ctrl.outbound_chan_launched());

            // Build a linkspec with the identities of the dummy channel
            let mut linkspecs = ctrl
                .inbound_chan
                .channel
                .target()
                .identities()
                .map(|id| LinkSpec::from(id.to_owned()).encode())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Make sure this channel actually has some identities
            // (i.e. that it's not a client channel or something)
            assert_eq!(linkspecs.len(), 2);

            // There must be at least one IPv4 OR port address
            linkspecs.push(
                LinkSpec::OrPort("127.0.0.1".parse::<IpAddr>().unwrap(), 999)
                    .encode()
                    .unwrap(),
            );
            let handshake_type = HandshakeType::NTOR_V3;
            let extend2 = relaymsg::Extend2::new(linkspecs, handshake_type, vec![]).into();
            ctrl.send_fwd(None, extend2, Recognized::Yes, true).await;
            rt.advance_until_stalled().await;

            // The reactor handled the EXTEND2 and launched an outbound channel
            assert!(logs_contain("Cannot extend circuit to previous hop"));
            assert!(!ctrl.outbound_chan_launched());
            assert!(ctrl.is_closing());
        });
    }

    #[traced_test]
    #[test]
    fn extend_and_forward() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // No outbound circuits yet
            assert!(!ctrl.outbound_chan_launched());

            let linkspecs = dummy_linkspecs();
            let handshake_type = HandshakeType::NTOR_V3;
            let extend2 = relaymsg::Extend2::new(linkspecs, handshake_type, vec![]).into();
            ctrl.send_fwd(None, extend2, Recognized::Yes, true).await;
            rt.advance_until_stalled().await;

            // The reactor handled the EXTEND2 and launched an outbound channel
            assert!(logs_contain(
                "Launched channel to the next hop circ_uniq_id=Circ 8.17"
            ));
            assert!(ctrl.outbound_chan_launched());
            assert!(!ctrl.is_closing());

            let _circid = ctrl.do_create2_handshake(&rt, handshake_type).await;
            assert!(logs_contain("Got CREATED2 response from next hop"));
            assert!(logs_contain("Extended circuit to the next hop"));

            // Time to forward a message to the next hop!
            let early = false;
            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap();
            ctrl.send_fwd(None, begin.clone().into(), Recognized::No, early)
                .await;
            rt.advance_until_stalled().await;

            // Ensure the other end received the BEGIN cell
            let cell = ctrl.read_outbound();
            let recvd_begin = expect_cell!(cell, Relay, Begin);
            assert_eq!(begin, recvd_begin);

            // Now send the same message again, but this time in a RELAY_EARLY
            let early = true;
            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap();
            ctrl.send_fwd(None, begin.clone().into(), Recognized::No, early)
                .await;
            rt.advance_until_stalled().await;
            let cell = ctrl.read_outbound();
            let recvd_begin = expect_cell!(cell, RelayEarly, Begin);
            assert_eq!(begin, recvd_begin);
        });
    }

    #[traced_test]
    #[test]
    fn forward_before_extend() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // Send an arbitrary unrecognized cell. The reactor should flag this as
            // a protocol violation, because we don't have an outbound channel to forward it on.
            let extend2 = relaymsg::End::new_misc().into();
            ctrl.send_fwd(None, extend2, Recognized::No, true).await;
            rt.advance_until_stalled().await;

            // The reactor handled the EXTEND2 and launched an outbound channel
            assert!(logs_contain(
                "Asked to forward cell before the circuit was extended?!"
            ));
            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn reject_invalid_begin() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap().into();

            // BEGIN cells *must* have a stream ID, so expect the reactor to reject this
            // and close the circuit
            ctrl.send_fwd(None, begin, Recognized::Yes, false).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain(
                "Invalid stream ID [scrubbed] for relay command BEGIN"
            ));
            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn destroy_from_client() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // Simulate the client sending us a DESTROY cell
            let destroy = Destroy::new(DestroyReason::PROTOCOL);
            ctrl.send_fwd_cmsg(destroy.into()).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain(
                "Received outbound DESTROY, circuit shutting down"
            ));

            // Ensure the destroy reason (PROTOCOL) is not propagated
            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn destroy_from_next_hop() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // Extend the circuit by another hop
            let linkspecs = dummy_linkspecs();
            let handshake_type = HandshakeType::NTOR_V3;
            let extend2 = relaymsg::Extend2::new(linkspecs, handshake_type, vec![]).into();
            ctrl.send_fwd(None, extend2, Recognized::Yes, true).await;
            rt.advance_until_stalled().await;
            let circid = ctrl.do_create2_handshake(&rt, handshake_type).await;
            assert!(logs_contain("Extended circuit to the next hop"));
            assert!(ctrl.outbound_chan_launched());

            // Simulate the client sending us a DESTROY cell
            let destroy = Destroy::new(DestroyReason::PROTOCOL);
            ctrl.write_outbound(circid, destroy.into());
            rt.advance_until_stalled().await;

            // We have *not* received an outbound destroy
            assert!(!logs_contain(
                "Received outbound DESTROY, circuit shutting down"
            ));

            // We received an inbound one (from the next hop)
            assert!(logs_contain(
                "Received inbound DESTROY, circuit shutting down"
            ));

            // Ensure the destroy reason (PROTOCOL) is not propagated
            // This will check that we've sent a DESTROY cell in both directions.
            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn truncate() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, _incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            // Simulate the client sending us a TRUNCATE cell
            let truncate = relaymsg::Truncate::default().into();
            ctrl.send_fwd(None, truncate, Recognized::Yes, false).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain(
                "Circuit protocol violation: TRUNCATE not allowed"
            ));

            assert_destroy_sent(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn data_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            const TO_SEND: &[u8] = b"The bells were musical in the silvery sun";

            let (mut ctrl, mut incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap().into();
            ctrl.send_fwd(StreamId::new(1), begin, Recognized::Yes, false)
                .await;
            rt.advance_until_stalled().await;

            let data = relaymsg::Data::new(TO_SEND).unwrap().into();
            ctrl.send_fwd(StreamId::new(1), data, Recognized::Yes, false)
                .await;

            // We should have a pending incoming stream
            let pending = incoming_streams.next().await.unwrap();

            // Accept it, and let's see what we have!
            let mut stream = pending
                .accept_data(relaymsg::Connected::new_empty())
                .await
                .unwrap();

            let mut recv_buf = [0_u8; TO_SEND.len()];
            stream.read_exact(&mut recv_buf).await.unwrap();
            assert_eq!(recv_buf, TO_SEND);
        });
    }

    #[traced_test]
    #[test]
    fn reject_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, mut incoming_streams) =
                ReactorTestCtrl::spawn_reactor(&rt, &[RelayCmd::BEGIN]);
            rt.advance_until_stalled().await;

            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap().into();
            ctrl.send_fwd(StreamId::new(1), begin, Recognized::Yes, false)
                .await;
            rt.advance_until_stalled().await;

            // We should have a pending incoming stream
            let pending = incoming_streams.next().await.unwrap();

            // Reject the stream, and wait for the reactor to finish sending the END
            let end = relaymsg::End::new_misc();
            pending.reject(end.clone()).await.unwrap();
            rt.advance_until_stalled().await;

            // The END cell written to the Tor channel should be the same as
            // the one we sent above, in reject().
            let cell = ctrl.read_inbound();
            let actual_end = expect_cell!(cell, Relay, End);
            assert_eq!(end.reason(), actual_end.reason());

            // Sending another message on this stream results is flagged
            // as a proto violation
            let data = relaymsg::Data::new(b"no dice").unwrap().into();
            ctrl.send_fwd(StreamId::new(1), data, Recognized::Yes, false)
                .await;
            rt.advance_until_stalled().await;

            assert!(logs_contain("Stream protocol violation"));
            assert!(logs_contain(
                "Unexpected RelayCmd(DATA) message on unknown stream 1"
            ));
        });
    }

    #[traced_test]
    #[test]
    fn only_allow_begin_dir() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (mut ctrl, mut incoming_streams) = ReactorTestCtrl::spawn_reactor(
                &rt,
                // The stream reactor will only accept BEGIN_DIR streams
                &[RelayCmd::BEGIN_DIR],
            );
            rt.advance_until_stalled().await;

            // Directory streams should be allowed (because BEGIN_DIR is allowed)...
            let begin_dir = relaymsg::BeginDir::default().into();
            ctrl.send_fwd(StreamId::new(1), begin_dir, Recognized::Yes, false)
                .await;
            rt.advance_until_stalled().await;

            let pending_dir_stream = incoming_streams.next().await.unwrap();
            assert!(matches!(
                pending_dir_stream.request(),
                IncomingStreamRequest::BeginDir(_)
            ));

            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap().into();
            ctrl.send_fwd(StreamId::new(2), begin, Recognized::Yes, false)
                .await;
            rt.advance_until_stalled().await;

            // ... but the exit stream is not
            assert!(logs_contain("stream reactor shut down"));
            assert!(logs_contain(
                "Stream protocol violation: Unexpected BEGIN on incoming stream circ_uniq_id=Circ 8.17"
            ));

            // The reactor won't create an IncomingStream,
            // because the stream request is rejected right away
            let mut noop_cx = Context::from_waker(Waker::noop());
            assert_eq!(
                incoming_streams.poll_next_unpin(&mut noop_cx).map(|_| ()),
                Poll::Pending
            );
        });
    }
}
