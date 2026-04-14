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

use futures::channel::mpsc;

use tor_cell::chancell::CircId;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::Runtime;

use crate::channel::Channel;
use crate::circuit::circhop::{CircHopOutbound, HopSettings};
use crate::circuit::reactor::Reactor as BaseReactor;
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::circuit::reactor::stream;
use crate::circuit::{CircuitRxReceiver, UniqId};
use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
use crate::memquota::CircuitAccount;
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::backward::Backward;
use crate::relay::reactor::forward::Forward;

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
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
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
        memquota: &CircuitAccount,
    ) -> crate::Result<(Self, Arc<RelayCirc>)> {
        // NOTE: not registering this channel with the memquota subsystem is okay,
        // because it has no buffering (if ever decide to make the size of this buffer
        // non-zero for whatever reason, we must remember to register it with memquota
        // so that it counts towards the total memory usage for the circuit.
        #[allow(clippy::disallowed_methods)]
        let (stream_tx, stream_rx) = mpsc::channel(0);

        let mut hop_mgr = HopMgr::new(
            runtime.clone(),
            unique_id,
            StreamHandler,
            stream_tx,
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
        let forward_foo = Forward::new(
            unique_id,
            crypto_out,
            chan_provider,
            fwd_ev_tx,
            memquota.clone(),
        );
        let backward_foo = Backward::new(crypto_in);

        let (inner, handle) = BaseReactor::new(
            runtime,
            channel,
            circ_id,
            unique_id,
            input,
            forward_foo,
            backward_foo,
            hop_mgr,
            padding_ctrl,
            padding_event_stream,
            stream_rx,
            fwd_ev_rx,
            memquota,
        );

        let reactor = Self(inner);
        let handle = Arc::new(RelayCirc(handle));

        Ok((reactor, handle))
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::circuit::reactor::test::{AllowAllStreamsFilter, rmsg_to_ccmsg};
    use crate::circuit::{CircParameters, CircuitRxSender};
    use crate::client::circuit::padding::new_padding;
    use crate::congestion::test_utils::params::build_cc_vegas_params;
    use crate::crypto::cell::RelayCellBody;
    use crate::crypto::cell::{InboundRelayLayer, OutboundRelayLayer};
    use crate::fake_mpsc;
    use crate::memquota::SpecificAccount as _;
    use crate::relay::channel::test::{DummyChan, DummyChanProvider, working_dummy_channel};
    use crate::stream::flow_ctrl::params::FlowCtrlParameters;
    use crate::stream::incoming::{IncomingStream, IncomingStreamRequestFilter};

    use futures::{AsyncReadExt as _, SinkExt as _, StreamExt as _};
    use tracing_test::traced_test;

    use tor_cell::chancell::{ChanCell, ChanCmd, msg as chanmsg};
    use tor_cell::relaycell::{
        AnyRelayMsgOuter, RelayCellFormat, RelayCmd, StreamId, msg as relaymsg,
    };
    use tor_linkspec::{EncodedLinkSpec, LinkSpec};
    use tor_protover::{Protocols, named};
    use tor_rtcompat::SpawnExt;
    use tor_rtcompat::{DynTimeProvider, Runtime};
    use tor_rtmock::MockRuntime;

    use chanmsg::{AnyChanMsg, DestroyReason, HandshakeType};
    use relaymsg::SendmeTag;

    use std::net::IpAddr;
    use std::sync::{Arc, Mutex, mpsc};

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
        fn spawn_reactor<R: Runtime>(rt: &R) -> Self {
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

            let (reactor, relay_circ) = Reactor::new(
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
                &CircuitAccount::new_noop(),
            )
            .unwrap();

            rt.spawn(async {
                let _ = reactor.run().await;
            })
            .unwrap();

            Self {
                relay_circ,
                circmsg_send,
                recognized_tx,
                inbound_chan,
                outbound_chan,
            }
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

        /// Whether the reactor opened an outbound channel
        /// (i.e. a channel to the next relay in the circuit).
        fn outbound_chan_launched(&self) -> bool {
            self.outbound_chan.lock().unwrap().is_some()
        }

        /// Allow inbound stream requests.
        ///
        /// Used for testing leaky pipe and exit functionality.
        async fn allow_stream_requests<'a, FILT>(
            &self,
            allow_commands: &'a [RelayCmd],
            filter: FILT,
        ) -> impl futures::Stream<Item = IncomingStream> + use<'a, FILT>
        where
            FILT: IncomingStreamRequestFilter,
        {
            Arc::clone(&self.relay_circ)
                .allow_stream_requests(allow_commands, filter)
                .await
                .unwrap()
        }

        /// Perform the CREATE2 handshake.
        async fn do_create2_handshake(
            &mut self,
            rt: &MockRuntime,
            expected_hs_type: HandshakeType,
        ) {
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
            let created2 = chanmsg::Created2::new(handshake);
            // ...and then finalize the handshake by pretending to be
            // the responding relay
            self.write_outbound(circid, chanmsg::AnyChanMsg::Created2(created2));
            rt.advance_until_stalled().await;
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

    /// Assert that the relay circuit is shutting down.
    ///
    /// Also asserts that the next cell on the inbound channel
    /// is a DESTROY with the specified `reason`.
    /// The test is expected to drain the inbound Tor "channel"
    /// of any non-ending cells it might be expecting before calling this function.
    fn assert_circuit_destroyed(ctrl: &mut ReactorTestCtrl, reason: DestroyReason) {
        assert!(ctrl.is_closing());

        let cell = ctrl.read_inbound();

        match cell.msg() {
            chanmsg::AnyChanMsg::Destroy(d) => {
                assert_eq!(d.reason(), reason);
            }
            _ => panic!("unexpected ending {cell:?}"),
        }
    }

    #[traced_test]
    #[test]
    fn reject_extend2_relay() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let mut ctrl = ReactorTestCtrl::spawn_reactor(&rt);
            rt.advance_until_stalled().await;

            let linkspecs = dummy_linkspecs();
            let extend2 = relaymsg::Extend2::new(linkspecs, HandshakeType::NTOR_V3, vec![]).into();
            ctrl.send_fwd(None, extend2, Recognized::Yes, false).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain("got EXTEND2 in a RELAY cell?!"));
            assert!(!ctrl.outbound_chan_launched());
            assert_circuit_destroyed(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn extend_and_forward() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let mut ctrl = ReactorTestCtrl::spawn_reactor(&rt);
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
                "Launched channel to the next hop circ_id=Circ 8.17"
            ));
            assert!(ctrl.outbound_chan_launched());
            assert!(!ctrl.is_closing());

            ctrl.do_create2_handshake(&rt, handshake_type).await;
            assert!(logs_contain("Got CREATED2 response from next hop"));
            assert!(logs_contain("Extended circuit to the next hop"));

            // Time to forward a message to the next hop!
            let early = false;
            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap();
            ctrl.send_fwd(None, begin.clone().into(), Recognized::No, early)
                .await;
            rt.advance_until_stalled().await;

            macro_rules! expect_cell {
                ($chanmsg:tt, $relaymsg:tt) => {{
                    let cell = ctrl.read_outbound();
                    let msg = match cell.msg() {
                        chanmsg::AnyChanMsg::$chanmsg(m) => {
                            let body = m.clone().into_relay_body();
                            AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, body).unwrap()
                        }
                        _ => panic!("unexpected forwarded {cell:?}"),
                    };

                    match msg.msg() {
                        relaymsg::AnyRelayMsg::$relaymsg(m) => m.clone(),
                        _ => panic!("unexpected cell {msg:?}"),
                    }
                }};
            }

            // Ensure the other end received the BEGIN cell
            let recvd_begin = expect_cell!(Relay, Begin);
            assert_eq!(begin, recvd_begin);

            // Now send the same message again, but this time in a RELAY_EARLY
            let early = true;
            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap();
            ctrl.send_fwd(None, begin.clone().into(), Recognized::No, early)
                .await;
            rt.advance_until_stalled().await;
            let recvd_begin = expect_cell!(RelayEarly, Begin);
            assert_eq!(begin, recvd_begin);
        });
    }

    #[traced_test]
    #[test]
    fn forward_before_extend() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let mut ctrl = ReactorTestCtrl::spawn_reactor(&rt);
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
            assert_circuit_destroyed(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    fn reject_invalid_begin() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let mut ctrl = ReactorTestCtrl::spawn_reactor(&rt);
            rt.advance_until_stalled().await;

            let _streams = ctrl
                .allow_stream_requests(&[RelayCmd::BEGIN], AllowAllStreamsFilter)
                .await;

            let begin = relaymsg::Begin::new("127.0.0.1", 1111, 0).unwrap().into();

            // BEGIN cells *must* have a stream ID, so expect the reactor to reject this
            // and close the circuit
            ctrl.send_fwd(None, begin, Recognized::Yes, false).await;
            rt.advance_until_stalled().await;

            assert!(logs_contain(
                "Invalid stream ID [scrubbed] for relay command BEGIN"
            ));
            assert_circuit_destroyed(&mut ctrl, DestroyReason::NONE);
        });
    }

    #[traced_test]
    #[test]
    #[ignore] // TODO(relay): Sad trombone, this is not yet supported
    fn data_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            const TO_SEND: &[u8] = b"The bells were musical in the silvery sun";

            let mut ctrl = ReactorTestCtrl::spawn_reactor(&rt);
            rt.advance_until_stalled().await;

            let mut incoming_streams = ctrl
                .allow_stream_requests(&[RelayCmd::BEGIN], AllowAllStreamsFilter)
                .await;

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
}
