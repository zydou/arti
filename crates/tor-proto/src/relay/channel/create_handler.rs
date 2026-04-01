//! Handler for CREATE* cells.

use crate::FlowCtrlParameters;
use crate::ccparams::{
    Algorithm, AlgorithmDiscriminants, CongestionControlParams, CongestionWindowParams,
    FixedWindowParams, RoundTripEstimatorParams, VegasParams,
};
use crate::channel::Channel;
use crate::circuit::CircuitRxSender;
use crate::circuit::UniqId;
use crate::circuit::celltypes::{CreateRequest, CreateResponse};
use crate::circuit::circhop::{HopNegotiationType, HopSettings};
use crate::client::circuit::CircParameters;
use crate::client::circuit::padding::PaddingController;
use crate::crypto::cell::CryptInit as _;
use crate::crypto::cell::RelayLayer as _;
use crate::crypto::cell::tor1;
use crate::crypto::handshake::ServerHandshake as _;
use crate::crypto::handshake::fast::CreateFastServer;
use crate::memquota::SpecificAccount as _;
use crate::memquota::{ChannelAccount, CircuitAccount};
use crate::relay::RelayCirc;
use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::Reactor;
use std::sync::{Arc, RwLock, Weak};
use tor_cell::chancell::ChanMsg as _;
use tor_cell::chancell::CircId;
use tor_cell::chancell::msg::{CreatedFast, Destroy, DestroyReason};
use tor_error::{Bug, debug_report, into_internal, warn_report};
use tor_linkspec::OwnedChanTarget;
use tor_llcrypto::cipher::aes::Aes128Ctr;
use tor_llcrypto::d::Sha1;
use tor_memquota::mq_queue::ChannelSpec as _;
use tor_memquota::mq_queue::MpscSpec;
use tor_rtcompat::SpawnExt as _;
use tor_rtcompat::{DynTimeProvider, Runtime};
use tracing::warn;

/// Everything needed to handle CREATE* messages on channels.
#[derive(Debug)]
pub struct CreateRequestHandler {
    /// Something that can launch channels. Typically the `ChanMgr`.
    chan_provider: Weak<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
    /// Circuit-related network parameters.
    circ_net_params: RwLock<CircNetParameters>,
    // TODO(relay): We probably want the ntor key here as well.
}

impl CreateRequestHandler {
    /// Build a new [`CreateRequestHandler`].
    pub fn new(
        chan_provider: Weak<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
        circ_net_params: CircNetParameters,
    ) -> Self {
        Self {
            chan_provider,
            circ_net_params: RwLock::new(circ_net_params),
        }
    }

    /// Update the circuit parameters from a network consensus.
    pub fn update_params(&self, circ_net_params: CircNetParameters) {
        *self.circ_net_params.write().expect("rwlock poisoned") = circ_net_params;
    }

    /// Handle a CREATE* cell.
    ///
    /// This intentionally does not return a [`crate::Error`] so that we don't accidentally shut
    /// down the channel reactor when we really should be returning a DESTROY. Shutting down a
    /// channel may cause us to leak information about paths of circuits travelling through this
    /// relay. This is especially important here since we're handling data that is controllable from
    /// the other end of the circuit.
    pub(crate) fn handle_create<R: Runtime>(
        &self,
        runtime: &R,
        channel: &Arc<Channel>,
        circ_id: CircId,
        msg: CreateRequest,
        memquota: &ChannelAccount,
        circ_unique_id: UniqId,
    ) -> Result<(CreateResponse, RelayCircComponents), Destroy> {
        // TODO(relay): The log messages throughout could be very noisy, so should have rate limiting.
        // TODO(relay): A macro could probably help clean up the error handling paths here.

        // Perform the handshake crypto and build the response.
        let (response, hop_settings, crypto_out, crypto_in) = match msg {
            CreateRequest::CreateFast(msg) => {
                // TODO(relay): We should split this CREATE_FAST handling off into a helper.

                // TODO(relay): We might want to offload this to a CPU worker in the future.
                let server_result = CreateFastServer::server(
                    &mut rand::rng(),
                    &mut |_: &()| Some(()),
                    &[()],
                    msg.handshake(),
                );

                let (keygen, handshake_msg) = match server_result {
                    Ok(x) => x,
                    Err(ref e) => {
                        debug_report!(e, "Circuit {} handshake failed", msg.cmd());
                        return Err(Destroy::new(e.destroy_reason()));
                    }
                };

                let crypt = match tor1::CryptStatePair::<Aes128Ctr, Sha1>::construct(keygen) {
                    Ok(x) => x,
                    Err(e) => {
                        warn_report!(e, "Circuit {} crypt state construction failed", msg.cmd());
                        return Err(Destroy::new(DestroyReason::INTERNAL));
                    }
                };

                let circ_params = self
                    .circ_net_params
                    .read()
                    .expect("rwlock poisoned")
                    // CREATE_FAST always uses fixed-window flow control.
                    .as_circ_parameters(AlgorithmDiscriminants::FixedWindow);
                let circ_params = match circ_params {
                    Ok(x) => x,
                    Err(e) => {
                        warn_report!(e, "Unable to build `CircParameters` while handling CREATE*");
                        return Err(Destroy::new(DestroyReason::INTERNAL));
                    }
                };

                // TODO(relay): I think we might want to get these from the consensus instead?
                let protos = tor_protover::Protocols::default();

                // TODO(relay): I'm not sure if this is the right way to do this. It works for
                // CREATE_FAST, but we might want to rethink it for CREATE2.
                let hop_settings = HopSettings::from_params_and_caps(
                    HopNegotiationType::None,
                    &circ_params,
                    &protos,
                );
                let hop_settings = match hop_settings {
                    Ok(x) => x,
                    Err(e) => {
                        warn_report!(e, "Unable to build `HopSettings` while handling CREATE*");
                        return Err(Destroy::new(DestroyReason::INTERNAL));
                    }
                };

                let response = CreatedFast::new(handshake_msg);
                let response = CreateResponse::CreatedFast(response);

                let (crypto_out, crypto_in, _binding) = crypt.split_relay_layer();
                let (crypto_out, crypto_in) = (Box::new(crypto_out), Box::new(crypto_in));

                (response, hop_settings, crypto_out, crypto_in)
            }
            CreateRequest::Create2(_) => {
                // TODO(relay): We might want to offload this to a CPU worker in the future.
                // TODO(relay): Implement this.
                warn!("Rejecting {}; not implemented", msg.cmd());
                return Err(Destroy::new(DestroyReason::INTERNAL));
            }
        };

        let memquota = match CircuitAccount::new(memquota) {
            Ok(x) => x,
            Err(e) => {
                warn_report!(e, "Unable to build `CircuitAccount` while handling CREATE*");
                return Err(Destroy::new(DestroyReason::INTERNAL));
            }
        };

        // We use a large mpsc queue here since a circuit should never block the channel,
        // and we hope that memquota will help us if an attacker intentionally fills this buffer.
        // We use `10_000_000` since `usize::MAX` causes `futures::channel::mpsc` to panic.
        // TODO(relay): We should switch to an unbounded queue, but the circuit reactor is expecting
        // a bounded queue.
        let time_provider = DynTimeProvider::new(runtime.clone());
        let account = memquota.as_raw_account();
        let (sender, receiver) = match MpscSpec::new(10_000_000).new_mq(time_provider, account) {
            Ok(x) => x,
            Err(e) => {
                warn_report!(e, "Unable to create new mspc queue while handling CREATE*");
                return Err(Destroy::new(DestroyReason::INTERNAL));
            }
        };

        // TODO(relay): Do we really want a client padding machine here?
        let (padding_ctrl, padding_stream) =
            crate::client::circuit::padding::new_padding(DynTimeProvider::new(runtime.clone()));

        // Upgrade the channel provider, which in practice is the `ChanMgr` so this should not fail.
        let Some(chan_provider) = self.chan_provider.upgrade() else {
            warn!("Unable to upgrade weak `ChannelProvider` while handling CREATE*");
            return Err(Destroy::new(DestroyReason::INTERNAL));
        };

        // Build the relay circuit reactor.
        let reactor_result = Reactor::new(
            runtime.clone(),
            channel,
            circ_id,
            circ_unique_id,
            receiver,
            crypto_in,
            crypto_out,
            &hop_settings,
            chan_provider,
            padding_ctrl.clone(),
            padding_stream,
            &memquota,
        );

        let (reactor, circ) = match reactor_result {
            Ok(x) => x,
            Err(e) => {
                warn_report!(e, "Unable to build relay reactor while handling CREATE*");
                return Err(Destroy::new(DestroyReason::INTERNAL));
            }
        };

        // Start the reactor in a task.
        match runtime.spawn(async {
            match reactor.run().await {
                Ok(()) => {}
                Err(e) => {
                    debug_report!(e, "Relay circuit reactor exited with an error");
                }
            }
        }) {
            Ok(()) => {}
            Err(e) => {
                warn_report!(e, "Unable to spawn task while handling CREATE*");
                return Err(Destroy::new(DestroyReason::INTERNAL));
            }
        }

        Ok((
            response,
            RelayCircComponents {
                circ,
                sender,
                padding_ctrl,
            },
        ))
    }
}

/// A collection of objects built for a new relay circuit.
pub(crate) struct RelayCircComponents {
    /// The relay circuit handle.
    pub(crate) circ: Arc<RelayCirc>,
    /// Used to send data from the channel to the circuit reactor.
    pub(crate) sender: CircuitRxSender,
    /// The circuit's padding controller.
    pub(crate) padding_ctrl: PaddingController,
}

/// Congestion control network parameters.
#[derive(Debug, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct CongestionControlNetParams {
    /// Fixed-window algorithm parameters.
    pub fixed_window: FixedWindowParams,

    /// Vegas algorithm parameters for exit circuits.
    // NOTE: In this module we are handling CREATE* cells,
    // which only happens for non-hs circuits.
    // So we don't need to store the vegas hs parameters here.
    pub vegas_exit: VegasParams,

    /// Congestion window parameters.
    pub cwnd: CongestionWindowParams,

    /// RTT calculation parameters.
    pub rtt: RoundTripEstimatorParams,

    /// Flow control parameters to use for all streams on this circuit.
    pub flow_ctrl: FlowCtrlParameters,
}

/// Network consensus parameters for handling incoming circuits.
///
/// Unlike `CircParameters`,
/// this is unopinionated and contains all relevant consensus parameters,
/// which is needed when handling an incoming CREATE* request where the
/// circuit origin chooses the type/settings
/// (for example congestion control type) of the circuit.
#[derive(Debug, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct CircNetParameters {
    /// Whether we should include ed25519 identities when we send EXTEND2 cells.
    pub extend_by_ed25519_id: bool,

    /// Congestion control network parameters.
    pub cc: CongestionControlNetParams,
}

impl CircNetParameters {
    /// Convert the [`CircNetParameters`] into a [`CircParameters`].
    ///
    /// We expect the circuit creation handshake to know what congestion control algorithm was
    /// negotiated, and provide that as `algorithm`.
    //
    // We disable `unused` warnings at the root of tor-proto,
    // but it's nice to have here so we re-enable it.
    #[warn(unused)]
    fn as_circ_parameters(&self, algorithm: AlgorithmDiscriminants) -> Result<CircParameters, Bug> {
        // Unpack everything to make sure that we aren't missing anything
        // (otherwise clippy would warn).
        let Self {
            extend_by_ed25519_id,
            cc:
                CongestionControlNetParams {
                    fixed_window,
                    vegas_exit,
                    cwnd,
                    rtt,
                    flow_ctrl,
                },
        } = self;

        let algorithm = match algorithm {
            AlgorithmDiscriminants::FixedWindow => Algorithm::FixedWindow(*fixed_window),
            AlgorithmDiscriminants::Vegas => Algorithm::Vegas(*vegas_exit),
        };

        // TODO(arti#2442): The builder pattern here seems like a footgun.
        let cc = CongestionControlParams::builder()
            .alg(algorithm)
            .fixed_window_params(*fixed_window)
            .cwnd_params(*cwnd)
            .rtt_params(rtt.clone())
            .build()
            .map_err(into_internal!("Could not build `CongestionControlParams`"))?;

        Ok(CircParameters::new(
            *extend_by_ed25519_id,
            cc,
            flow_ctrl.clone(),
        ))
    }
}
