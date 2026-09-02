//! Handler for CREATE* cells.

use crate::FlowCtrlParameters;
use crate::ccparams::{
    AlgorithmDiscriminants, CongestionWindowParams, FixedWindowParams, RoundTripEstimatorParams,
    VegasParams,
};
use crate::channel::Channel;
use crate::circuit::celltypes::{CreateRequest, CreateResponse};
use crate::circuit::circhop::{HandshakeParamsError, HopSettings};
use crate::circuit::{
    CircuitRxSender, HandshakeSubprotocols, InvalidHandshakeSubprotocolError, UniqId,
};
use crate::client::circuit::padding::PaddingController;
use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::CryptInit as _;
use crate::crypto::cell::{
    CgoRelayCrypto, InboundRelayLayer, OutboundRelayLayer, RelayLayer, Tor1RelayCrypto,
};
use crate::crypto::handshake::RelayHandshakeError;
use crate::crypto::handshake::ServerHandshake as _;
use crate::crypto::handshake::fast::CreateFastServer;
use crate::crypto::handshake::ntor::{NtorSecretKey, NtorServer};
use crate::crypto::handshake::ntor_v3::{NtorV3SecretKey, NtorV3Server};
use crate::memquota::SpecificAccount as _;
use crate::memquota::{ChannelAccount, CircuitAccount};
use crate::relay::channel_provider::ChannelProvider;
use crate::relay::reactor::Reactor;
use crate::relay::{IncomingStreamRequestFilter, RelayCirc};
use crate::stream::IncomingStream;
use futures::channel::mpsc;
use futures::{SinkExt, Stream};
use smallvec::SmallVec;
use std::sync::{Arc, RwLock, Weak};
use tor_cell::chancell::ChanMsg as _;
use tor_cell::chancell::CircId;
use tor_cell::chancell::msg::{
    CreateFast, Created2, CreatedFast, Destroy, DestroyReason, HandshakeType,
};
use tor_cell::relaycell::RelayCmd;
use tor_cell::relaycell::extend::{
    CcRequest, CcResponse, CircRequestExt, CircResponseExt, SubprotocolRequest,
};
use tor_error::{ErrorKind, HasKind, debug_report, internal, into_internal, warn_report};
use tor_linkspec::OwnedChanTarget;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::mq_queue::ChannelSpec as _;
use tor_memquota::mq_queue::MpscSpec;
use tor_relay_crypto::pk::{RelayNtorKeypair, RelayNtorKeys};
use tor_rtcompat::SpawnExt as _;
use tor_rtcompat::{DynTimeProvider, Runtime};
use tracing::{debug, trace};

/// Everything needed to handle CREATE* messages on channels.
#[derive(derive_more::Debug)]
pub struct CreateRequestHandler {
    /// Something that can launch channels. Typically the `ChanMgr`.
    chan_provider: Weak<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
    /// Circuit-related network parameters.
    circ_net_params: RwLock<CircNetParameters>,
    /// The circuit extension keys.
    #[debug(skip)]
    ntor_keys: RwLock<RelayNtorKeys>,
    /// An [`IncomingStreamRequestFilter`] factory for checking whether the user wants
    /// this request, or wants to reject it immediately.
    ///
    /// Used for obtaining a current [`IncomingStreamRequestFilter`]
    /// for building a circuit reactor.
    //
    // TODO(relay): it's likely this will end up changing quite a bit once we start
    // figuring out exactly how the config/reconfigure() logic and IncomingStreamRequestFilter
    // should function for relays.
    #[debug(skip)]
    incoming_filter_factory: Box<dyn IncomingStreamRequestFilterFactory + Send + Sync>,
    /// The allowed incoming stream commands.
    ///
    /// Used for rejecting BEGIN and RESOLVE if we are not configured to be an exit.
    ///
    // TODO(relay): we might use this for rejecting BEGIN_DIR too,
    // if we decide to allow relays to opt out of being dir mirrors.
    // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4107/diffs#note_3426447
    allowed_stream_cmds: SmallVec<[RelayCmd; 3]>,
    /// A sender for the [`Stream`]s of `IncomingStream` of all circuits.
    ///
    /// The receiver will receive one [`Stream`] (of tor streams) per circuit.
    ///
    /// This being a bounded MPSC might seem a bit risky, because in theory,
    /// if the receiver is not reading fast enough, sending will block.
    /// In practice, however, it should never block (or buffer very much at all,
    /// for that matter), because the user (arti-relay) is expected to read from
    /// this in a tight loop, and spawn a task for handling each [`Stream`].
    ///
    /// Note: because this MPSC is not associated with any particular circuit or channel,
    /// it does not participate in the memquota system (see [crate::memquota]).
    #[debug(skip)]
    circuit_stream_tx: mpsc::Sender<Box<dyn Stream<Item = IncomingStream> + Send + Sync + Unpin>>,
}

// We make the CREATE-handling methods of `CreateRequestHandler` async
// since we expect that in the future we may want to offload the crypto to a worker thread.
#[expect(clippy::unused_async)]
impl CreateRequestHandler {
    /// Build a new [`CreateRequestHandler`], and a [`CircuitIncomingStreamReceiver`]
    /// for receiving new streams that are opened on any incoming circuits.
    pub fn new(
        chan_provider: Weak<dyn ChannelProvider<BuildSpec = OwnedChanTarget> + Send + Sync>,
        circ_net_params: CircNetParameters,
        ntor_keys: RelayNtorKeys,
        incoming_filter_factory: Box<dyn IncomingStreamRequestFilterFactory + Send + Sync>,
        allowed_stream_cmds: &[RelayCmd],
    ) -> (Self, CircuitIncomingStreamReceiver) {
        // TODO(relay-tuning): this MPSC can be a bottleneck,
        // as all the channels on this relay will want to send one item on it
        // each time a new circuit is created.
        //
        // The value set here is a guesstimate.
        const CIRC_STREAM_BUF_SIZE: usize = 1024;

        // This is not associated with any particular circuit
        // (it is for *all* circuits), so it doesn't participate in memquota
        // (see circuit_stream_tx docs)
        #[allow(clippy::disallowed_methods)]
        let (stream_tx, stream_rx) = mpsc::channel(CIRC_STREAM_BUF_SIZE);

        let handler = Self {
            chan_provider,
            circ_net_params: RwLock::new(circ_net_params),
            ntor_keys: RwLock::new(ntor_keys),
            incoming_filter_factory,
            allowed_stream_cmds: allowed_stream_cmds.into(),
            circuit_stream_tx: stream_tx,
        };

        let circuit_stream_rx = CircuitIncomingStreamReceiver {
            circuit_stream_rx: stream_rx,
        };

        (handler, circuit_stream_rx)
    }

    /// Update the circuit parameters from a network consensus.
    pub fn update_params(&self, circ_net_params: CircNetParameters) {
        *self.circ_net_params.write().expect("rwlock poisoned") = circ_net_params;
    }

    /// Update the handler with a new set of circuit extension keys.
    ///
    /// This is called periodically by the relay key rotation task.
    pub fn update_ntor_keys(&self, ntor_keys: RelayNtorKeys) {
        *self.ntor_keys.write().expect("rwlock poisoned") = ntor_keys;
    }

    /// Handle a CREATE* cell.
    ///
    /// This intentionally does not return a [`crate::Error`] so that we don't accidentally shut
    /// down the channel reactor when we really should be returning a DESTROY. Shutting down a
    /// channel may cause us to leak information about paths of circuits travelling through this
    /// relay. This is especially important here since we're handling data that is controllable from
    /// the other end of the circuit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_create<R: Runtime>(
        &self,
        runtime: &R,
        channel: &Arc<Channel>,
        our_ed25519_id: &Ed25519Identity,
        our_rsa_id: &RsaIdentity,
        circ_id: CircId,
        msg: &CreateRequest,
        memquota: &ChannelAccount,
        circ_unique_id: UniqId,
    ) -> Result<(CreateResponse, RelayCircComponents), Destroy> {
        let result = self
            .handle_create_inner(
                runtime,
                channel,
                our_ed25519_id,
                our_rsa_id,
                circ_id,
                msg,
                memquota,
                circ_unique_id,
            )
            .await;

        match result {
            Ok(x) => Ok(x),
            Err(e) => {
                // TODO(relay): The log messages throughout could be very noisy, so should have rate limiting.
                let cmd = msg.cmd();
                debug_report!(&e, %cmd, "Failed to handle circuit create request");

                // `tor-spec/tearing-down-circuits.md`:
                //
                // > Implementations SHOULD always use the NONE reason to avoid side channels: [...]
                Err(Destroy::new(DestroyReason::NONE))
            }
        }
    }

    /// See [`Self::handle_create`].
    #[allow(clippy::too_many_arguments)]
    async fn handle_create_inner<R: Runtime>(
        &self,
        runtime: &R,
        channel: &Arc<Channel>,
        our_ed25519_id: &Ed25519Identity,
        our_rsa_id: &RsaIdentity,
        circ_id: CircId,
        msg: &CreateRequest,
        memquota: &ChannelAccount,
        circ_unique_id: UniqId,
    ) -> Result<(CreateResponse, RelayCircComponents), HandleCreateError> {
        // Perform the handshake crypto and build the response.
        let handshake_components = match msg {
            CreateRequest::CreateFast(msg) => self.handle_create_fast(msg).await?,
            CreateRequest::Create2(msg) => match msg.handshake_type() {
                HandshakeType::NTOR_V3 => {
                    self.handle_create2_ntorv3(msg.body(), our_ed25519_id)
                        .await?
                }
                HandshakeType::NTOR => self.handle_create2_ntor(msg.body(), our_rsa_id).await?,
                x @ HandshakeType::TAP | x => {
                    return Err(HandleCreateError::Create2HandshakeType(x));
                }
            },
        };

        let memquota = CircuitAccount::new(memquota)?;

        // We use a large mpsc queue here since a circuit should never block the channel,
        // and we hope that memquota will help us if an attacker intentionally fills this buffer.
        // We use `10_000_000` since `usize::MAX` causes `futures::channel::mpsc` to panic.
        // TODO(relay): We should switch to an unbounded queue, but the circuit reactor is expecting
        // a bounded queue.
        let time_provider = DynTimeProvider::new(runtime.clone());
        let account = memquota.as_raw_account();
        let (sender, receiver) =
            MpscSpec::new(10_000_000).new_mq(time_provider.clone(), account)?;
        let (sender, receiver) = crate::circuit::circ_sender::channel(sender, receiver);

        // TODO(relay): Do we really want a client padding machine here?
        let (padding_ctrl, padding_stream) =
            crate::client::circuit::padding::new_padding(DynTimeProvider::new(runtime.clone()));

        // Upgrade the channel provider, which in practice is the `ChanMgr` so this should not fail.
        let Some(chan_provider) = self.chan_provider.upgrade() else {
            return Err(internal!("Unable to upgrade weak `ChannelProvider`").into());
        };

        // Create an IncomingStreamRequestFilter for this circuit.
        // This will get applied to every stream request (BEGIN, BEGIN_DIR, RESOLVE)
        // arriving on the circuit.
        //
        // Note: once built, a circuit reactor's IncomingStreamRequestFilter cannot be changed
        // (it's fixed for the entire duration of the circuit).
        let incoming_filter = self.incoming_filter_factory.current_filter();

        // Build the relay circuit reactor.
        let (reactor, circ, incoming_streams) = Reactor::new(
            runtime.clone(),
            channel,
            circ_id,
            circ_unique_id,
            receiver,
            handshake_components.crypto_in,
            handshake_components.crypto_out,
            &handshake_components.hop_settings,
            chan_provider,
            padding_ctrl.clone(),
            padding_stream,
            incoming_filter,
            &self.allowed_stream_cmds,
            &memquota,
        )
        .map_err(into_internal!("Failed to start circuit reactor"))?;

        let mut circuit_stream_tx = self.circuit_stream_tx.clone();
        // Start the reactor in a task.
        let () = runtime.spawn(async move {
            if let Err(e) = circuit_stream_tx.send(Box::new(incoming_streams)).await {
                warn_report!(e, "IncomingStream handler disappeared?!");
                // If we get here, it means the relay stream handler task has gone away,
                // so there won't be anything handling the incoming streams.
                //
                // The reactor is dropped, making the RelayCirc returned below
                // in the RelayCircComponents unusable
                // (RelayCirc::is_closing() will return `true`).
                drop(reactor);
            } else {
                // Only spawn the circuit reactor if the incoming stream handler was
                // able to receive our message
                match reactor.run().await {
                    Ok(()) => {}
                    Err(e) => {
                        debug_report!(e, "Relay circuit reactor exited with an error");
                    }
                }
            }
        })?;

        Ok((
            handshake_components.response,
            RelayCircComponents {
                circ,
                sender,
                padding_ctrl,
            },
        ))
    }

    /// The handshake code for a CREATE_FAST request.
    async fn handle_create_fast(
        &self,
        msg: &CreateFast,
    ) -> Result<CompletedHandshakeComponents, HandleCreateError> {
        // TODO(relay): We might want to offload this to a CPU worker in the future.
        let (keygen, handshake_msg) = CreateFastServer::server(
            &mut rand::rng(),
            // The CREATE_FAST handshake doesn't accept or return extensions,
            // so this `AuxDataReply` is a no-op.
            &mut |_: &()| Some(()),
            // The CREATE_FAST handshake doesn't use any keys.
            &[],
            msg.handshake(),
        )?;

        let circ_net_params = self
            .circ_net_params
            .read()
            .expect("rwlock poisoned")
            .clone();

        // No subprotocols are requested during a CREATE_FAST handshake.
        let subprotos = HandshakeSubprotocols::default();

        let hop_settings = HopSettings::from_handshake_params(
            circ_net_params,
            // CREATE_FAST always uses fixed-window flow control.
            AlgorithmDiscriminants::FixedWindow,
            subprotos,
        )?;

        let crypt = Tor1RelayCrypto::construct(keygen)
            .map_err(into_internal!("Circuit crypt state construction failed"))?;

        let (crypto_out, crypto_in, _binding) = split_relay_layer(crypt);

        let response = CreatedFast::new(handshake_msg);
        let response = CreateResponse::CreatedFast(response);

        trace!("Completed CREATE_FAST handshake");

        Ok(CompletedHandshakeComponents {
            response,
            hop_settings,
            crypto_out,
            crypto_in,
        })
    }

    /// The handshake code for a CREATE2 ntor (non-v3) request.
    async fn handle_create2_ntor(
        &self,
        msg_body: &[u8],
        our_rsa_id: &RsaIdentity,
    ) -> Result<CompletedHandshakeComponents, HandleCreateError> {
        let ntor_keys = self.ntor_keys(|k| {
            NtorSecretKey::new(k.secret().clone(), *k.public().inner(), *our_rsa_id)
        });

        // TODO(relay): We might want to offload this to a CPU worker in the future.
        let (keygen, handshake_msg) = NtorServer::server(
            &mut rand::rng(),
            // The ntor (non-v3) handshake doesn't accept or return extensions,
            // so this `AuxDataReply` is a no-op.
            &mut |_: &()| Some(()),
            ntor_keys.as_ref(),
            msg_body,
        )?;

        let circ_net_params = self
            .circ_net_params
            .read()
            .expect("rwlock poisoned")
            .clone();

        // No subprotocols are requested during an ntor (non-v3) handshake.
        let subprotos = HandshakeSubprotocols::default();

        let hop_settings = HopSettings::from_handshake_params(
            circ_net_params,
            // CREATE2 with ntor (non-v3) always uses fixed-window flow control.
            AlgorithmDiscriminants::FixedWindow,
            subprotos,
        )?;

        let crypt = Tor1RelayCrypto::construct(keygen)
            .map_err(into_internal!("Circuit crypt state construction failed"))?;

        let (crypto_out, crypto_in, _binding) = split_relay_layer(crypt);

        let response = Created2::new(handshake_msg);
        let response = CreateResponse::Created2(response);

        trace!("Completed ntor handshake");

        Ok(CompletedHandshakeComponents {
            response,
            hop_settings,
            crypto_out,
            crypto_in,
        })
    }

    /// The handshake code for a CREATE2 ntor-v3 request.
    async fn handle_create2_ntorv3(
        &self,
        msg_body: &[u8],
        our_ed25519_id: &Ed25519Identity,
    ) -> Result<CompletedHandshakeComponents, HandleCreateError> {
        let ntor_keys = self.ntor_keys(|k| {
            NtorV3SecretKey::new(k.secret().clone(), *k.public().inner(), *our_ed25519_id)
        });

        let circ_net_params = self
            .circ_net_params
            .read()
            .expect("rwlock poisoned")
            .clone();

        // These extensions can be negotiated during the handshake.
        let mut cc_algorithm = AlgorithmDiscriminants::FixedWindow;

        // These subprotocols were requested during the handshake.
        // They are not validated.
        let mut subprotos = SubprotocolRequest::default();

        // Helper which processes extension requests and returns any responses.
        // Returns `None` if the handshake should fail.
        let mut ext_reply_fn = |client_exts: &[CircRequestExt]| {
            let mut response_exts = Vec::new();

            // https://spec.torproject.org/tor-spec/create-created-cells.html#additional-data
            //
            // > Unless otherwise specified in the documentation for an extension type:
            // > - [...]
            // > - Parties MUST ignore any occurrence of an extension with a given type after the first such occurrence.
            //
            // TODO: Is there something nicer that we can do here?
            // We could use accessors like `ExtList::get_cc_request()`
            // which iterate over the extension list for each extension,
            // but using an enum match like we do below is kind of nice.
            let mut handled_cc_request = false;
            let mut handled_subproto_request = false;

            for ext in client_exts {
                match ext {
                    CircRequestExt::CcRequest(CcRequest { .. }) => {
                        if handled_cc_request {
                            continue;
                        }
                        handled_cc_request = true;

                        cc_algorithm = AlgorithmDiscriminants::Vegas;

                        let sendme_inc: u8 = circ_net_params.cc.cwnd.sendme_inc();
                        let response = CcResponse::new(sendme_inc);
                        response_exts.push(CircResponseExt::CcResponse(response));
                    }
                    // The given `SubprotocolRequest` stores a list of `NumberedSubver`,
                    // but a circuit extension request is limited to 255 bytes (127 subprotocols).
                    // So while a malicious client could send us a lot of invalid subprotocols,
                    // this limit prevents this list from being excessively large.
                    CircRequestExt::SubprotocolRequest(subproto_request) => {
                        if handled_subproto_request {
                            continue;
                        }
                        handled_subproto_request = true;

                        // We don't check the requested subprotocols here.
                        subprotos = subproto_request.clone();
                    }
                    CircRequestExt::Unrecognized(ext) => {
                        // https://spec.torproject.org/tor-spec/create-created-cells.html#additional-data
                        //
                        // > Parties MUST ignore extensions with `EXT_FIELD_TYPE` bodies they do not recognize.
                        debug!(
                            ?ext,
                            "CREATE2 ntor-v3 handshake requested unrecognized extension",
                        );
                    }
                    ext => {
                        // https://spec.torproject.org/tor-spec/create-created-cells.html#additional-data
                        //
                        // > Parties MUST ignore extensions with `EXT_FIELD_TYPE` bodies they do not recognize.
                        //
                        // We recognize this but don't know what to do with it.
                        // We haven't implemented it, or it doesn't make sense
                        // (for example `CircRequestExt::ProofOfWork`).
                        // So we'll just behave as if we don't recognize it.
                        debug!(
                            ?ext,
                            "CREATE2 ntor-v3 handshake requested unsupported extension",
                        );
                    }
                }
            }

            Some(response_exts)
        };

        // TODO(relay): We might want to offload this to a CPU worker in the future.
        let (keygen, handshake_msg) = NtorV3Server::server(
            &mut rand::rng(),
            &mut ext_reply_fn,
            ntor_keys.as_ref(),
            msg_body,
        )?;

        // Ensure that the client did not request invalid/unsupported subprotocols.
        let subprotos = HandshakeSubprotocols::try_from_request(subprotos)?;

        let hop_settings =
            HopSettings::from_handshake_params(circ_net_params, cc_algorithm, subprotos)?;

        let (crypto_out, crypto_in, _binding) = if subprotos.relay_crypt_cgo {
            let crypt = CgoRelayCrypto::construct(keygen)
                .map_err(into_internal!("Circuit crypt state construction failed"))?;
            split_relay_layer(crypt)
        } else {
            let crypt = Tor1RelayCrypto::construct(keygen)
                .map_err(into_internal!("Circuit crypt state construction failed"))?;
            split_relay_layer(crypt)
        };

        let response = Created2::new(handshake_msg);
        let response = CreateResponse::Created2(response);

        trace!(?cc_algorithm, ?subprotos, "Completed ntor-v3 handshake");

        Ok(CompletedHandshakeComponents {
            response,
            hop_settings,
            crypto_out,
            crypto_in,
        })
    }

    /// Helper to get the ntor keypairs after some transformation `map`.
    ///
    /// The `map` transformation must be fast since it blocks a read lock.
    /// The returned keys are sorted with the most recent key first.
    ///
    /// It would be nice if this just returned an iterator,
    /// but the read lock prevents this.
    fn ntor_keys<T>(&self, map: impl FnMut(&RelayNtorKeypair) -> T) -> impl AsRef<[T]> {
        let ntor_keys = self.ntor_keys.read().expect("rwlock poisoned");
        let ntor_keys = [Some(ntor_keys.latest()), ntor_keys.previous()];
        ntor_keys
            .into_iter()
            .flatten()
            .map(map)
            .collect::<SmallVec<[T; 2]>>()
    }
}

/// A receiver of [`Stream`]s (one for each incoming circuit),
/// where each `Stream` produces [`IncomingStream`]s for that circuit.
///
// Note: in theory, it would be nice if we could get rid of this type altogether.
// In an ideal world, I would've instead
//
//   * added a `RelayCirc::take_incoming_streams()` method for obtaining
//     the futures::Stream of IncomingStream of that circuit
//   * made the CreateRequestHandler send each Arc<RelayCirc> over to arti-relay for handling
//   * made arti-relay obtain the futures::Stream<Item = IncomingStream> of each RelayCirc
//     by calling `RelayCirc::take_incoming_streams()`
//
// However, that would involve adding some locking/interior mutability within RelayCirc
// (which is always behind an Arc), or extending mq_queue::Receiver to be Clone,
// which would be tricky to pull off (see the comment on mq_queue::Receiver about this).
pub struct CircuitIncomingStreamReceiver {
    /// The receiver for the [`Stream`]s of `IncomingStream` of all circuits.
    ///
    /// Receives one [`Stream`] (of tor streams) per circuit.
    /// Each of these will be handled in a new task.
    circuit_stream_rx: mpsc::Receiver<<Self as Stream>::Item>,
}

impl Stream for CircuitIncomingStreamReceiver {
    // TODO: it would be nice if we could return a type-erased Stream here
    // (impl Stream<...>), but impl Trait in associated types is unstable.
    // See rust issue #63063 <https://github.com/rust-lang/rust/issues/63063>
    type Item = Box<dyn Stream<Item = IncomingStream> + Send + Sync + Unpin>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt as _;

        self.circuit_stream_rx.poll_next_unpin(cx)
    }
}

/// Helper function to split a `RelayLayer` into forward and backward type-erased trait objects.
fn split_relay_layer<F, B>(
    crypt: impl RelayLayer<F, B>,
) -> (
    Box<dyn OutboundRelayLayer + Send>,
    Box<dyn InboundRelayLayer + Send>,
    CircuitBinding,
)
where
    F: OutboundRelayLayer + Send + 'static,
    B: InboundRelayLayer + Send + 'static,
{
    let (crypto_out, crypto_in, binding) = crypt.split_relay_layer();
    let (crypto_out, crypto_in) = (Box::new(crypto_out), Box::new(crypto_in));

    (crypto_out, crypto_in, binding)
}

/// An error that occurred while handling a CREATE* request.
#[derive(Debug, thiserror::Error)]
enum HandleCreateError {
    /// Circuit relay handshake failed.
    #[error("Circuit relay handshake failed")]
    Handshake(#[from] RelayHandshakeError),
    /// Circuit relay handshake failed.
    #[error("Failed to process the circuit relay handshake parameters")]
    HandshakeParameters(#[from] HandshakeParamsError),
    /// Requested subprotocols which aren't supported.
    #[error("Client requested subprotocol(s) which aren't supported")]
    HandshakeSubprotocols(#[from] InvalidHandshakeSubprotocolError),
    /// The requested handshake type is unsupported.
    #[error("Unsupported handshake type {0}")]
    Create2HandshakeType(HandshakeType),
    /// A memquota error.
    #[error("Memquota error")]
    Memquota(#[from] tor_memquota::Error),
    /// Error when spawning a task.
    #[error("Runtime task spawn error")]
    Spawn(#[from] futures::task::SpawnError),
    /// An internal error.
    ///
    /// Note that other variants (such as `Handshake` containing a [`RelayHandshakeError`])
    /// may themselves contain internal errors.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

impl HasKind for HandleCreateError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Handshake(e) => e.kind(),
            Self::HandshakeParameters(e) => e.kind(),
            Self::HandshakeSubprotocols(e) => e.kind(),
            Self::Create2HandshakeType(_) => ErrorKind::NotImplemented,
            Self::Memquota(e) => e.kind(),
            Self::Spawn(e) => e.kind(),
            Self::Internal(_) => ErrorKind::Internal,
        }
    }
}

/// The components of a completed CREATE* handshake.
struct CompletedHandshakeComponents {
    /// The message to send in response.
    response: CreateResponse,
    /// The negotiated hop settings.
    hop_settings: HopSettings,
    /// Outbound onion crypto.
    crypto_out: Box<dyn OutboundRelayLayer + Send>,
    /// Inbound onion crypto.
    crypto_in: Box<dyn InboundRelayLayer + Send>,
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

impl CongestionControlNetParams {
    #[cfg(test)]
    // These have been copied from C-tor.
    pub(crate) fn defaults_for_tests() -> Self {
        Self {
            fixed_window: FixedWindowParams::defaults_for_tests(),
            vegas_exit: VegasParams::defaults_for_tests(),
            cwnd: CongestionWindowParams::defaults_for_tests(),
            rtt: RoundTripEstimatorParams::defaults_for_tests(),
            flow_ctrl: FlowCtrlParameters::defaults_for_tests(),
        }
    }
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
    /// Congestion control network parameters.
    pub cc: CongestionControlNetParams,
}

/// An [`IncomingStreamRequestFilter`] factory for building [`IncomingStreamRequestFilter`]s.
///
/// Each time a new circuit is opened, the [`CreateRequestHandler`] calls
/// [`IncomingStreamRequestFilterFactory::current_filter`] to build
/// an [`IncomingStreamRequestFilter`] for the circuit.
pub trait IncomingStreamRequestFilterFactory {
    /// Return the [`IncomingStreamRequestFilter`] to apply to the incoming stream requests
    /// arriving on a circuit.
    fn current_filter(&self) -> Box<dyn IncomingStreamRequestFilter>;
}

impl<F> IncomingStreamRequestFilterFactory for F
where
    F: Fn() -> Box<dyn IncomingStreamRequestFilter>,
{
    fn current_filter(&self) -> Box<dyn IncomingStreamRequestFilter> {
        (self)()
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_cell::chancell::msg::{AnyChanMsg, Create2, CreateFast, HandshakeType};
    use tor_cell::chancell::{AnyChanCell, ChanCmd, ChanMsg as _};
    use tor_rtcompat::test_with_one_runtime;

    use crate::channel::test_utils;
    use crate::circuit::CircParameters;

    /// Test the CREATE_FAST handshake.
    #[test]
    fn create_fast() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            let (client_chan, relay_chan, _circuit_stream_rx, _target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

            let circ_params = CircParameters::default();

            let tunnel = pending_tunnel
                .create_firsthop_fast(circ_params)
                .await
                .unwrap();

            // Client sent a CREATE_FAST, relay responded with a CREATED_FAST.
            assert_eq!(
                conn_inspector.try_client_cell().unwrap().msg().cmd(),
                ChanCmd::CREATE_FAST,
            );
            assert_eq!(
                conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                ChanCmd::CREATED_FAST,
            );

            drop(tunnel);

            assert_eq!(
                conn_inspector.client_cell().await.unwrap().msg().cmd(),
                ChanCmd::DESTROY,
            );

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the CREATE_FAST handshake, but with a modified handshake payload.
    #[test]
    fn create_fast_fail() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            // Rewrite any client-sent CREATE_FAST messages to cause the client to fail the
            // handshake when processing the CREATED_FAST.
            conn_inspector.set_client_cell_modifier(|cell: &mut AnyChanCell| {
                let circ_id = cell.circid();
                if let AnyChanMsg::CreateFast(msg) = cell.msg() {
                    let mut new_handshake = msg.handshake().to_vec();

                    // Flip all bits.
                    for byte in &mut new_handshake {
                        *byte = !*byte;
                    }

                    // Reassemble the CREATE_FAST cell with the incorrect handshake body.
                    let new_msg = CreateFast::new(new_handshake);
                    *cell = AnyChanCell::new(circ_id, AnyChanMsg::CreateFast(new_msg));
                }
            });

            let (client_chan, relay_chan, _circuit_stream_rx, _target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

            let circ_params = CircParameters::default();

            // I don't think it's possible to modify the CREATE_FAST cell to make the relay fail the
            // handshake (the CREATE_FAST payload consists of only random bytes),
            // so the relay will respond successfully with a CREATED_FAST.
            // But the client will fail since the CREATED_FAST will contain garbage bytes.

            // The relay successfully processed the handshake,
            // but the client fails to validate the handshake since the handshake data was modified.
            assert!(matches!(
                pending_tunnel.create_firsthop_fast(circ_params).await,
                Err(crate::Error::BadCircHandshakeAuth),
            ));

            // Client sent a CREATE_FAST, relay responded with a CREATED_FAST.
            assert_eq!(
                conn_inspector.try_client_cell().unwrap().msg().cmd(),
                ChanCmd::CREATE_FAST,
            );
            assert_eq!(
                conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                ChanCmd::CREATED_FAST,
            );

            // Since the `create_firsthop_fast()` failed above,
            // the client should have sent a DESTROY.
            assert_eq!(
                conn_inspector.client_cell().await.unwrap().msg().cmd(),
                ChanCmd::DESTROY,
            );

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the client with the "Relay=1" subprotocol (corresponds to the TAP handshake),
    /// which Arti doesn't support.
    #[test]
    fn tap() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            let (client_chan, _relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

            let circ_params = CircParameters::default();

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 1 = RELAY_BASE
            let protocols = "Relay=1".parse().unwrap();
            let target = target_builder.protocols(protocols).build().unwrap();

            // TODO: This should fail since we don't support TAP handshakes.
            // But the channel will do an ntor handshake anyway even though it's not supported.
            // https://gitlab.torproject.org/tpo/core/arti/-/work_items/2489
            let _tunnel = pending_tunnel
                .create_firsthop(&target, circ_params)
                .await
                .unwrap();

            // TODO: As above, this is wrong.
            assert_eq!(
                conn_inspector.try_client_cell().unwrap().msg().cmd(),
                ChanCmd::CREATE2,
            );
            assert_eq!(
                conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                ChanCmd::CREATED2,
            );
        });
    }

    /// Test the CREATE2 ntor handshake.
    #[test]
    fn ntor() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            let (client_chan, relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 2 = RELAY_NTOR
            // 3 = RELAY_EXTEND_IPv6
            for relay_version in [2, 3] {
                let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

                let circ_params = CircParameters::default();

                let protocols = format!("Relay=2-{relay_version}").parse().unwrap();
                let target = target_builder.protocols(protocols).build().unwrap();

                let tunnel = pending_tunnel
                    .create_firsthop(&target, circ_params)
                    .await
                    .unwrap();

                let client_cell = conn_inspector.try_client_cell().unwrap().msg().clone();
                let relay_cell = conn_inspector.try_relay_cell().unwrap().msg().clone();

                // Client sent a CREATE2, relay responded with a CREATED2.
                assert_eq!(client_cell.cmd(), ChanCmd::CREATE2);
                assert_eq!(relay_cell.cmd(), ChanCmd::CREATED2);

                // Check that it was an ntor handshake.
                let AnyChanMsg::Create2(client_cell) = client_cell else {
                    unreachable!("CREATE2 checked above");
                };
                assert_eq!(client_cell.handshake_type(), HandshakeType::NTOR);

                drop(tunnel);

                assert_eq!(
                    conn_inspector.client_cell().await.unwrap().msg().cmd(),
                    ChanCmd::DESTROY,
                );

                // We don't expect any other messages to have been sent.
                assert!(conn_inspector.try_client_cell().is_none());
                assert!(conn_inspector.try_relay_cell().is_none());
            }

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the CREATE2 ntor handshake, but with a modified handshake payload.
    #[test]
    fn ntor_fail() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            // Rewrite any client-sent CREATE2 messages to cause the relay to fail the handshake.
            conn_inspector.set_client_cell_modifier(|cell: &mut AnyChanCell| {
                let circ_id = cell.circid();
                if let AnyChanMsg::Create2(msg) = cell.msg() {
                    let mut new_body = msg.body().to_vec();

                    // Flip some arbitrarily chosen byte.
                    new_body[10] = !new_body[10];

                    // Reassemble the CREATE2 cell with the incorrect handshake body.
                    let new_msg = Create2::new(msg.handshake_type(), new_body);
                    *cell = AnyChanCell::new(circ_id, AnyChanMsg::Create2(new_msg));
                }
            });

            let (client_chan, relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 2 = RELAY_NTOR
            // 3 = RELAY_EXTEND_IPv6
            for relay_version in [2, 3] {
                let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

                let circ_params = CircParameters::default();

                let protocols = format!("Relay=2-{relay_version}").parse().unwrap();
                let target = target_builder.protocols(protocols).build().unwrap();

                // The relay refuses the circuit handshake since the CREATED2 cell had some
                // intentional issue with the handshake body.
                assert!(matches!(
                    pending_tunnel.create_firsthop(&target, circ_params).await,
                    Err(crate::Error::CircRefused(_)),
                ));

                // Client sent a CREATE2, relay responded with a DESTROY.
                assert_eq!(
                    conn_inspector.try_client_cell().unwrap().msg().cmd(),
                    ChanCmd::CREATE2,
                );
                assert_eq!(
                    conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                    ChanCmd::DESTROY,
                );

                // We don't expect any other messages to have been sent.
                assert!(conn_inspector.try_client_cell().is_none());
                assert!(conn_inspector.try_relay_cell().is_none());
            }

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the CREATE2 ntor-v3 handshake.
    #[test]
    fn ntor_v3() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            let (client_chan, relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 4 = RELAY_NTORV3
            // 5 = RELAY_NEGOTIATE_SUBPROTO
            // 6 = RELAY_CRYPT_CGO
            for relay_version in [4, 5, 6] {
                let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

                let circ_params = CircParameters::default();

                let protocols = format!("Relay=4-{relay_version}").parse().unwrap();
                let target = target_builder.protocols(protocols).build().unwrap();

                let tunnel = pending_tunnel
                    .create_firsthop(&target, circ_params)
                    .await
                    .unwrap();

                let client_cell = conn_inspector.try_client_cell().unwrap().msg().clone();
                let relay_cell = conn_inspector.try_relay_cell().unwrap().msg().clone();

                // Client sent a CREATE2, relay responded with a CREATED2.
                assert_eq!(client_cell.cmd(), ChanCmd::CREATE2);
                assert_eq!(relay_cell.cmd(), ChanCmd::CREATED2);

                // Check that it was an ntor-v3 handshake.
                let AnyChanMsg::Create2(client_cell) = client_cell else {
                    unreachable!("CREATE2 checked above");
                };
                assert_eq!(client_cell.handshake_type(), HandshakeType::NTOR_V3);

                // TODO: It would be nice if we had a way to check that CGO was in use when
                // `relay_version` is >=6, but I don't see a nice way to do that.

                drop(tunnel);

                assert_eq!(
                    conn_inspector.client_cell().await.unwrap().msg().cmd(),
                    ChanCmd::DESTROY,
                );

                // We don't expect any other messages to have been sent.
                assert!(conn_inspector.try_client_cell().is_none());
                assert!(conn_inspector.try_relay_cell().is_none());
            }

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the CREATE2 ntor-v3 handshake, but with a modified handshake payload.
    #[test]
    fn ntor_v3_fail() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            // Rewrite any client-sent CREATE2 messages to cause the relay to fail the handshake.
            conn_inspector.set_client_cell_modifier(|cell: &mut AnyChanCell| {
                let circ_id = cell.circid();
                if let AnyChanMsg::Create2(msg) = cell.msg() {
                    let mut new_body = msg.body().to_vec();

                    // Flip some arbitrarily chosen byte.
                    new_body[10] = !new_body[10];

                    // Reassemble the CREATE2 cell with the incorrect handshake body.
                    let new_msg = Create2::new(msg.handshake_type(), new_body);
                    *cell = AnyChanCell::new(circ_id, AnyChanMsg::Create2(new_msg));
                }
            });

            let (client_chan, relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 4 = RELAY_NTORV3
            // 5 = RELAY_NEGOTIATE_SUBPROTO
            // 6 = RELAY_CRYPT_CGO
            for relay_version in [4, 5, 6] {
                let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

                let circ_params = CircParameters::default();

                let protocols = format!("Relay=4-{relay_version}").parse().unwrap();
                let target = target_builder.protocols(protocols).build().unwrap();

                // The relay refuses the circuit handshake since the CREATED2 cell had some
                // intentional issue with the handshake body.
                assert!(matches!(
                    pending_tunnel.create_firsthop(&target, circ_params).await,
                    Err(crate::Error::CircRefused(_)),
                ));

                // Client sent a CREATE2, relay responded with a DESTROY.
                assert_eq!(
                    conn_inspector.try_client_cell().unwrap().msg().cmd(),
                    ChanCmd::CREATE2,
                );
                assert_eq!(
                    conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                    ChanCmd::DESTROY,
                );

                // We don't expect any other messages to have been sent.
                assert!(conn_inspector.try_client_cell().is_none());
                assert!(conn_inspector.try_relay_cell().is_none());
            }

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }

    /// Test the CREATE2 handshake, but with an invalid handshake type.
    #[test]
    fn create2_invalid_handshake_fail() {
        test_with_one_runtime!(|rt| async move {
            let mut conn_inspector = test_utils::ConnInspector::new();

            // Rewrite any client-sent CREATE2 messages to cause the relay to fail the handshake.
            conn_inspector.set_client_cell_modifier(|cell: &mut AnyChanCell| {
                let circ_id = cell.circid();
                if let AnyChanMsg::Create2(msg) = cell.msg() {
                    // Reassemble the CREATE2 cell with the incorrect handshake type.
                    let new_msg = tor_cell::chancell::msg::Create2::new(99.into(), msg.body());
                    *cell = AnyChanCell::new(circ_id, AnyChanMsg::Create2(new_msg));
                }
            });

            let (client_chan, relay_chan, _circuit_stream_rx, mut target_builder) =
                test_utils::new_channel_pair_with_keys(&rt, &conn_inspector);

            // https://spec.torproject.org/tor-spec/subprotocol-versioning.html
            // 2 = RELAY_NTOR
            // 3 = RELAY_EXTEND_IPv6
            // 4 = RELAY_NTORV3
            // 5 = RELAY_NEGOTIATE_SUBPROTO
            // 6 = RELAY_CRYPT_CGO
            for relay_version in [2, 6] {
                let pending_tunnel = test_utils::new_pending_tunnel(&rt, &client_chan).await;

                let circ_params = CircParameters::default();

                let protocols = format!("Relay=2-{relay_version}").parse().unwrap();
                let target = target_builder.protocols(protocols).build().unwrap();

                // The relay refuses the circuit handshake since the CREATED2 cell had some
                // unrecognized handshake type.
                assert!(matches!(
                    pending_tunnel.create_firsthop(&target, circ_params).await,
                    Err(crate::Error::CircRefused(_)),
                ));

                // Client sent a CREATE2, relay responded with a DESTROY.
                assert_eq!(
                    conn_inspector.try_client_cell().unwrap().msg().cmd(),
                    ChanCmd::CREATE2,
                );
                assert_eq!(
                    conn_inspector.try_relay_cell().unwrap().msg().cmd(),
                    ChanCmd::DESTROY,
                );

                // We don't expect any other messages to have been sent.
                assert!(conn_inspector.try_client_cell().is_none());
                assert!(conn_inspector.try_relay_cell().is_none());
            }

            // Wait for both channels to close (ignoring any channel errors).
            let wait_fut =
                futures::future::join(client_chan.wait_for_close(), relay_chan.wait_for_close());
            drop((client_chan, relay_chan));
            let _ = wait_fut.await;

            // We don't expect any other messages to have been sent.
            assert!(conn_inspector.try_client_cell().is_none());
            assert!(conn_inspector.try_relay_cell().is_none());
        });
    }
}
