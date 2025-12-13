//! Implementation for the introduce-and-rendezvous handshake.

use super::*;

// These imports just here, because they have names unsuitable for importing widely.
use tor_cell::relaycell::{
    hs::intro_payload::{IntroduceHandshakePayload, OnionKey},
    msg::{Introduce2, Rendezvous1},
};
use tor_circmgr::{ServiceOnionServiceDataTunnel, build::onion_circparams_from_netparams};
use tor_linkspec::verbatim::VerbatimLinkSpecCircTarget;
use tor_proto::{
    client::circuit::handshake::{
        self,
        hs_ntor::{self, HsNtorHkdfKeyGenerator},
    },
    client::stream::{IncomingStream, IncomingStreamRequestFilter},
};

/// An error produced while trying to process an introduction request we have
/// received from a client via an introduction point.
#[derive(Debug, Clone, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
pub enum IntroRequestError {
    /// We couldn't get a timely network directory in
    /// chosen circuits.
    #[error("Network directory not available")]
    NetdirUnavailable(#[source] tor_netdir::Error),

    /// Got an onion key with an unrecognized type (not ntor).
    #[error("Received an unsupported type of onion key")]
    UnsupportedOnionKey,

    /// The rendezvous point in the Introduce2 message was invalid and couldn't be used.
    #[error("Couldn't decode rendezvous point")]
    InvalidRendezvousPoint(#[source] tor_netdir::VerbatimCircTargetDecodeError),

    /// The handshake (e.g. hs_ntor) in the Introduce2 message was invalid and
    /// could not be completed.
    #[error("Introduction handshake was invalid")]
    InvalidHandshake(#[source] tor_proto::Error),

    /// The decrypted payload of the Introduce2 message could not be parsed.
    #[error("Could not parse INTRODUCE2 payload")]
    InvalidPayload(#[source] tor_bytes::Error),

    /// We weren't able to build a ChanTarget from the Introduce2 message.
    #[error("Invalid link specifiers in INTRODUCE2 payload")]
    InvalidLinkSpecs(#[source] tor_linkspec::decode::ChanTargetDecodeError),

    /// We weren't able to obtain the subcredentials for decrypting the Introduce2 message.
    #[error("Could not obtain subcredentials")]
    Subcredentials(#[source] crate::FatalError),
}

impl HasKind for IntroRequestError {
    fn kind(&self) -> tor_error::ErrorKind {
        use IntroRequestError as E;
        use tor_error::ErrorKind as EK;
        match self {
            E::NetdirUnavailable(e) => e.kind(),
            E::UnsupportedOnionKey => EK::RemoteProtocolViolation,
            E::InvalidRendezvousPoint(_) => EK::RemoteProtocolViolation,
            E::InvalidHandshake(e) => e.kind(),
            E::InvalidPayload(_) => EK::RemoteProtocolViolation,
            E::InvalidLinkSpecs(_) => EK::RemoteProtocolViolation,
            E::Subcredentials(e) => e.kind(),
        }
    }
}

/// An error produced while trying to connect to a rendezvous point and open a
/// session with a client.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum EstablishSessionError {
    /// We couldn't get a timely network directory in order to build our
    /// chosen circuits.
    #[error("Network directory not available")]
    NetdirUnavailable(#[source] tor_netdir::Error),
    /// Unable to build a circuit to the rendezvous point.
    #[error("Could not establish circuit to rendezvous point")]
    RendCirc(#[source] RetryError<tor_circmgr::Error>),
    /// Encountered a failure while trying to add a virtual hop to the circuit.
    #[error("Could not add virtual hop to circuit")]
    VirtualHop(#[source] tor_circmgr::Error),
    /// We encountered an error while configuring the virtual hop to send us
    /// BEGIN messages.
    #[error("Could not configure circuit to allow BEGIN messages")]
    AcceptBegins(#[source] tor_circmgr::Error),
    /// We encountered an error while sending the rendezvous1 message.
    #[error("Could not send RENDEZVOUS1 message")]
    SendRendezvous(#[source] tor_circmgr::Error),
    /// An internal error occurred.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for EstablishSessionError {
    fn kind(&self) -> tor_error::ErrorKind {
        use EstablishSessionError as E;
        match self {
            E::NetdirUnavailable(e) => e.kind(),
            EstablishSessionError::RendCirc(e) => {
                tor_circmgr::Error::summarized_error_kind(e.sources())
            }
            EstablishSessionError::VirtualHop(e) => e.kind(),
            EstablishSessionError::AcceptBegins(e) => e.kind(),
            EstablishSessionError::SendRendezvous(e) => e.kind(),
            EstablishSessionError::Bug(e) => e.kind(),
        }
    }
}

/// A decrypted request from an onion service client which we can
/// choose to answer (or not).
///
/// This corresponds to a processed INTRODUCE2 message.
///
/// To accept this request, call its
/// [`establish_session`](IntroRequest::establish_session) method.
/// To reject this request, simply drop it.
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) struct IntroRequest {
    /// The introduce2 message itself. We keep this in case we want to look at
    /// the outer header.
    req: Introduce2,

    /// The key generator we'll use to derive our shared keys with the client when
    /// creating a virtual hop.
    #[educe(Debug(ignore))]
    key_gen: HsNtorHkdfKeyGenerator,

    /// The RENDEZVOUS1 message we'll send to the rendezvous point.
    ///
    /// (The rendezvous point will in turn send this to the client as a RENDEZVOUS2.)
    rend1_msg: Rendezvous1,

    /// The decrypted and parsed body of the introduce2 message.
    intro_payload: IntroduceHandshakePayload,

    /// The circuit target for the rendezvous point.
    rend_point: VerbatimLinkSpecCircTarget<OwnedCircTarget>,
}

/// An open session with a single client.
///
/// (We consume this type and take ownership of its members later in
/// [`RendRequest::accept()`](crate::req::RendRequest::accept).)
pub(crate) struct OpenSession {
    /// A stream of incoming BEGIN requests.
    pub(crate) stream_requests: BoxStream<'static, IncomingStream>,

    /// Our circuit with the client in question.
    ///
    /// See `RendRequest::accept()` for more information on the life cycle of
    /// this circuit.
    pub(crate) tunnel: ServiceOnionServiceDataTunnel,
}

/// Dyn-safe trait to represent a `HsCircPool`.
///
/// We need this so that we can hold an `Arc<HsCircPool<R>>` in
/// `RendRequestContext` without needing to parameterize on R.
#[async_trait]
pub(crate) trait RendCircConnector: Send + Sync {
    /// Launch or return an existing circuit to the specified target.
    async fn get_or_launch_specific(
        &self,
        netdir: &tor_netdir::NetDir,
        target: VerbatimLinkSpecCircTarget<OwnedCircTarget>,
    ) -> tor_circmgr::Result<ServiceOnionServiceDataTunnel>;

    /// Return the current time instant from the runtime.
    ///
    /// This provides mockable time for use in error tracking.
    fn now(&self) -> std::time::Instant;

    /// Return the current wall-clock time from the runtime.
    fn wallclock(&self) -> std::time::SystemTime;
}

#[async_trait]
impl<R: Runtime> RendCircConnector for HsCircPool<R> {
    async fn get_or_launch_specific(
        &self,
        netdir: &tor_netdir::NetDir,
        target: VerbatimLinkSpecCircTarget<OwnedCircTarget>,
    ) -> tor_circmgr::Result<ServiceOnionServiceDataTunnel> {
        HsCircPool::get_or_launch_svc_rend(self, netdir, target).await
    }

    fn now(&self) -> std::time::Instant {
        HsCircPool::now(self)
    }

    fn wallclock(&self) -> std::time::SystemTime {
        HsCircPool::wallclock(self)
    }
}

/// Filter callback used to enforce early requirements on streams.
#[derive(Clone, Debug)]
pub(crate) struct RequestFilter {
    /// Largest number of streams we will accept on a circuit at a time.
    //
    // TODO: Conceivably, this should instead be a
    // watch::Receiver<Arc<OnionServiceConfig>>, so we can re-check the latest
    // value of the setting every time.  Instead, we currently only copy this
    // setting when an intro request is accepted.
    pub(crate) max_concurrent_streams: usize,
}
impl IncomingStreamRequestFilter for RequestFilter {
    fn disposition(
        &mut self,
        _ctx: &tor_proto::client::stream::IncomingStreamRequestContext<'_>,
        circ: &tor_proto::circuit::CircSyncView<'_>,
    ) -> tor_proto::Result<tor_proto::client::stream::IncomingStreamRequestDisposition> {
        if circ.n_open_streams() >= self.max_concurrent_streams {
            // TODO: We may want to have a way to send back an END message as
            // well and not tear down the circuit.
            Ok(tor_proto::client::stream::IncomingStreamRequestDisposition::CloseCircuit)
        } else {
            Ok(tor_proto::client::stream::IncomingStreamRequestDisposition::Accept)
        }
    }
}

impl IntroRequest {
    /// Try to decrypt an incoming Introduce2 request, using the set of keys provided.
    pub(crate) fn decrypt_from_introduce2(
        req: Introduce2,
        context: &RendRequestContext,
    ) -> Result<Self, IntroRequestError> {
        use IntroRequestError as E;
        let mut rng = rand::rng();

        // We need the subcredential for the *current time period* in order to do the hs_ntor
        // handshake. But that can change over time.  We will instead use KeyMgr::get_matching to
        // find all current subcredentials.
        let subcredentials = context
            .compute_subcredentials()
            .map_err(IntroRequestError::Subcredentials)?;

        let (key_gen, rend1_body, msg_body) = hs_ntor::server_receive_intro(
            &mut rng,
            &context.kp_hss_ntor,
            &context.kp_hs_ipt_sid,
            &subcredentials[..],
            req.encoded_header(),
            req.encrypted_body(),
        )
        .map_err(E::InvalidHandshake)?;

        let intro_payload: IntroduceHandshakePayload = {
            let mut r = tor_bytes::Reader::from_slice(&msg_body);
            r.extract().map_err(E::InvalidPayload)?
            // Note: we _do not_ call `should_be_exhausted` here, since we
            // explicitly expect the payload of an introduce2 message to be
            // padded to hide its size.
        };

        // We build the rend_point now, so that we can detect any
        // problems as early as possible.
        let netdir = context
            .netdir_provider
            .netdir(tor_netdir::Timeliness::Timely)
            .map_err(E::NetdirUnavailable)?;
        let ntor_onion_key = match intro_payload.onion_key() {
            OnionKey::NtorOnionKey(ntor_key) => ntor_key,
            _ => return Err(E::UnsupportedOnionKey),
        };
        let rend_point = netdir
            .circ_target_from_verbatim_linkspecs(intro_payload.link_specifiers(), ntor_onion_key)
            .map_err(E::InvalidRendezvousPoint)?;

        let rend1_msg = Rendezvous1::new(*intro_payload.cookie(), rend1_body);

        Ok(IntroRequest {
            req,
            key_gen,
            rend1_msg,
            intro_payload,
            rend_point,
        })
    }

    /// Try to accept this client's request.
    ///
    /// To do so, we open a circuit to the client's chosen rendezvous point,
    /// send it a RENDEZVOUS1 message, and wait for incoming BEGIN messages from
    /// the client.
    pub(crate) async fn establish_session(
        self,
        filter: RequestFilter,
        hs_pool: Arc<dyn RendCircConnector>,
        provider: Arc<dyn NetDirProvider>,
    ) -> Result<OpenSession, EstablishSessionError> {
        use EstablishSessionError as E;

        // Find a netdir.  Note that we _won't_ try to wait or retry if the
        // netdir isn't there: we probably can't answer this user's request.
        let netdir = provider
            .netdir(tor_netdir::Timeliness::Timely)
            .map_err(E::NetdirUnavailable)?;

        let max_n_attempts = netdir.params().hs_service_rendezvous_failures_max;
        let mut tunnel = None;
        let mut retry_err: RetryError<tor_circmgr::Error> =
            RetryError::in_attempt_to("Establish a circuit to a rendezvous point");

        // Open circuit to rendezvous point.
        for _attempt in 1..=max_n_attempts.into() {
            match hs_pool
                .get_or_launch_specific(&netdir, self.rend_point.clone())
                .await
            {
                Ok(t) => {
                    tunnel = Some(t);
                    break;
                }
                Err(e) => {
                    retry_err.push_timed(e, hs_pool.now(), Some(hs_pool.wallclock()));
                    // Note that we do not sleep on errors: if there is any
                    // error that will be solved by waiting, it would probably
                    // require waiting too long to satisfy the client.
                }
            }
        }
        let tunnel = tunnel.ok_or_else(|| E::RendCirc(retry_err))?;

        // We'll need parameters to extend the virtual hop.
        let params = onion_circparams_from_netparams(netdir.params())
            .map_err(into_internal!("Unable to build CircParameters"))?;

        // TODO CC: We may be able to do better based on the client's handshake message.
        let protocols = netdir.client_protocol_status().required_protocols().clone();

        // We won't need the netdir any longer; stop holding the reference.
        drop(netdir);

        let last_real_hop = tunnel
            .last_hop()
            .map_err(into_internal!("Circuit with no final hop"))?;

        // Add a virtual hop.
        tunnel
            .extend_virtual(
                handshake::RelayProtocol::HsV3,
                handshake::HandshakeRole::Responder,
                self.key_gen,
                params,
                &protocols,
            )
            .await
            .map_err(E::VirtualHop)?;

        let virtual_hop = tunnel
            .last_hop()
            .map_err(into_internal!("Circuit with no virtual hop"))?;

        // Accept begins from that virtual hop
        let stream_requests = tunnel
            .allow_stream_requests(&[tor_cell::relaycell::RelayCmd::BEGIN], virtual_hop, filter)
            .await
            .map_err(E::AcceptBegins)?
            .boxed();

        // Send the RENDEZVOUS1 message.
        tunnel
            .send_raw_msg(self.rend1_msg.into(), last_real_hop)
            .await
            .map_err(E::SendRendezvous)?;

        Ok(OpenSession {
            stream_requests,
            tunnel,
        })
    }

    /// Get the [`IntroduceHandshakePayload`] associated with this [`IntroRequest`].
    pub(crate) fn intro_payload(&self) -> &IntroduceHandshakePayload {
        &self.intro_payload
    }
}
