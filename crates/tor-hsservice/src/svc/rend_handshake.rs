//! Implementation for the introduce-and-rendezvous handshake.

use std::sync::Arc;

use async_trait::async_trait;
use futures::{stream::BoxStream, StreamExt as _};
use retry_error::RetryError;
use tor_cell::relaycell::{
    hs::intro_payload::{IntroduceHandshakePayload, OnionKey},
    msg::{Introduce2, Rendezvous1},
};
use tor_circmgr::{
    build::circparameters_from_netparameters,
    hspool::{HsCircKind, HsCircPool},
};
use tor_error::{into_internal, HasKind};
use tor_linkspec::{
    decode::Strictness, verbatim::VerbatimLinkSpecCircTarget, CircTarget as _,
    OwnedChanTargetBuilder, OwnedCircTarget,
};
use tor_netdir::NetDirProvider;
use tor_proto::{
    circuit::{
        handshake,
        handshake::hs_ntor::{self, HsNtorHkdfKeyGenerator},
        ClientCirc,
    },
    stream::IncomingStream,
};
use tor_rtcompat::Runtime;

use crate::req::RendRequestContext;

/// An error produced while trying to process an introduction request we have
/// received from a client via an introduction point.
#[derive(Debug, Clone, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
#[non_exhaustive]
pub enum IntroRequestError {
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
}

impl HasKind for IntroRequestError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use IntroRequestError as E;
        match self {
            E::InvalidHandshake(e) => e.kind(),
            E::InvalidPayload(_) => EK::RemoteProtocolViolation,
            E::InvalidLinkSpecs(_) => EK::RemoteProtocolViolation,
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
    /// Got an onion key with an unrecognized type (not ntor).
    #[error("Received an unsupported type of onion key")]
    UnsupportedOnionKey,
    /// Unable to build a circuit to the rendezvous point.
    #[error("Could not establish circuit to rendezvous point")]
    RendCirc(#[source] RetryError<tor_circmgr::Error>),
    /// Encountered a failure while trying to add a virtual hop to the circuit.
    #[error("Could not add virtual hop to circuit")]
    VirtualHop(#[source] tor_proto::Error),
    /// We encountered an error while configuring the virtual hop to send us
    /// BEGIN messages.
    #[error("Could not configure circuit to allow BEGIN messages")]
    AcceptBegins(#[source] tor_proto::Error),
    /// We encountered an error while sending the rendezvous1 message.
    #[error("Could not send RENDEZVOUS1 message")]
    SendRendezvous(#[source] tor_proto::Error),
    /// The client sent us a rendezvous point with an impossible set of identities.
    ///
    /// (For example, it gave us `(Ed1, Rsa1)`, but in the network directory `Ed1` is
    /// associated with `Rsa2`.)
    #[error("Impossible combination of identities for rendezvous point")]
    ImpossibleIds(#[source] tor_netdir::RelayLookupError),
    /// An internal error occurred.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for EstablishSessionError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use EstablishSessionError as E;
        match self {
            E::NetdirUnavailable(e) => e.kind(),
            E::UnsupportedOnionKey => EK::RemoteProtocolViolation,
            // TODO (#1225) Not quite right.
            EstablishSessionError::RendCirc(_e) => EK::RemoteNetworkTimeout,
            EstablishSessionError::VirtualHop(e) => e.kind(),
            EstablishSessionError::AcceptBegins(e) => e.kind(),
            EstablishSessionError::SendRendezvous(e) => e.kind(),
            EstablishSessionError::ImpossibleIds(_) => EK::RemoteProtocolViolation,
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

    /// The (in progress) ChanTarget that we'll use to build a circuit target
    /// for connecting to the rendezvous point.
    chan_target: OwnedChanTargetBuilder,
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
    pub(crate) circuit: Arc<ClientCirc>,
}

/// Dyn-safe trait to represent a `HsCircPool`.
///
/// We need this so that we can hold an `Arc<HsCircPool<R>>` in
/// `RendRequestContext` without needing to parameterize on R.
#[async_trait]
pub(crate) trait RendCircConnector: Send + Sync {
    async fn get_or_launch_specific(
        &self,
        netdir: &tor_netdir::NetDir,
        kind: HsCircKind,
        target: VerbatimLinkSpecCircTarget<OwnedCircTarget>,
    ) -> tor_circmgr::Result<Arc<ClientCirc>>;
}

#[async_trait]
impl<R: Runtime> RendCircConnector for HsCircPool<R> {
    async fn get_or_launch_specific(
        &self,
        netdir: &tor_netdir::NetDir,
        kind: HsCircKind,
        target: VerbatimLinkSpecCircTarget<OwnedCircTarget>,
    ) -> tor_circmgr::Result<Arc<ClientCirc>> {
        HsCircPool::get_or_launch_specific(self, netdir, kind, target).await
    }
}

impl IntroRequest {
    /// Try to decrypt an incoming Introduce2 request, using the set of keys provided.
    pub(crate) fn decrypt_from_introduce2(
        req: Introduce2,
        context: &RendRequestContext,
    ) -> Result<Self, IntroRequestError> {
        use IntroRequestError as E;
        let mut rng = rand::thread_rng();

        let (key_gen, rend1_body, msg_body) = hs_ntor::server_receive_intro(
            &mut rng,
            &context.kp_hss_ntor,
            &context.kp_hs_ipt_sid,
            &context.subcredentials[..],
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

        // We build the OwnedChanTargetBuilder now, so that we can detect any
        // problems here earlier.
        let chan_target = OwnedChanTargetBuilder::from_encoded_linkspecs(
            Strictness::Standard,
            intro_payload.link_specifiers(),
        )
        .map_err(E::InvalidLinkSpecs)?;

        let rend1_msg = Rendezvous1::new(*intro_payload.cookie(), rend1_body);

        Ok(IntroRequest {
            req,
            key_gen,
            rend1_msg,
            intro_payload,
            chan_target,
        })
    }

    /// Try to accept this client's request.
    ///
    /// To do so, we open a circuit to the client's chosen rendezvous point,
    /// send it a RENDEZVOUS1 message, and wait for incoming BEGIN messages from
    /// the client.
    pub(crate) async fn establish_session(
        self,
        hs_pool: Arc<dyn RendCircConnector>,
        provider: Arc<dyn NetDirProvider>,
    ) -> Result<OpenSession, EstablishSessionError> {
        use EstablishSessionError as E;

        // Find a netdir.  Note that we _won't_ try to wait or retry if the
        // netdir isn't there: we probably can't answer this user's request.
        let netdir = provider
            .netdir(tor_netdir::Timeliness::Timely)
            .map_err(E::NetdirUnavailable)?;

        // Try to construct a CircTarget for rendezvous point based on the
        // intro_payload.
        let rend_point = {
            // TODO: We might have checked for a recognized onion key type earlier.
            let ntor_onion_key = match self.intro_payload.onion_key() {
                OnionKey::NtorOnionKey(ntor_key) => ntor_key,
                _ => return Err(E::UnsupportedOnionKey),
            };
            let mut bld = OwnedCircTarget::builder();
            *bld.chan_target() = self.chan_target;

            // TODO (#1223): This block is very similar to circtarget_from_pieces in
            // relay_info.rs.
            // Is there a clean way to refactor this?
            let protocols = {
                let chan_target = bld.chan_target().build().map_err(into_internal!(
                    "from_encoded_linkspecs gave an invalid output"
                ))?;
                match netdir
                    .by_ids_detailed(&chan_target)
                    .map_err(E::ImpossibleIds)?
                {
                    Some(relay) => relay.protovers().clone(),
                    None => netdir.relay_protocol_status().required_protocols().clone(),
                }
            };
            bld.protocols(protocols);
            bld.ntor_onion_key(*ntor_onion_key);
            VerbatimLinkSpecCircTarget::new(
                bld.build()
                    .map_err(into_internal!("Failed to construct a valid circtarget"))?,
                self.intro_payload.link_specifiers().into(),
            )
        };

        let max_n_attempts = netdir.params().hs_service_rendezvous_failures_max;
        let mut circuit = None;
        let mut retry_err: RetryError<tor_circmgr::Error> =
            RetryError::in_attempt_to("Establish a circuit to a rendezvous point");

        // Open circuit to rendezvous point.
        for _attempt in 1..=max_n_attempts.into() {
            match hs_pool
                .get_or_launch_specific(&netdir, HsCircKind::SvcRend, rend_point.clone())
                .await
            {
                Ok(circ) => {
                    circuit = Some(circ);
                    break;
                }
                Err(e) => {
                    retry_err.push(e);
                    // Note that we do not sleep on errors: if there is any
                    // error that will be solved by waiting, it would probably
                    // require waiting too long to satisfy the client.
                }
            }
        }
        let circuit = circuit.ok_or_else(|| E::RendCirc(retry_err))?;

        // We'll need parameters to extend the virtual hop.
        let params = circparameters_from_netparameters(netdir.params());

        // We won't need the netdir any longer; stop holding the reference.
        drop(netdir);

        let last_real_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Circuit with no final hop"))?;

        // Add a virtual hop.
        circuit
            .extend_virtual(
                handshake::RelayProtocol::HsV3,
                handshake::HandshakeRole::Responder,
                self.key_gen,
                params,
            )
            .await
            .map_err(E::VirtualHop)?;

        let virtual_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Circuit with no virtual hop"))?;

        // Accept begins from that virtual hop
        let stream_requests = circuit
            .allow_stream_requests(&[tor_cell::relaycell::RelayCmd::BEGIN], virtual_hop)
            .await
            .map_err(E::AcceptBegins)?
            .boxed();

        // Send the RENDEZVOUS1 message.
        circuit
            .send_raw_msg(self.rend1_msg.into(), last_real_hop)
            .await
            .map_err(E::SendRendezvous)?;

        Ok(OpenSession {
            stream_requests,
            circuit,
        })
    }
}
