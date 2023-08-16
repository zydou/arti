//! Implementation for the introduce-and-rendezvous handshake.

#![allow(dead_code)] // TODO HSS remove this.

use std::sync::Arc;

use futures::{stream::BoxStream, StreamExt as _};
use tor_cell::relaycell::{
    hs::intro_payload::{IntroduceHandshakePayload, OnionKey},
    msg::{Introduce2, Rendezvous1},
    RelayMsg as _,
};
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_error::into_internal;
use tor_linkspec::OwnedCircTarget;
use tor_netdir::NetDirProvider;
use tor_proto::{
    circuit::{
        handshake,
        handshake::hs_ntor::{self, HsNtorHkdfKeyGenerator, HsNtorServiceInput},
        ClientCirc,
    },
    stream::IncomingStream,
};
use tor_rtcompat::Runtime;

/// An error produced while trying to process an introduction request we have
/// received from a client via an introduction point.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum IntroRequestError {
    /// The handshake (e.g. hs_ntor) in the Introduce2 message was invalid and
    /// could not be completed.
    #[error("Introduction handshake was invalid")]
    InvalidHandshake(#[source] tor_proto::Error),

    /// The decrypted payload of the Introduce2 message could not be parsed.
    #[error("Could not parse INTRODUCE1 payload")]
    InvalidPayload(#[source] tor_bytes::Error),
}

/// An error produced while trying to connect to a rendezvous point and open a
/// session with a client.
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum EstablishSessionError {
    /// We couldn't get a timely network directory in order to build our
    /// chosen circuits.
    #[error("Network directory not available")]
    NetdirUnavailable(#[source] tor_netdir::Error),
    /// Got an onion key with an unrecognized type (not ntor).
    #[error("Received an unsupported type of onion key")]
    UnsupportedOnionKey,
    /// Encountered an error while trying to build a circuit to the rendezvous point.
    #[error("Could not establish circuit to rendezvous point")]
    RendCirc(#[source] tor_circmgr::Error),
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
    /// An internal error occurred.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// A decrypted request from an onion service client which we can
/// choose to answer (or not).
///
/// This corresponds to a processed INTRODUCE2 message.
///
/// To accept this request, call its
/// [`establish_session`](IntroRequest::establish_session) method.
/// To reject this request, simply drop it.
pub(crate) struct IntroRequest {
    /// The introduce2 message itself. We keep this in case we want to look at
    /// the outer header.
    req: Introduce2,

    /// The key generator we'll use to derive our shared keys with the client when
    /// creating a virtual hop.
    key_gen: HsNtorHkdfKeyGenerator,

    /// The RENDEZVOUS1 message we'll send to the rendezvous point.
    ///
    /// (The rendezvous point will in turn send this to the client as a RENDEZVOUS2.)
    rend1_msg: Rendezvous1,

    /// The decrypted and parsed body of the introduce2 message.
    intro_payload: IntroduceHandshakePayload,
}

/// An open session with a single client.
pub(crate) struct OpenSession {
    /// A stream of incoming BEGIN requests.
    stream_requests: BoxStream<'static, tor_proto::Result<IncomingStream>>,

    /// Our circuit with the client in question
    // TODO HSS: If we drop this handle, nothing will keep the circuit alive.
    // But we need to make sure we drop this handle when the other side destroys
    // the circuit.
    circuit: Arc<ClientCirc>,
}

impl IntroRequest {
    /// Try to decrypt an incoming Introduce2 request, using the set of keys provided.
    pub(crate) fn decrypt_from_introduce2(
        req: Introduce2,
        keys: &HsNtorServiceInput,
    ) -> Result<Self, IntroRequestError> {
        use IntroRequestError as E;
        let mut rng = rand::thread_rng();

        let (key_gen, rend1_body, msg_body) = hs_ntor::server_receive_intro(
            &mut rng,
            keys,
            req.encoded_header(),
            req.encrypted_body(),
        )
        .map_err(E::InvalidHandshake)?;

        let intro_payload: IntroduceHandshakePayload = {
            let mut r = tor_bytes::Reader::from_slice(&msg_body);
            let payload = r.extract().map_err(E::InvalidPayload)?;
            r.should_be_exhausted().map_err(E::InvalidPayload)?;
            payload
        };

        let rend1_msg = Rendezvous1::new(*intro_payload.cookie(), rend1_body);

        Ok(IntroRequest {
            req,
            key_gen,
            rend1_msg,
            intro_payload,
        })
    }

    /// Try to accept this client's request.
    ///
    /// To do so, we open a circuit to the client's chosen rendezvous point,
    /// send it a RENDEZVOUS1 message, and wait for incoming BEGIN messages from
    /// the client.
    #[allow(unreachable_code)] // TODO HSS remove.
    pub(crate) async fn establish_session<R: Runtime>(
        self,
        hs_pool: HsCircPool<R>,
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
        //
        // TODO: Maybe we should have tried to do this earlier?  But to do so we
        // would have needed a netdir before.  That suggest in turn that maybe
        // circtarget_from_pieces needs a different interface.
        let rend_point: OwnedCircTarget = {
            let ntor_onion_key = match self.intro_payload.onion_key() {
                OnionKey::NtorOnionKey(ntor_key) => ntor_key,
                _ => return Err(E::UnsupportedOnionKey),
            };

            // TODO HSS: this function needs to be exposed. currently it is only
            // in relay_info.rs in tor_hsclient, where it can't be used.
            //
            // circtarget_from_pieces(self.intro_payload.link_specifiers(),
            //                       ntor_onion_key, &netdir)?
            todo!()
        };

        // Open circuit to rendezvous point.
        let circuit = hs_pool
            .get_or_launch_specific(&netdir, HsCircKind::SvcRend, rend_point)
            .await
            .map_err(E::RendCirc)?;
        // TODO HSS: Maybe we should retry a couple of time if the failure is not
        // the fault of the rend_point?

        // We'll need parameters to extend the virtual hop.
        //
        // TODO HSS: We'll probably want to swipe this function from
        // tor-hsclient as well.
        //
        // let params = circparameters_from_netparameters(netdir.params());
        let params = tor_proto::circuit::CircParameters::default(); // TODO HSS replace.

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

        let _virtual_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Circuit with no virtual hop"))?;

        // Accept begins from that virtual hop
        let stream_requests = circuit
            .allow_stream_requests(&[tor_cell::relaycell::RelayCmd::BEGIN])
            .await
            .map_err(E::AcceptBegins)?
            .boxed();

        // Send the RENDEZVOUS1 message.
        let _converation: tor_proto::circuit::Conversation<'_> = circuit
            .start_conversation(Some(self.rend1_msg.into()), RejectMessages, last_real_hop)
            .await
            .map_err(E::SendRendezvous)?;
        // TODO: We don't actually expect any reply at all; start_conversation
        // may be excessive. See #1010

        Ok(OpenSession {
            stream_requests,
            circuit,
        })
    }
}

/// A MessageHandler that closes the circuit whenever it gets a reply.
struct RejectMessages;
impl tor_proto::circuit::MsgHandler for RejectMessages {
    fn handle_msg(
        &mut self,
        _conversation: tor_proto::circuit::ConversationInHandler<'_, '_, '_>,
        msg: tor_cell::relaycell::msg::AnyRelayMsg,
    ) -> tor_proto::Result<tor_proto::circuit::MetaCellDisposition> {
        Err(tor_proto::Error::CircProto(format!(
            "Received unexpected message {} from rendezvous point",
            msg.cmd()
        )))
    }
}
