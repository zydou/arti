//! Request objects used to implement onion services.
//!
//! These requests are yielded on a stream, and the calling code needs to decide
//! whether to permit or reject them.

use educe::Educe;
use futures::{Stream, StreamExt};
use std::sync::Arc;
use tor_cell::relaycell::msg::{Connected, End, Introduce2};
use tor_hscrypto::{
    pk::{HsIntroPtSessionIdKey, HsSvcNtorKeypair},
    Subcredential,
};

use tor_error::Bug;
use tor_proto::{
    circuit::ClientCirc,
    stream::{DataStream, IncomingStream, IncomingStreamRequest},
};

use crate::{
    svc::rend_handshake::{self, RendCircConnector},
    ClientError, IptLocalId,
};

/// Request to complete an introduction/rendezvous handshake.
///
/// A request of this kind indicates that a client has asked permission to
/// connect to an onion service through an introduction point.  The caller needs
/// to decide whether or not to complete the handshake.
///
/// Protocol details: More specifically, we create one of these whenever we get a well-formed
/// `INTRODUCE2` message.  Based on this, the caller decides whether to send a
/// `RENDEZVOUS1` message.
#[derive(Educe)]
#[educe(Debug)]
pub struct RendRequest {
    /// The introduction point that sent this request.
    ipt_lid: IptLocalId,

    /// The message as received from the remote introduction point.
    raw: Introduce2,

    /// Reference to the keys we'll need to decrypt and handshake with this request.
    #[educe(Debug(ignore))]
    context: Arc<RendRequestContext>,

    /// The introduce2 message that we've decrypted and processed.
    ///
    /// We do not compute this immediately upon receiving the Introduce2 cell,
    /// since there is a bit of cryptography involved and we don't want to add
    /// any extra latency to the message handler.
    ///
    /// TODO: This also contains `raw`, which is maybe not so great; it would be
    /// neat to implement more efficiently.
    expanded: once_cell::unsync::OnceCell<rend_handshake::IntroRequest>,
}

/// A request from a client to open a new stream to an onion service.
///
/// We can only receive these _after_ we have already permitted the client to
/// connect via a [`RendRequest`].
///
/// Protocol details: More specifically, we create one of these whenever we get a well-formed
/// `BEGIN` message.  Based on this, the caller decides whether to send a
/// `CONNECTED` message.
#[derive(Debug)]
pub struct StreamRequest {
    /// The object that will be used to send data to and from the client.
    stream: IncomingStream,

    /// The circuit that made this request.
    on_circuit: Arc<ClientCirc>,
}

/// Keys and objects needed to answer a RendRequest.
pub(crate) struct RendRequestContext {
    /// Key we'll use to decrypt the rendezvous request.
    pub(crate) kp_hss_ntor: Arc<HsSvcNtorKeypair>,

    /// We use this key to identify our session with this introduction point,
    /// and prevent replays across sessions.
    pub(crate) kp_hs_ipt_sid: HsIntroPtSessionIdKey,

    /// A set of subcredentials that we accept as identifying ourself on this
    /// introduction point.
    pub(crate) subcredentials: Vec<Subcredential>,

    /// Provider we'll use to find a directory so that we can build a rendezvous
    /// circuit.
    pub(crate) netdir_provider: Arc<dyn tor_netdir::NetDirProvider>,

    /// Circuit pool we'll use to build a rendezvous circuit.
    pub(crate) circ_pool: Arc<dyn RendCircConnector + Send + Sync>,
}

impl RendRequest {
    /// Construct a new RendRequest from its parts.
    pub(crate) fn new(
        ipt_lid: IptLocalId,
        msg: Introduce2,
        context: Arc<RendRequestContext>,
    ) -> Self {
        Self {
            ipt_lid,
            raw: msg,
            context,
            expanded: Default::default(),
        }
    }

    /// Try to return a reference to the intro_request, creating it if it did
    /// not previously exist.
    fn intro_request(
        &self,
    ) -> Result<&rend_handshake::IntroRequest, rend_handshake::IntroRequestError> {
        self.expanded.get_or_try_init(|| {
            rend_handshake::IntroRequest::decrypt_from_introduce2(self.raw.clone(), &self.context)
        })
    }

    /// Mark this request as accepted, and try to connect to the client's
    /// provided rendezvous point.
    pub async fn accept(
        mut self,
    ) -> Result<impl Stream<Item = StreamRequest> + Unpin, ClientError> {
        // Make sure the request is there.
        self.intro_request().map_err(ClientError::BadIntroduce)?;
        // Take ownership of the request.
        let intro_request = self
            .expanded
            .take()
            .expect("intro_request succeeded but did not fill 'expanded'.");
        let rend_handshake::OpenSession {
            stream_requests,
            circuit,
        } = intro_request
            .establish_session(
                self.context.circ_pool.clone(),
                self.context.netdir_provider.clone(),
            )
            .await
            .map_err(ClientError::EstablishSession)?;

        // Note that we move circuit (which is an Arc<ClientCirc>) into this
        // closure, which lives for as long as the stream of StreamRequest, and
        // for as long as each individual StreamRequest.  This is how we keep
        // the rendezvous circuit alive.
        Ok(stream_requests.map(move |stream| StreamRequest {
            stream,
            on_circuit: circuit.clone(),
        }))
    }

    /// Reject this request.  (The client will receive no notification.)
    pub async fn reject(self) -> Result<(), Bug> {
        // nothing to do.
        Ok(())
    }

    // TODO HSS: also add various accessors
}

impl StreamRequest {
    /// Return the message that was used to request this stream.
    ///
    /// NOTE: for consistency with other onion service implementations, you
    /// should typically only accept `BEGIN` messages, and only check the port
    /// in those messages. If you behave differently, your implementation will
    /// be distinguishable.
    pub fn request(&self) -> &IncomingStreamRequest {
        self.stream.request()
    }

    /// Accept this request and send the client a `CONNECTED` message.
    pub async fn accept(self, connected_message: Connected) -> Result<DataStream, ClientError> {
        self.stream
            .accept_data(connected_message)
            .await
            .map_err(ClientError::AcceptStream)
    }

    /// Reject this request, and send the client an `END` message.
    ///
    /// NOTE: If you need to be consistent with other onion service
    /// implementations, you should typically only send back `End` messages with
    /// the `DONE` reason. If you send back any other rejection, your
    /// implementation will be distinguishable.
    pub async fn reject(self, end_message: End) -> Result<(), ClientError> {
        self.stream
            .reject(end_message)
            .await
            .map_err(ClientError::RejectStream)
    }

    /// Reject this request and close the rendezvous circuit entirely,
    /// along with all other streams attached to the circuit.
    pub fn shutdown_circuit(self) -> Result<(), Bug> {
        self.on_circuit.terminate();
        Ok(())
    }

    // TODO HSS various accessors, including for circuit.
}
