//! Request objects used to implement onion services.
//!
//! These requests are yielded on a stream, and the calling code needs to decide
//! whether to permit or reject them.

use futures::{channel::mpsc, Stream};
use std::net::SocketAddr;
use tor_cell::relaycell::msg::Introduce2;

use tor_error::Bug;
use tor_proto::{circuit::handshake::hs_ntor::HsNtorServiceInput, stream::DataStream};

use crate::{
    svc::{rend_handshake, IntroPointId},
    ClientError,
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
#[derive(Debug)]
pub struct RendRequest {
    /// The introduction point that sent this request.
    intro_point: IntroPointId,

    /// The message as received from the remote introduction point.
    raw: Introduce2,

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

/// The cryptographic state needed to complete an introduce/rendezvous
/// handshake.
#[derive(Debug, Clone)]
struct HandshakeState {
    // TODO HSS: replace this type or its contents as needed.
}

/// Information about a proof of work received from a client's introduction
/// point.
///  
// Todo: use Beth's API instead.
#[derive(Debug, Clone)]
enum ProofOfWork {
    /// TODO HSS document or replace.
    EquixV1 {
        /// TODO HSS document or replace
        effort_level: usize,
    },
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
    ///
    /// TODO HSS: Possibly instead this will be some type from tor_proto that
    /// can turn into a DataStream.
    stream: DataStream,

    /// The address that the client has asked to connect to.
    ///
    /// TODO HSS: This is the wrong type! It may be a hostname.
    target: SocketAddr,
}

/// A stream opened over an onion service.
//
// TODO HSS: This may belong in another module.
#[derive(Debug)]
pub struct OnionServiceDataStream {
    /// The underlying data stream; this type is just a thin wrapper.
    inner: DataStream,
}

impl RendRequest {
    /// Construct a new RendRequest from its parts.
    pub(crate) fn new(source: IntroPointId, msg: Introduce2) -> Self {
        Self {
            intro_point: source,
            raw: msg,
            expanded: Default::default(),
        }
    }

    /// Try to return a reference to the intro_request, creating it if it did
    /// not previously exist.
    ///
    // TODO HSS: Perhaps we need to have an Arc<HsNtorServiceInput> as a member
    // of this type instead of an argument here.
    fn intro_request(
        &self,
        keys: &HsNtorServiceInput,
    ) -> Result<&rend_handshake::IntroRequest, rend_handshake::IntroRequestError> {
        self.expanded.get_or_try_init(|| {
            rend_handshake::IntroRequest::decrypt_from_introduce2(self.raw.clone(), keys)
        })
    }

    /// Mark this request as accepted, and try to connect to the client's
    /// provided rendezvous point.
    ///
    /// TODO HSS: Should this really be async?  It might be nicer if it weren't.
    pub async fn accept(self) -> Result<impl Stream<Item = StreamRequest>, ClientError> {
        let r: Result<mpsc::Receiver<StreamRequest>, ClientError>;
        todo!();
        #[allow(unreachable_code)]
        r
    }
    /// Reject this request.  (The client will receive no notification.)
    ///
    /// TODO HSS: Should this really be async?  It might be nicer if it weren't.
    /// TODO HSS: Should this really be fallible?  How might it fail?
    pub async fn reject(self) -> Result<(), Bug> {
        // nothing to do.
        Ok(())
    }
    //
    // TODO HSS: also add various accessors
}

impl StreamRequest {
    /// Accept this request and send the client a `CONNECTED` message.
    pub async fn accept(self) -> Result<OnionServiceDataStream, ClientError> {
        todo!()
    }
    /// Reject this request, and send the client an `END` message.
    /// TODO HSS: Should this really be fallible?  How might it fail?
    pub async fn reject(self) -> Result<(), Bug> {
        todo!()
    }
    /// Reject this request and close the rendezvous circuit entirely,
    /// along with all other streams attached to the circuit.
    /// TODO HSS: Should this really be fallible?  How might it fail?
    pub fn shutdown_circuit(self) -> Result<(), Bug> {
        todo!()
    }
    // TODO HSS various accessors, including for circuit.
}
