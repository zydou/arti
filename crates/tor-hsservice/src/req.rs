//! Request objects used to implement onion services.
//!
//! These requests are yielded on a stream, and the calling code needs to decide
//! whether to permit or reject them.

use educe::Educe;
use futures::{Stream, StreamExt};
use itertools::Itertools;
use std::sync::Arc;
use tor_cell::relaycell::msg::{Connected, End, Introduce2};
use tor_hscrypto::{
    pk::{HsBlindIdKeypair, HsIdKey, HsIdKeypair, HsIntroPtSessionIdKey, HsSvcNtorKeypair},
    time::TimePeriod,
    Subcredential,
};
use tor_keymgr::{KeyMgr, KeyPath, KeyPathRange, KeySpecifierComponent, KeySpecifierPattern};
use tor_persist::slug::Slug;

use tor_error::{internal, Bug};
use tor_proto::{
    circuit::ClientCirc,
    stream::{DataStream, IncomingStream, IncomingStreamRequest},
};

use crate::{
    keys::BlindIdKeypairSpecifierPattern,
    svc::rend_handshake::{self, RendCircConnector},
    ClientError, FatalError, HsIdKeypairSpecifier, HsNickname, IptLocalId,
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
    /// The nickname of the service receiving the request.
    pub(crate) nickname: HsNickname,

    /// The key manager, used for looking up subcredentials.
    pub(crate) keymgr: Arc<KeyMgr>,

    /// Key we'll use to decrypt the rendezvous request.
    pub(crate) kp_hss_ntor: Arc<HsSvcNtorKeypair>,

    /// We use this key to identify our session with this introduction point,
    /// and prevent replays across sessions.
    pub(crate) kp_hs_ipt_sid: HsIntroPtSessionIdKey,

    /// Provider we'll use to find a directory so that we can build a rendezvous
    /// circuit.
    pub(crate) netdir_provider: Arc<dyn tor_netdir::NetDirProvider>,

    /// Circuit pool we'll use to build a rendezvous circuit.
    pub(crate) circ_pool: Arc<dyn RendCircConnector + Send + Sync>,
}

impl RendRequestContext {
    /// Obtain the all current `Subcredential`s of `nickname`
    /// from the `K_hs_blind_id` read from the keystore.
    pub(crate) fn compute_subcredentials(&self) -> Result<Vec<Subcredential>, FatalError> {
        let hsid_key_spec = HsIdKeypairSpecifier::new(self.nickname.clone());

        // TODO (#1194): Revisit when we add support for offline hsid mode
        let keypair = self
            .keymgr
            .get::<HsIdKeypair>(&hsid_key_spec)?
            .ok_or_else(|| FatalError::MissingHsIdKeypair(self.nickname.clone()))?;

        let hsid = HsIdKey::from(&keypair);

        let pattern = BlindIdKeypairSpecifierPattern {
            nickname: Some(self.nickname.clone()),
            period: None,
        }
        .arti_pattern()?;

        let blind_id_kps: Vec<(HsBlindIdKeypair, TimePeriod)> = self
            .keymgr
            .list_matching(&pattern)?
            .iter()
            .map(|entry| -> Result<Option<_>, FatalError> {
                let path = entry.key_path();
                let matches = path
                    .matches(&pattern)
                    .ok_or_else(|| internal!("path matched but no longer does?!"))?;
                let period = Self::parse_time_period(path, &matches)?;
                // Try to retrieve the key.
                self.keymgr
                    .get_entry::<HsBlindIdKeypair>(entry)
                    .map_err(FatalError::Keystore)
                    // If the key is not found, it means it has been garbage collected between the time
                    // we queried the keymgr for the list of keys matching the pattern and now.
                    // This is OK, because we only need the "current" keys
                    .map(|maybe_key| maybe_key.map(|key| (key, period)))
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, FatalError>>()?;

        Ok(blind_id_kps
            .iter()
            .map(|(blind_id_key, period)| hsid.compute_subcredential(&blind_id_key.into(), *period))
            .collect())
    }

    /// Try to parse the `captures` of `path` as a [`TimePeriod`].
    fn parse_time_period(
        path: &KeyPath,
        captures: &[KeyPathRange],
    ) -> Result<TimePeriod, tor_keymgr::Error> {
        use tor_keymgr::{KeyPathError, KeystoreCorruptionError as KCE};

        let path = match path {
            KeyPath::Arti(path) => path,
            KeyPath::CTor(_) => todo!(),
            _ => todo!(),
        };

        let [denotator] = captures else {
            return Err(internal!(
                "invalid number of denotator captures: expected 1, found {}",
                captures.len()
            )
            .into());
        };

        let Some(denotator) = path.substring(denotator) else {
            return Err(internal!("captured substring out of range?!").into());
        };

        let slug = Slug::new(denotator.to_string())
            .map_err(|e| KCE::KeyPath(KeyPathError::InvalidArtiPath(e.into())))?;
        let tp = TimePeriod::from_slug(&slug).map_err(|error| {
            KCE::KeyPath(KeyPathError::InvalidKeyPathComponentValue {
                key: "time_period".to_owned(),
                path: path.clone(),
                value: slug,
                error,
            })
        })?;

        Ok(tp)
    }
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
        // the rendezvous circuit alive, and ensure that it gets closed when
        // the Stream we return is dropped.
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

    // TODO: also add various accessors, as needed.
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

    // TODO various accessors, including for circuit.
}
