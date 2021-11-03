//! Multi-hop paths over the Tor network.
//!
//! Right now, we only implement "client circuits" -- also sometimes
//! called "origin circuits".  A client circuit is one that is
//! constructed by this Tor instance, and used in its own behalf to
//! send data over the Tor network.
//!
//! Each circuit has multiple hops over the Tor network: each hop
//! knows only the hop before and the hop after.  The client shares a
//! separate set of keys with each hop.
//!
//! To build a circuit, first create a [crate::channel::Channel], then
//! call its [crate::channel::Channel::new_circ] method.  This yields
//! a [PendingClientCirc] object that won't become live until you call
//! one of the methods that extends it to its first hop.  After you've
//! done that, you can call [ClientCirc::extend_ntor] on the circuit to
//! build it into a multi-hop circuit.  Finally, you can use
//! [ClientCirc::begin_stream] to get a Stream object that can be used
//! for anonymized data.
//!
//! # Implementation
//!
//! Each open circuit has a corresponding Reactor object that runs in
//! an asynchronous task, and manages incoming cells from the
//! circuit's upstream channel.  These cells are either RELAY cells or
//! DESTROY cells.  DESTROY cells are handled immediately.
//! RELAY cells are either for a particular stream, in which case they
//! get forwarded to a RawCellStream object, or for no particular stream,
//! in which case they are considered "meta" cells (like EXTENDED2)
//! that should only get accepted if something is waiting for them.
//!
//! # Limitations
//!
//! This is client-only.
//!
//! There's one big mutex on the whole circuit: the reactor needs to hold
//! it to process a cell, and streams need to hold it to send.
//!
//! There is no flow-control or rate-limiting or fairness.

pub(crate) mod celltypes;
pub(crate) mod halfcirc;
mod halfstream;
pub(crate) mod reactor;
pub(crate) mod sendme;
mod streammap;
mod unique_id;

use crate::channel::{Channel, CircDestroyHandle};
use crate::circuit::celltypes::*;
use crate::circuit::reactor::CtrlMsg;
pub use crate::circuit::unique_id::UniqId;
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody,
};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::stream::{DataStream, RawCellStream, ResolveStream};
use crate::{Error, Result};
use tor_cell::chancell::{self, msg::ChanMsg, ChanCell, CircId};
use tor_cell::relaycell::msg::{Begin, RelayMsg, Resolve, Resolved, ResolvedVal, Sendme};
use tor_cell::relaycell::{RelayCell, RelayCmd, StreamId};

use tor_linkspec::{ChanTarget, CircTarget, LinkSpec};

pub use tor_cell::relaycell::msg::IpVersionPreference;

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
// use std::time::Duration;

use rand::{thread_rng, CryptoRng, Rng};

use tracing::{debug, trace};

/// A circuit that we have constructed over the Tor network.
pub struct ClientCirc {
    /// This circuit can't be used because it has been closed, locally
    /// or remotely.
    closed: AtomicBool,
    /// A unique identifier for this circuit.
    unique_id: UniqId,

    /// Reference-counted locked reference to the inner circuit object.
    c: Mutex<ClientCircImpl>,
}

impl std::fmt::Debug for ClientCirc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCirc")
            .field("unique_id", &self.unique_id)
            .field("closed", &self.closed)
            .finish()
    }
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call create_firsthop_fast() or create_firsthop_ntor()
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: Arc<ClientCirc>,
}

/// Description of the network's current rules for building circuits.
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Initial value to use for our outbound circuit-level windows.
    initial_send_window: u16,
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    extend_by_ed25519_id: bool,
}

impl Default for CircParameters {
    fn default() -> CircParameters {
        CircParameters {
            initial_send_window: 1000,
            extend_by_ed25519_id: true,
        }
    }
}

impl CircParameters {
    /// Override the default initial send window for these parameters.
    /// Gives an error on any value above 1000.
    ///
    /// You should probably not call this.
    pub fn set_initial_send_window(&mut self, v: u16) -> Result<()> {
        if v <= 1000 {
            self.initial_send_window = v;
            Ok(())
        } else {
            Err(Error::BadConfig(
                "Tried to set an initial send window over 1000".into(),
            ))
        }
    }

    /// Return the initial send window as set in this parameter set.
    pub fn initial_send_window(&self) -> u16 {
        self.initial_send_window
    }

    /// Override the default decision about whether to use ed25519
    /// identities in outgoing EXTEND2 cells.
    ///
    /// You should probably not call this.
    pub fn set_extend_by_ed25519_id(&mut self, v: bool) {
        self.extend_by_ed25519_id = v;
    }

    /// Return true if we're configured to extend by ed25519 ID; false
    /// otherwise.
    pub fn extend_by_ed25519_id(&self) -> bool {
        self.extend_by_ed25519_id
    }
}

/// A result type used to tell a circuit about some a "meta-cell"
/// (like extended, intro_established, etc).
type MetaResult = Result<RelayMsg>;

/// The implementation type for this circuit.
struct ClientCircImpl {
    /// This circuit's ID on the upstream channel.
    id: CircId,
    /// The channel that this circuit uses to send its cells to the
    /// next hop.
    channel: Channel,
    /// The cryptographic state for this circuit for outbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit
    crypto_out: OutboundClientCrypt,
    /// When this is dropped, the channel reactor is told to send a DESTROY
    /// cell.
    circ_closed: Option<CircDestroyHandle>,
    /// Per-hop circuit information.
    ///
    /// Note that hops.len() must be the same as crypto.n_layers().
    hops: Vec<CircHop>,
    /// Control channel to send messages to the reactor.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// A oneshot sender that can be used by the reactor to report a
    /// meta-cell to an owning task.
    ///
    /// This comes along with a hop number saying which hop we expect a
    /// meta-cell from.  Cells from other hops won't go to this sender.
    ///
    /// For the purposes of this implementation, a "meta" cell
    /// is a RELAY cell with a stream ID value of 0.
    sendmeta: Option<(HopNum, oneshot::Sender<MetaResult>)>,

    /// An identifier for this circuit, for logging purposes.
    /// TODO: Make this field go away in favor of the one in ClientCirc.
    unique_id: UniqId,
}

/// A handle to a circuit as held by a stream. Used to send cells.
///
/// Rather than using the stream directly, the stream uses this object
/// to send its relay cells to the correct hop, using the correct stream ID.
///
/// When this object is dropped, the reactor will be told to close the stream.
// XXXX TODO: rename this
pub(crate) struct StreamTarget {
    /// The stream ID for this stream on its circuit.
    stream_id: StreamId,
    /// Which hop on this circuit is this stream built from?
    // XXXX Using 'hop' by number here will cause bugs if circuits can get
    // XXXX truncated and then re-extended.
    hop: HopNum,
    /// Reference to the circuit that this stream is on.
    circ: Arc<ClientCirc>,
    /// Window for sending cells on this circuit.
    window: sendme::StreamSendWindow,
    /// Control sender, for notifying the reactor when this stream gets dropped.
    control: mpsc::UnboundedSender<CtrlMsg>,
    /// Window to track incoming cells and SENDMEs.
    // XXXX Putting this field here in this object means that this
    // object isn't really so much a "target", since a "target"
    // doesn't know how to receive.  Maybe we should rename it to be
    // some kind of a "handle" or something?
    pub(crate) recvwindow: sendme::StreamRecvWindow,
}

/// Information about a single hop of a client circuit, from the sender-side
/// point of view.
///
/// (see also circuit::reactor::InboundHop)
struct CircHop {
    /// If true, this hop is using an older link protocol and we
    /// shouldn't expect good authenticated SENDMEs from it.
    auth_sendme_optional: bool,
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
}

impl CircHop {
    /// Construct a new (sender-side) view of a circuit hop.
    fn new(auth_sendme_optional: bool, initial_window: u16) -> Self {
        CircHop {
            auth_sendme_optional,
            sendwindow: sendme::CircSendWindow::new(initial_window),
        }
    }
}

impl ClientCirc {
    /// Helper: return the number of hops for this circuit
    #[cfg(test)]
    async fn n_hops(&self) -> usize {
        let c = self.c.lock().await;
        c.crypto_out.n_layers()
    }

    /// Helper: extend the circuit by one hop.
    ///
    /// The `rng` is used to generate handshake material.  The
    /// `handshake_id` is the numeric identifier for what kind of
    /// handshake we're doing.  The `key is the relay's onion key that
    /// goes along with the handshake, and the `linkspecs` are the
    /// link specifiers to include in the EXTEND cell to tell the
    /// current last hop which relay to connect to.
    async fn extend_impl<R, L, FWD, REV, H>(
        &self,
        rng: &mut R,
        handshake_id: u16,
        key: &H::KeyType,
        linkspecs: Vec<LinkSpec>,
        supports_flowctrl_1: bool,
        params: &CircParameters,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV>,
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        H::KeyGen: KeyGenerator,
    {
        use tor_cell::relaycell::msg::{Body, Extend2};
        // Perform the first part of the cryptographic handshake
        let (state, msg) = H::client1(rng, key)?;
        // Cloning linkspecs is only necessary because of the log
        // below. Would be nice to fix that.
        let extend_msg = Extend2::new(linkspecs.clone(), handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.into_message());

        // Now send the EXTEND2 cell to the the last hop...
        let (unique_id, _hop, receiver) = {
            let mut c = self.c.lock().await;
            let n_hops = c.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();
            debug!(
                "{}: Extending circuit to hop {} with {:?}",
                c.unique_id,
                n_hops + 1,
                linkspecs
            );

            // We'll be waiting for an EXTENDED2 cell; install the handler.
            let receiver = c.register_meta_handler(hop)?;

            // Send the message to the last hop...
            c.send_relay_cell(
                hop, true, // use a RELAY_EARLY cell
                cell,
            )
            .await?;

            (c.unique_id, hop, receiver)
            // note that we're dropping the lock here, since we're going
            // to wait for a response.
        };

        trace!("{}: waiting for EXTENDED2 cell", unique_id);
        // ... and now we wait for a response.
        let msg = match receiver.await {
            Ok(Ok(m)) => Ok(m),
            Err(_) => Err(Error::InternalError(
                "Receiver cancelled while waiting for EXTENDED2".into(),
            )),
            Ok(Err(Error::CircuitClosed)) => Err(Error::CircDestroy(
                "Circuit closed while waiting for EXTENDED2".into(),
            )),
            Ok(Err(e)) => Err(e),
        }?;

        // XXXX If two EXTEND cells are of these are launched on the
        // same circuit at once, could they collide in this part of
        // the function?  I don't _think_ so, but it might be a good idea
        // to have an "extending" bit that keeps two tasks from entering
        // extend_impl at the same time.
        //
        // Also we could enforce that `hop` is still what we expect it
        // to be at this point.

        // Did we get the right response?
        if msg.cmd() != RelayCmd::EXTENDED2 {
            self.protocol_error().await;
            return Err(Error::CircProto(format!(
                "wanted EXTENDED2; got {}",
                msg.cmd(),
            )));
        }

        // ???? Do we need to shutdown the circuit for the remaining error
        // ???? cases in this function?

        let msg = match msg {
            RelayMsg::Extended2(e) => e,
            _ => return Err(Error::InternalError("Body didn't match cmd".into())),
        };
        let relay_handshake = msg.into_body();

        trace!(
            "{}: Received EXTENDED2 cell; completing handshake.",
            unique_id
        );
        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let keygen = H::client2(state, relay_handshake)?;
        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit extended.", unique_id);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back) = layer.split();
        self.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
            params,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    ///
    /// This function is a bit tricky, since we need to add the
    /// hop to our own structures, and tell the reactor to add it to the
    /// reactor's structures as well, and wait for the reactor to tell us
    /// that it did.
    async fn add_hop<'a>(
        &'a self,
        supports_flowctrl_1: bool,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        params: &'a CircParameters,
    ) -> Result<()> {
        let inbound_hop = crate::circuit::reactor::InboundHop::new();
        let (snd, rcv) = oneshot::channel();
        {
            let c = self.c.lock().await;
            c.control
                .unbounded_send(CtrlMsg::AddHop(inbound_hop, rev, snd))
                .map_err(|_| Error::InternalError("Can't queue AddHop request".into()))?;
        }

        // I think we don't need to worry about two hops being added at
        // once, because there can only be on meta-message receiver at
        // a time.

        rcv.await
            .map_err(|_| Error::InternalError("AddHop request cancelled".into()))?;

        {
            let mut c = self.c.lock().await;
            let hop = CircHop::new(supports_flowctrl_1, params.initial_send_window());
            c.hops.push(hop);
            c.crypto_out.add_layer(fwd);
        }
        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    ///
    /// The same caveats apply from extend_impl.
    pub async fn extend_ntor<R, Tg>(
        &self,
        rng: &mut R,
        target: &Tg,
        params: &CircParameters,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        Tg: CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let key = NtorPublicKey {
            id: *target.rsa_identity(),
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target.linkspecs();
        if !params.extend_by_ed25519_id() {
            linkspecs.retain(|ls| !matches!(ls, LinkSpec::Ed25519Id(_)));
        }
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.extend_impl::<R, Tor1RelayCrypto, _, _, NtorClient>(
            rng,
            0x0002,
            &key,
            linkspecs,
            supports_flowctrl_1,
            params,
        )
        .await
    }

    /// Helper, used to begin a stream.
    ///
    /// This function allocates a stream ID, and sends the message
    /// (like a BEGIN or RESOLVE), but doesn't wait for a response.
    ///
    /// The caller will typically want to see the first cell in response,
    /// to see whether it is e.g. an END or a CONNECTED.
    async fn begin_stream_impl(self: &Arc<Self>, begin_msg: RelayMsg) -> Result<RawCellStream> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.

        // XXXX Both a bound and a lack of bound are scary here :/
        let (sender, receiver) = mpsc::channel(128);

        let window = sendme::StreamSendWindow::new(StreamTarget::SEND_WINDOW_INIT);

        let (id_snd, id_rcv) = oneshot::channel();
        let hopnum;
        {
            let c = self.c.lock().await;
            let h = c.hops.len() - 1;
            hopnum = (h as u8).into();

            c.control
                .unbounded_send(CtrlMsg::AddStream(hopnum, sender, window.new_ref(), id_snd))
                .map_err(|_| Error::InternalError("Can't queue new-stream request.".into()))?;
        }

        let id = id_rcv
            .await
            .map_err(|_| Error::InternalError("Didn't receive a stream ID.".into()))?;
        let id = id?;

        let relaycell = RelayCell::new(id, begin_msg);

        let control_tx = {
            let mut c = self.c.lock().await;
            c.send_relay_cell(hopnum, false, relaycell).await?;
            c.control.clone()
        };

        /// Initial value for inbound flow-control window on streams.
        const STREAM_RECV_INIT: u16 = 500;

        let target = StreamTarget {
            circ: Arc::clone(self),
            stream_id: id,
            hop: hopnum,
            window,
            recvwindow: sendme::StreamRecvWindow::new(STREAM_RECV_INIT),
            control: control_tx,
        };

        Ok(RawCellStream::new(target, receiver))
    }

    /// Start a DataStream (anonymized connection) to the given
    /// address and port, using a BEGIN cell.
    async fn begin_data_stream(self: Arc<Self>, msg: RelayMsg) -> Result<DataStream> {
        let stream = self.begin_stream_impl(msg).await?;
        // TODO: waiting for a response here precludes optimistic data.

        let response = stream.recv().await?;
        match response {
            RelayMsg::Connected(_) => Ok(DataStream::new(stream)),
            RelayMsg::End(cell) => Err(Error::EndReceived(cell.reason())),
            _ => {
                self.protocol_error().await;
                Err(Error::StreamProto(format!(
                    "Received {} while waiting for connection",
                    response.cmd()
                )))
            }
        }
    }

    /// Start a stream to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(
        self: Arc<Self>,
        target: &str,
        port: u16,
        flags: Option<IpVersionPreference>,
    ) -> Result<DataStream> {
        let flags = flags.unwrap_or_default();
        let beginmsg = Begin::new(target, port, flags)?;
        self.begin_data_stream(beginmsg.into()).await
    }

    /// Start a new stream to the last relay in the circuit, using
    /// a BEGIN_DIR cell.
    pub async fn begin_dir_stream(self: Arc<Self>) -> Result<DataStream> {
        self.begin_data_stream(RelayMsg::BeginDir).await
    }

    /// Perform a DNS lookup, using a RESOLVE cell with the last relay
    /// in this circuit.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve(self: Arc<Self>, hostname: &str) -> Result<Vec<IpAddr>> {
        let resolve_msg = Resolve::new(hostname);

        let resolved_msg = self.try_resolve(resolve_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Ip(ip)) => Some(Ok(ip)),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Perform a reverse DNS lookup, by sending a RESOLVE cell with
    /// the last relay on this circuit.
    ///
    /// Note that this function does not check for timeouts; that's
    /// the caller's responsibility.
    pub async fn resolve_ptr(self: Arc<Self>, addr: IpAddr) -> Result<Vec<String>> {
        let resolve_ptr_msg = Resolve::new_reverse(&addr);

        let resolved_msg = self.try_resolve(resolve_ptr_msg).await?;

        resolved_msg
            .into_answers()
            .into_iter()
            .filter_map(|(val, _)| match resolvedval_to_result(val) {
                Ok(ResolvedVal::Hostname(v)) => Some(
                    String::from_utf8(v)
                        .map_err(|_| Error::StreamProto("Resolved Hostname was not utf-8".into())),
                ),
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    /// Helper: Encode the relay cell `cell`, encrypt it, and send it to the
    /// 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&self, hop: HopNum, early: bool, cell: RelayCell) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::CircuitClosed);
        }
        let mut c = self.c.lock().await;
        c.send_relay_cell(hop, early, cell).await
    }

    /// Helper: Send the resolve message, and read resolved message from
    /// resolve stream.
    async fn try_resolve(self: &Arc<Self>, msg: Resolve) -> Result<Resolved> {
        let rc_stream = self.begin_stream_impl(msg.into()).await?;
        let mut resolve_stream = ResolveStream::new(rc_stream);
        resolve_stream.read_msg().await
    }

    /// Shut down this circuit immediately, along with all streams that
    /// are using it.
    ///
    /// Note that other references to this circuit may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a circuit: the channel should close on its own once nothing
    /// is using it any more.
    pub async fn terminate(&self) {
        let outcome = self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        if outcome == Ok(false) {
            // The old value was false and the new value is true.
            self.c.lock().await.shutdown_reactor();
        }
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// circuit needs to shut down.
    ///
    /// This is a separate function because we may eventually want to have
    /// it do more than just shut down.
    pub(crate) async fn protocol_error(&self) {
        self.terminate().await;
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Return a process-unique identifier for this circuit.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Helper: register a meta-handler for this circuit.
    #[cfg(test)]
    async fn register_meta_handler(&self, hop: HopNum) -> Result<oneshot::Receiver<MetaResult>> {
        let mut c = self.c.lock().await;
        c.register_meta_handler(hop)
    }
}

impl ClientCircImpl {
    /// Return a mutable reference to the nth hop of this circuit, if one
    /// exists.
    fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Helper: Register a handler that will be told about the RELAY message
    /// with StreamId 0.
    ///
    /// This pattern is useful for parts of the protocol where the circuit
    /// originator sends a single request, and waits for a single relay
    /// message in response.  (For example, EXTEND/EXTENDED,
    /// ESTABLISH_RENDEZVOUS/RENDEZVOUS_ESTABLISHED, and so on.)
    ///
    /// It isn't suitable for SENDME cells, INTRODUCE2 cells, or TRUNCATED
    /// cells.
    ///
    /// Only one handler can be registered at a time; until it fires or is
    /// cancelled, you can't register another.
    ///
    /// Note that you should register a meta handler _before_ you send whatever
    /// cell you're waiting a response to, or you might miss the response.
    // TODO: It would be cool for this to take a list of allowable
    // cell types to get in response, so that any other cell types are
    // treated as circuit protocol violations automatically.
    fn register_meta_handler(&mut self, hop: HopNum) -> Result<oneshot::Receiver<MetaResult>> {
        // Was there previously a handler?
        if self.sendmeta.is_some() {
            return Err(Error::InternalError(
                "Tried to register a second meta-cell handler".into(),
            ));
        }
        let (sender, receiver) = oneshot::channel();

        self.sendmeta = Some((hop, sender));

        trace!(
            "{}: Registered a meta-cell handler for hop {}",
            self.unique_id,
            hop
        );

        Ok(receiver)
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    async fn handle_meta_cell(&mut self, hopnum: HopNum, msg: RelayMsg) -> Result<()> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.
        if let RelayMsg::Sendme(s) = msg {
            return self.handle_sendme(hopnum, s).await;
        }
        if let RelayMsg::Truncated(_) = msg {
            // XXXX need to handle Truncated cells. This isn't the right
            // way, but at least it's safe.
            // TODO: If we ever do handle Truncate cells more
            // correctly, we will need to audit all our use of HopNum
            // to identify a layer.  Otherwise we could confuse a
            // message from the previous hop N with a message from the
            // new hop N.
            return Err(Error::CircuitClosed);
        }

        trace!("{}: Received meta-cell {:?}", self.unique_id, msg);

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some((expected_hop, sender)) = self.sendmeta.take() {
            if expected_hop == hopnum {
                // Somebody was waiting for a message -- maybe this message
                sender
                    .send(Ok(msg))
                    // I think this means that the channel got closed.
                    .map_err(|_| Error::CircuitClosed)
            } else {
                // Somebody wanted a message from a different hop!  Put this
                // one back.
                self.sendmeta = Some((expected_hop, sender));
                Err(Error::CircProto(format!(
                    "Unexpected {} cell from hop {} on client circuit",
                    msg.cmd(),
                    hopnum,
                )))
            }
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    async fn handle_sendme(&mut self, hopnum: HopNum, msg: Sendme) -> Result<()> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find {} hop", hopnum)))?;

        let auth: Option<[u8; 20]> = match msg.into_tag() {
            Some(v) if v.len() == 20 => {
                // XXXX ugly code.
                let mut tag = [0_u8; 20];
                (&mut tag).copy_from_slice(&v[..]);
                Some(tag)
            }
            Some(_) => return Err(Error::CircProto("malformed tag on circuit sendme".into())),
            None => {
                if !hop.auth_sendme_optional {
                    return Err(Error::CircProto("missing tag on circuit sendme".into()));
                } else {
                    None
                }
            }
        };
        match hop.sendwindow.put(auth).await {
            Some(_) => Ok(()),
            None => Err(Error::CircProto("bad auth tag on circuit sendme".into())),
        }
    }

    /// Helper: Put a cell onto this circuit's channel.
    ///
    /// This takes a raw cell that has already been encrypted, puts
    /// a circuit ID on it, and sends it.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Helper: Encode the relay cell `cell`, encrypt it, and send it to the
    /// 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&mut self, hop: HopNum, early: bool, cell: RelayCell) -> Result<()> {
        let c_t_w = sendme::cell_counts_towards_windows(&cell);
        let mut body: RelayCellBody = cell.encode(&mut thread_rng())?.into();
        let tag = self.crypto_out.encrypt(&mut body, hop)?;
        let msg = chancell::msg::Relay::from_raw(body.into());
        let msg = if early {
            ChanMsg::RelayEarly(msg)
        } else {
            ChanMsg::Relay(msg)
        };
        // If the cell counted towards our sendme window, decrement
        // that window, and maybe remember the authentication tag.
        if c_t_w {
            // TODO: I'd like to use get_hops_mut here, but the borrow checker
            // won't let me.
            // This blocks if the send window is empty.
            self.hops[Into::<usize>::into(hop)]
                .sendwindow
                .take(tag)
                .await?;
        }
        self.send_msg(msg).await
    }

    /// Shut down this circuit's reactor and send a DESTROY cell.
    ///
    /// This is idempotent and safe to call more than once.
    fn shutdown_reactor(&mut self) {
        let _ = self.control.unbounded_send(CtrlMsg::Shutdown);
        // Drop the circuit destroy handle now so that a DESTROY cell
        // gets sent.
        drop(self.circ_closed.take());
    }
}

impl PendingClientCirc {
    /// Instantiate a new circuit object: used from Channel::new_circ().
    ///
    /// Does not send a CREATE* cell on its own.
    ///
    ///
    pub(crate) fn new(
        id: CircId,
        channel: Channel,
        createdreceiver: oneshot::Receiver<CreateResponse>,
        circ_closed: Option<CircDestroyHandle>,
        input: mpsc::Receiver<ClientCircChanMsg>,
        unique_id: UniqId,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let crypto_out = OutboundClientCrypt::new();
        let (control_tx, control_rx) = mpsc::unbounded();
        let hops = Vec::new();

        let circuit_impl = ClientCircImpl {
            id,
            channel,
            crypto_out,
            hops,
            circ_closed,
            control: control_tx,
            sendmeta: None,
            unique_id,
        };
        let circuit = ClientCirc {
            closed: AtomicBool::new(false),
            c: Mutex::new(circuit_impl),
            unique_id,
        };
        let circuit = Arc::new(circuit);
        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: Arc::clone(&circuit),
        };
        let reactor = reactor::Reactor::new(&circuit, control_rx, input, unique_id);
        (pending, reactor)
    }

    /// Check whether this pending circuit matches a given channel target;
    /// return an error if it doesn't.
    async fn check_chan_match<T: ChanTarget>(&self, target: &T) -> Result<()> {
        let c = self.circ.c.lock().await;
        c.channel.check_match(target)
    }

    /// Testing only: extract the circuit ID for this pending circuit.
    #[cfg(test)]
    pub(crate) async fn peek_circid(&self) -> CircId {
        let c = self.circ.c.lock().await;
        c.id
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, FWD, REV, H, W>(
        self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
        supports_flowctrl_1: bool,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV> + 'static + Send, // need all this?XXXX
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let PendingClientCirc { circ, recvcreated } = self;
        let (state, msg) = H::client1(rng, key)?;
        let create_cell = wrap.to_chanmsg(msg);
        let unique_id = {
            let mut c = circ.c.lock().await;
            debug!(
                "{}: Extending to hop 1 with {}",
                c.unique_id,
                create_cell.cmd()
            );
            c.send_msg(create_cell).await?;
            c.unique_id
        };

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let relay_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, relay_handshake)?;

        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit created.", unique_id);

        let (layer_fwd, layer_back) = layer.split();
        circ.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
            params,
        )
        .await?;
        Ok(circ)
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast<R>(
        self,
        rng: &mut R,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::fast::CreateFastClient;
        let wrap = CreateFastWrap;
        self.create_impl::<R, Tor1RelayCrypto, _, _, CreateFastClient, _>(
            rng,
            &wrap,
            &(),
            false,
            params,
        )
        .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop_ntor<R, Tg>(
        self,
        rng: &mut R,
        target: &Tg,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};

        // Exit now if we have an Ed25519 or RSA identity mismatch.
        self.check_chan_match(target).await?;

        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        let key = NtorPublicKey {
            id: *target.rsa_identity(),
            pk: *target.ntor_onion_key(),
        };
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.create_impl::<R, Tor1RelayCrypto, _, _, NtorClient, _>(
            rng,
            &wrap,
            &key,
            supports_flowctrl_1,
            params,
        )
        .await
    }
}

/// An object that can put a given handshake into a ChanMsg for a CREATE*
/// cell, and unwrap a CREATED* cell.
trait CreateHandshakeWrap {
    /// Construct an appropriate ChanMsg to hold this kind of handshake.
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    /// Decode a ChanMsg to an appropriate handshake value, checking
    /// its type.
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            CreatedFast(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with unexpected cell.",
            )),
        }
    }
}

/// A CreateHandshakeWrap that generates CREATE2 and handles CREATED2
struct Create2Wrap {
    /// The handshake type to put in the CREATE2 cell.
    handshake_type: u16,
}
impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::Create2::new(self.handshake_type, bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            Created2(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE2 with unexpected cell.",
            )),
        }
    }
}

impl StreamTarget {
    /// Initial value for outbound flow-control window on streams.
    const SEND_WINDOW_INIT: u16 = 500;

    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        if sendme::msg_counts_towards_windows(&msg) {
            // Decrement the stream window (and block if it's empty)
            self.window.take(&()).await?;
        }
        let cell = RelayCell::new(self.stream_id, msg);
        self.circ.send_relay_cell(self.hop, false, cell).await
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// circuit needs to shut down.
    pub(crate) async fn protocol_error(&mut self) {
        self.circ.protocol_error().await;
    }
}

impl Drop for ClientCircImpl {
    fn drop(&mut self) {
        self.shutdown_reactor();
    }
}

impl Drop for StreamTarget {
    fn drop(&mut self) {
        // This "clone" call is a bit dangerous: it means that we might
        // allow the other side to send a couple of cells that get
        // decremented from self.recvwindow but don't get reflected
        // in the circuit-owned view of the window.
        let window = self.recvwindow.clone();
        let _ = self
            .control
            .unbounded_send(CtrlMsg::CloseStream(self.hop, self.stream_id, window));
        // If there's an error, no worries: it's hard-cancel, and we
        // can just ignore it. XXXX (I hope?)
    }
}

/// Convert a [`ResolvedVal`] into a Result, based on whether or not
/// it represents an error.
fn resolvedval_to_result(val: ResolvedVal) -> Result<ResolvedVal> {
    match val {
        ResolvedVal::TransientError => Err(Error::ResolveError(
            "Received retriable transient error".into(),
        )),
        ResolvedVal::NontransientError => {
            Err(Error::ResolveError("Received not retriable error.".into()))
        }
        _ => Ok(val),
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::channel::test::new_reactor;
    use chanmsg::{ChanMsg, Created2, CreatedFast};
    use futures::channel::mpsc::{Receiver, Sender};
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use hex_literal::hex;
    use tokio::runtime::Handle;
    use tokio_crate as tokio;
    use tokio_crate::test as async_test;
    use tor_cell::chancell::msg as chanmsg;
    use tor_cell::relaycell::msg as relaymsg;
    use tor_llcrypto::pk;

    fn rmsg_to_ccmsg<ID>(id: ID, msg: relaymsg::RelayMsg) -> ClientCircChanMsg
    where
        ID: Into<StreamId>,
    {
        let body: RelayCellBody = RelayCell::new(id.into(), msg)
            .encode(&mut thread_rng())
            .unwrap()
            .into();
        let chanmsg = chanmsg::Relay::from_raw(body.into());
        ClientCircChanMsg::Relay(chanmsg)
    }

    struct ExampleTarget {
        ntor_key: pk::curve25519::PublicKey,
        protovers: tor_protover::Protocols,
        ed_id: pk::ed25519::Ed25519Identity,
        rsa_id: pk::rsa::RsaIdentity,
    }
    impl tor_linkspec::ChanTarget for ExampleTarget {
        fn addrs(&self) -> &[std::net::SocketAddr] {
            &[]
        }
        fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
            &self.ed_id
        }
        fn rsa_identity(&self) -> &pk::rsa::RsaIdentity {
            &self.rsa_id
        }
    }
    impl tor_linkspec::CircTarget for ExampleTarget {
        fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
            &self.ntor_key
        }
        fn protovers(&self) -> &tor_protover::Protocols {
            &self.protovers
        }
    }
    /// return an ExampleTarget that can get used for an ntor handshake.
    fn example_target() -> ExampleTarget {
        ExampleTarget {
            ntor_key: hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253")
                .into(),
            protovers: "FlowCtrl=1".parse().unwrap(),
            ed_id: [6_u8; 32].into(),
            rsa_id: [10_u8; 20].into(),
        }
    }
    fn example_ntor_key() -> crate::crypto::handshake::ntor::NtorSecretKey {
        crate::crypto::handshake::ntor::NtorSecretKey::new(
            hex!("7789d92a89711a7e2874c61ea495452cfd48627b3ca2ea9546aafa5bf7b55803").into(),
            hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253").into(),
            [10_u8; 20].into(),
        )
    }

    fn working_fake_channel() -> (
        Channel,
        Receiver<ChanCell>,
        Sender<std::result::Result<ChanCell, tor_cell::Error>>,
    ) {
        let (channel, chan_reactor, rx, tx) = new_reactor();
        Handle::current().spawn(chan_reactor.run());
        (channel, rx, tx)
    }

    async fn test_create(fast: bool) {
        // We want to try progressing from a pending circuit to a circuit
        // via a crate_fast handshake.

        use crate::crypto::handshake::{fast::CreateFastServer, ntor::NtorServer, ServerHandshake};
        use futures::future::FutureExt;

        let (chan, mut rx, _sink) = working_fake_channel();
        let circid = 128.into();
        let (created_send, created_recv) = oneshot::channel();
        let (_circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, mut reactor) = PendingClientCirc::new(
            circid,
            chan,
            created_recv,
            None, // circ_closed.
            circmsg_recv,
            unique_id,
        );

        // Future to pretend to be a relay on the other end of the circuit.
        let simulate_relay_fut = async move {
            let mut rng = rand::thread_rng();
            let create_cell = rx.next().await.unwrap();
            assert_eq!(create_cell.circid(), 128.into());
            let reply = if fast {
                let cf = match create_cell.msg() {
                    ChanMsg::CreateFast(cf) => cf,
                    _ => panic!(),
                };
                let (_, rep) = CreateFastServer::server(&mut rng, &[()], cf.body()).unwrap();
                CreateResponse::CreatedFast(CreatedFast::new(rep))
            } else {
                let c2 = match create_cell.msg() {
                    ChanMsg::Create2(c2) => c2,
                    _ => panic!(),
                };
                let (_, rep) =
                    NtorServer::server(&mut rng, &[example_ntor_key()], c2.body()).unwrap();
                CreateResponse::Created2(Created2::new(rep))
            };
            created_send.send(reply).unwrap();
        };
        // Future to pretend to be a client.
        let client_fut = async move {
            let mut rng = rand::thread_rng();
            let target = example_target();
            let params = CircParameters::default();
            let ret = if fast {
                eprintln!("doing fast create");
                pending.create_firsthop_fast(&mut rng, &params).await
            } else {
                eprintln!("doing ntor create");
                pending
                    .create_firsthop_ntor(&mut rng, &target, &params)
                    .await
            };
            eprintln!("create done: result {:?}", ret);
            ret
        };
        // Future to run the reactor.
        let reactor_fut = reactor.run_once().map(|_| ());

        let (circ, _, _) = futures::join!(client_fut, reactor_fut, simulate_relay_fut);

        let _circ = circ.unwrap();

        // pfew!  We've build a circuit!  Let's make sure it has one hop.
        /* TODO: reinstate this.
        let inner = Arc::get_mut(&mut circuit).unwrap().c.into_inner();
        assert_eq!(inner.hops.len(), 1);
         */
    }

    #[async_test]
    async fn test_create_fast() {
        test_create(true).await
    }
    #[async_test]
    async fn test_create_ntor() {
        test_create(false).await
    }

    // An encryption layer that doesn't do any crypto.   Can be used
    // as inbound or outbound, but not both at once.
    struct DummyCrypto {
        counter_tag: [u8; 20],
        counter: u32,
        lasthop: bool,
    }
    impl DummyCrypto {
        fn next_tag(&mut self) -> &[u8; 20] {
            #![allow(clippy::identity_op)]
            self.counter_tag[0] = ((self.counter >> 0) & 255) as u8;
            self.counter_tag[1] = ((self.counter >> 8) & 255) as u8;
            self.counter_tag[2] = ((self.counter >> 16) & 255) as u8;
            self.counter_tag[3] = ((self.counter >> 24) & 255) as u8;
            self.counter += 1;
            &self.counter_tag
        }
    }

    impl crate::crypto::cell::OutboundClientLayer for DummyCrypto {
        fn originate_for(&mut self, _cell: &mut RelayCellBody) -> &[u8] {
            self.next_tag()
        }
        fn encrypt_outbound(&mut self, _cell: &mut RelayCellBody) {}
    }
    impl crate::crypto::cell::InboundClientLayer for DummyCrypto {
        fn decrypt_inbound(&mut self, _cell: &mut RelayCellBody) -> Option<&[u8]> {
            if self.lasthop {
                Some(self.next_tag())
            } else {
                None
            }
        }
    }
    impl DummyCrypto {
        fn new(lasthop: bool) -> Self {
            DummyCrypto {
                counter_tag: [0; 20],
                counter: 0,
                lasthop,
            }
        }
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newcirc_ext(
        chan: Channel,
        next_msg_from: HopNum,
    ) -> (
        Arc<ClientCirc>,
        reactor::Reactor,
        mpsc::Sender<ClientCircChanMsg>,
    ) {
        let circid = 128.into();
        let (_created_send, created_recv) = oneshot::channel();
        let (circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, mut reactor) = PendingClientCirc::new(
            circid,
            chan,
            created_recv,
            None, // circ_closed.
            circmsg_recv,
            unique_id,
        );

        let PendingClientCirc {
            circ,
            recvcreated: _,
        } = pending;

        for idx in 0_u8..3 {
            let params = CircParameters::default();
            let (hopf, reacf) = futures::join!(
                circ.add_hop(
                    true,
                    Box::new(DummyCrypto::new(idx == 2)),
                    Box::new(DummyCrypto::new(idx == next_msg_from.into())),
                    &params,
                ),
                reactor.run_once()
            );
            assert!(hopf.is_ok());
            assert!(reacf.is_ok());
        }

        (circ, reactor, circmsg_send)
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newcirc(
        chan: Channel,
    ) -> (
        Arc<ClientCirc>,
        reactor::Reactor,
        mpsc::Sender<ClientCircChanMsg>,
    ) {
        newcirc_ext(chan, 2.into()).await
    }

    // Try sending a cell via send_relay_cell
    #[async_test]
    async fn send_simple() {
        let (chan, mut rx, _sink) = working_fake_channel();
        let (circ, _reactor, _send) = newcirc(chan).await;
        let begindir = RelayCell::new(0.into(), RelayMsg::BeginDir);
        circ.send_relay_cell(2.into(), false, begindir)
            .await
            .unwrap();

        // Here's what we tried to put on the TLS channel.  Note that
        // we're using dummy relay crypto for testing convenience.
        let rcvd = rx.next().await.unwrap();
        assert_eq!(rcvd.circid(), 128.into());
        let m = match rcvd.into_circid_and_msg().1 {
            ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
            _ => panic!(),
        };
        assert!(matches!(m.msg(), RelayMsg::BeginDir));
    }

    // Try getting a "meta-cell", which is what we're calling those not
    // for a specific circuit.
    #[async_test]
    async fn recv_meta() {
        let (chan, _, _sink) = working_fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;

        // 1: Try doing it via handle_meta_cell directly.
        let meta_receiver = circ.register_meta_handler(2.into()).await.unwrap();
        let extended: RelayMsg = relaymsg::Extended2::new((*b"123").into()).into();
        {
            circ.c
                .lock()
                .await
                .handle_meta_cell(2.into(), extended.clone())
                .await
                .unwrap();
        }
        let msg = meta_receiver.await.unwrap().unwrap();
        assert!(matches!(msg, RelayMsg::Extended2(_)));

        // 2: Try doing it via the reactor.
        let meta_receiver = circ.register_meta_handler(2.into()).await.unwrap();
        sink.send(rmsg_to_ccmsg(0, extended.clone())).await.unwrap();
        reactor.run_once().await.unwrap();
        let msg = meta_receiver.await.unwrap().unwrap();
        assert!(matches!(msg, RelayMsg::Extended2(_)));

        // 3: Try getting a meta cell that we didn't want.
        let e = {
            circ.c
                .lock()
                .await
                .handle_meta_cell(2.into(), extended.clone())
                .await
                .err()
                .unwrap()
        };
        assert_eq!(
            format!("{}", e),
            "circuit protocol violation: Unexpected EXTENDED2 cell on client circuit"
        );

        // 3: Try getting a meta from a hop that we didn't want.
        let _receiver = circ.register_meta_handler(2.into()).await.unwrap();
        let e = {
            circ.c
                .lock()
                .await
                .handle_meta_cell(1.into(), extended.clone())
                .await
                .err()
                .unwrap()
        };
        assert_eq!(
            format!("{}", e),
            "circuit protocol violation: Unexpected EXTENDED2 cell from hop 1 on client circuit"
        );
    }

    #[async_test]
    async fn extend() {
        use crate::crypto::handshake::{ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;
        let params = CircParameters::default();

        let extend_fut = async move {
            let target = example_target();
            let mut rng = thread_rng();
            circ.extend_ntor(&mut rng, &target, &params).await.unwrap();
            circ // gotta keep the circ alive, or the reactor would exit.
        };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the extend2 cell.
            let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, 128.into());
            let rmsg = match chmsg {
                ChanMsg::RelayEarly(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let e2 = match rmsg.msg() {
                RelayMsg::Extend2(e2) => e2,
                _ => panic!(),
            };
            let mut rng = thread_rng();
            let (_, reply) =
                NtorServer::server(&mut rng, &[example_ntor_key()], e2.handshake()).unwrap();
            let extended2 = relaymsg::Extended2::new(reply).into();
            sink.send(rmsg_to_ccmsg(0, extended2)).await.unwrap();
            sink // gotta keep the sink alive, or the reactor will exit.
        };
        let reactor_fut = async move {
            reactor.run_once().await.unwrap(); // to deliver the relay cell
            reactor.run_once().await.unwrap(); // to handle the AddHop
        };

        let (circ, _, _) = futures::join!(extend_fut, reply_fut, reactor_fut);

        // Did we really add another hop?
        assert_eq!(circ.n_hops().await, 4);
    }

    async fn bad_extend_test_impl(reply_hop: HopNum, bad_reply: ClientCircChanMsg) -> Error {
        let (chan, _rx, _sink) = working_fake_channel();
        let (circ, mut reactor, mut sink) = newcirc_ext(chan, reply_hop).await;
        let params = CircParameters::default();

        let extend_fut = async move {
            let target = example_target();
            let mut rng = thread_rng();
            let outcome = circ.extend_ntor(&mut rng, &target, &params).await;
            (outcome, circ) // keep the circ alive, or the reactor will exit.
        };
        let bad_reply_fut = async move {
            sink.send(bad_reply).await.unwrap();
            sink // keep the sink alive, or the reactor will exit.
        };
        let reactor_fut = async move {
            let res = reactor.run_once().await;
            if res.is_err() {
                reactor.propagate_close().await;
            }
        };
        let ((outcome, circ), _, _) = futures::join!(extend_fut, bad_reply_fut, reactor_fut);

        assert_eq!(circ.n_hops().await, 3);
        assert!(outcome.is_err());
        outcome.unwrap_err()
    }

    #[async_test]
    async fn bad_extend_wronghop() {
        let extended2 = relaymsg::Extended2::new(vec![]).into();
        let cc = rmsg_to_ccmsg(0, extended2);

        let error = bad_extend_test_impl(1.into(), cc).await;
        // This case shows up as a CircDestroy, since a message sent
        // from the wrong hop won't even be delivered to the extend
        // code's meta-handler.  Instead the unexpected message will cause
        // the circuit to get torn down.
        match error {
            Error::CircDestroy(s) => {
                assert_eq!(s, "Circuit closed while waiting for EXTENDED2");
            }
            x => panic!("got other error: {}", x),
        }
    }

    #[async_test]
    async fn bad_extend_wrongtype() {
        let extended = relaymsg::Extended::new(vec![7; 200]).into();
        let cc = rmsg_to_ccmsg(0, extended);

        let error = bad_extend_test_impl(2.into(), cc).await;
        match error {
            Error::CircProto(s) => {
                assert_eq!(s, "wanted EXTENDED2; got EXTENDED")
            }
            _ => panic!(),
        }
    }

    #[async_test]
    async fn bad_extend_destroy() {
        let cc = ClientCircChanMsg::Destroy(chanmsg::Destroy::new(4.into()));
        let error = bad_extend_test_impl(2.into(), cc).await;
        match error {
            Error::CircDestroy(s) => assert_eq!(s, "Circuit closed while waiting for EXTENDED2"),
            _ => panic!(),
        }
    }

    #[async_test]
    async fn bad_extend_crypto() {
        let extended2 = relaymsg::Extended2::new(vec![99; 256]).into();
        let cc = rmsg_to_ccmsg(0, extended2);
        let error = bad_extend_test_impl(2.into(), cc).await;
        assert!(matches!(error, Error::BadHandshake));
    }

    #[async_test]
    async fn begindir() {
        let (chan, mut rx, _sink) = working_fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;

        let begin_and_send_fut = async move {
            // Here we'll say we've got a circuit, and we want to
            // make a simple BEGINDIR request with it.
            let mut stream = circ.begin_dir_stream().await.unwrap();
            stream.write_all(b"HTTP/1.0 GET /\r\n").await.unwrap();
            stream.flush().await.unwrap();
            let mut buf = [0_u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"HTTP/1.0 404 Not found\r\n");
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(n, 0);
            stream
        };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the begindir cell.
            let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, 128.into()); // hardcoded circid.
            let rmsg = match chmsg {
                ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let (streamid, rmsg) = rmsg.into_streamid_and_msg();
            assert!(matches!(rmsg, RelayMsg::BeginDir));

            // Reply with a Connected cell to indicate success.
            let connected = relaymsg::Connected::new_empty().into();
            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();

            // Now read a DATA cell...
            let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, 128.into());
            let rmsg = match chmsg {
                ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let (streamid_2, rmsg) = rmsg.into_streamid_and_msg();
            assert_eq!(streamid_2, streamid);
            if let RelayMsg::Data(d) = rmsg {
                assert_eq!(d.as_ref(), &b"HTTP/1.0 GET /\r\n"[..]);
            } else {
                panic!();
            }

            // Write another data cell in reply!
            let data = relaymsg::Data::new(b"HTTP/1.0 404 Not found\r\n")
                .unwrap()
                .into();
            sink.send(rmsg_to_ccmsg(streamid, data)).await.unwrap();

            // Send an END cell to say that the conversation is over.
            let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE).into();
            sink.send(rmsg_to_ccmsg(streamid, end)).await.unwrap();

            sink // gotta keep the sink alive, or the reactor will exit.
        };
        let reactor_fut = async move {
            reactor.run_once().await.unwrap(); // AddStream
            reactor.run_once().await.unwrap(); // Connected cell
            reactor.run_once().await.unwrap(); // Data cell
            reactor.run_once().await.unwrap(); // End cell
            reactor
        };

        let (_stream, _, _) = futures::join!(begin_and_send_fut, reply_fut, reactor_fut);
    }

    // Set up a circuit and stream that expects some incoming SENDMEs.
    async fn setup_incoming_sendme_case(
        n_to_send: usize,
    ) -> (
        Arc<ClientCirc>,
        DataStream,
        mpsc::Sender<ClientCircChanMsg>,
        StreamId,
        crate::circuit::reactor::Reactor,
        usize,
    ) {
        let (chan, mut rx, _sink) = working_fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;
        let (snd_done, mut rcv_done) = oneshot::channel::<()>();

        let circ_clone = Arc::clone(&circ);
        let begin_and_send_fut = async move {
            // Take our circuit and make a stream on it.
            let mut stream = circ_clone
                .begin_stream("www.example.com", 443, None)
                .await
                .unwrap();
            let junk = [0_u8; 1024];
            let mut remaining = n_to_send;
            while remaining > 0 {
                let n = std::cmp::min(remaining, junk.len());
                stream.write_all(&junk[..n]).await.unwrap();
                remaining -= n;
            }
            stream.flush().await.unwrap();
            stream
        };

        let receive_fut = async move {
            // Read the begindir cell.
            let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            let rmsg = match chmsg {
                ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let (streamid, rmsg) = rmsg.into_streamid_and_msg();
            assert!(matches!(rmsg, RelayMsg::Begin(_)));
            // Reply with a connected cell...
            let connected = relaymsg::Connected::new_empty().into();
            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();
            // Now read bytes from the stream until we have them all.
            let mut bytes_received = 0_usize;
            let mut cells_received = 0_usize;
            while bytes_received < n_to_send {
                // Read a data cell, and remember how much we got.
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, 128.into());

                let rmsg = match chmsg {
                    ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                    _ => panic!(),
                };
                let (streamid2, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(streamid2, streamid);
                if let RelayMsg::Data(dat) = rmsg {
                    cells_received += 1;
                    bytes_received += dat.as_ref().len();
                } else {
                    panic!()
                }
            }
            snd_done.send(()).unwrap();

            (sink, streamid, cells_received)
        };

        let reactor_fut = async move {
            use futures::FutureExt;
            loop {
                futures::select! {
                    r = reactor.run_once().fuse() => r.unwrap(),
                    _ = rcv_done => break,
                }
            }
            reactor
        };

        let (stream, (sink, streamid, cells_received), reactor) =
            futures::join!(begin_and_send_fut, receive_fut, reactor_fut);

        (circ, stream, sink, streamid, reactor, cells_received)
    }

    #[async_test]
    async fn accept_valid_sendme() {
        let (circ, _stream, mut sink, streamid, mut reactor, cells_received) =
            setup_incoming_sendme_case(300 * 498 + 3).await;

        assert_eq!(cells_received, 301);

        // Make sure that the circuit is indeed expecting the right sendmes
        {
            let mut c = circ.c.lock().await;
            let hop = c.hop_mut(2.into()).unwrap();
            let (window, tags) = hop.sendwindow.window_and_expected_tags().await;
            assert_eq!(window, 1000 - 301);
            assert_eq!(tags.len(), 3);
            // 100
            assert_eq!(tags[0], hex!("6400000000000000000000000000000000000000"));
            // 200
            assert_eq!(tags[1], hex!("c800000000000000000000000000000000000000"));
            // 300
            assert_eq!(tags[2], hex!("2c01000000000000000000000000000000000000"));
        }

        let reply_with_sendme_fut = async move {
            // make and send a circuit-level sendme.
            let c_sendme =
                relaymsg::Sendme::new_tag(hex!("6400000000000000000000000000000000000000")).into();
            sink.send(rmsg_to_ccmsg(0_u16, c_sendme)).await.unwrap();

            // Make and send a stream-level sendme.
            let s_sendme = relaymsg::Sendme::new_empty().into();
            sink.send(rmsg_to_ccmsg(streamid, s_sendme)).await.unwrap();

            sink
        };

        let reactor_fut = async move {
            reactor.run_once().await.unwrap(); // circuit sendme
            reactor.run_once().await.unwrap(); // stream sendme
            reactor
        };

        let (_, _) = futures::join!(reply_with_sendme_fut, reactor_fut);

        // Now make sure that the circuit is still happy, and its
        // window is updated.
        {
            let mut c = circ.c.lock().await;
            let hop = c.hop_mut(2.into()).unwrap();
            let (window, _tags) = hop.sendwindow.window_and_expected_tags().await;
            assert_eq!(window, 1000 - 201);
        }
    }

    #[async_test]
    async fn invalid_circ_sendme() {
        // Same setup as accept_valid_sendme() test above but try giving
        // a sendme with the wrong tag.

        let (_circ, _stream, mut sink, _streamid, mut reactor, _cells_received) =
            setup_incoming_sendme_case(300 * 498 + 3).await;

        let reply_with_sendme_fut = async move {
            // make and send a circuit-level sendme with a bad tag.
            let c_sendme =
                relaymsg::Sendme::new_tag(hex!("FFFF0000000000000000000000000000000000FF")).into();
            sink.send(rmsg_to_ccmsg(0_u16, c_sendme)).await.unwrap();
            sink
        };

        let reactor_fut = async move {
            use crate::util::err::ReactorError;
            let r = reactor.run_once().await;
            match r {
                Err(ReactorError::Err(Error::CircProto(m))) => {
                    assert_eq!(m, "bad auth tag on circuit sendme")
                }
                _ => panic!(),
            }
            reactor
        };

        let (_, _) = futures::join!(reply_with_sendme_fut, reactor_fut);

        // TODO: check that the circuit is shut down too
    }

    #[test]
    fn basic_params() {
        use super::CircParameters;
        let mut p = CircParameters::default();
        assert_eq!(p.initial_send_window(), 1000);
        assert!(p.extend_by_ed25519_id());

        assert!(p.set_initial_send_window(500).is_ok());
        p.set_extend_by_ed25519_id(false);
        assert_eq!(p.initial_send_window(), 500);
        assert!(!p.extend_by_ed25519_id());

        assert!(p.set_initial_send_window(9000).is_err());
        assert_eq!(p.initial_send_window(), 500);
    }
}
