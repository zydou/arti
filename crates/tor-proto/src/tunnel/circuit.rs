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
//! call its [crate::channel::Channel::new_tunnel] method.  This yields
//! a [PendingClientTunnel] object that won't become live until you call
//! one of the methods
//! (typically [`PendingClientTunnel::create_firsthop`])
//! that extends it to its first hop.  After you've
//! done that, you can call [`ClientCirc::extend`] on the tunnel to
//! build it into a multi-hop tunnel.  Finally, you can use
//! [ClientTunnel::begin_stream] to get a Stream object that can be used
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

pub(crate) mod celltypes;
pub(crate) mod halfcirc;

#[cfg(feature = "hs-common")]
pub mod handshake;
#[cfg(not(feature = "hs-common"))]
pub(crate) mod handshake;

pub(super) mod path;
pub(crate) mod unique_id;

use crate::channel::Channel;
use crate::circuit::handshake::RelayCryptLayerProtocol;
use crate::congestion::params::CongestionControlParams;
use crate::crypto::cell::HopNum;
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::memquota::CircuitAccount;
use crate::tunnel::circuit::celltypes::*;
use crate::tunnel::reactor::{CircuitHandshake, CtrlCmd, CtrlMsg, Reactor};
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use cfg_if::cfg_if;
use educe::Educe;
use path::HopDetail;
use tor_cell::chancell::CircId;
use tor_cell::relaycell::RelayCellFormat;
use tor_error::{bad_api_usage, internal, into_internal};
use tor_linkspec::{CircTarget, LinkSpecType, OwnedChanTarget, RelayIdType};
use tor_protover::named;
use tor_rtcompat::DynTimeProvider;

pub use crate::crypto::binding::CircuitBinding;
pub use crate::memquota::StreamAccount;
pub use crate::tunnel::circuit::unique_id::UniqId;

use super::{ClientTunnel, TargetHop};

use futures::channel::mpsc;
use oneshot_fused_workaround as oneshot;

use futures::FutureExt as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tor_memquota::mq_queue::{self, MpscSpec};

use crate::crypto::handshake::ntor::NtorPublicKey;

pub use path::{Path, PathEntry};

/// The size of the buffer for communication between `ClientCirc` and its reactor.
pub const CIRCUIT_BUFFER_SIZE: usize = 128;

pub use crate::tunnel::reactor::syncview::ClientCircSyncView;

/// MPSC queue relating to a stream (either inbound or outbound), sender
pub(crate) type StreamMpscSender<T> = mq_queue::Sender<T, MpscSpec>;
/// MPSC queue relating to a stream (either inbound or outbound), receiver
pub(crate) type StreamMpscReceiver<T> = mq_queue::Receiver<T, MpscSpec>;

/// MPSC queue for inbound data on its way from channel to circuit, sender
pub(crate) type CircuitRxSender = mq_queue::Sender<ClientCircChanMsg, MpscSpec>;
/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<ClientCircChanMsg, MpscSpec>;

#[derive(Debug)]
/// A circuit that we have constructed over the Tor network.
///
/// # Circuit life cycle
///
/// `ClientCirc`s are created in an initially unusable state using [`Channel::new_tunnel`],
/// which returns a [`PendingClientTunnel`].  To get a real (one-hop) tunnel from
/// one of these, you invoke one of its `create_firsthop` methods (typically
/// [`create_firsthop_fast()`](PendingClientTunnel::create_firsthop_fast) or
/// [`create_firsthop()`](PendingClientTunnel::create_firsthop)).
/// Then, to add more hops to the circuit, you can call
/// [`extend()`](ClientCirc::extend) on it.
///
/// For higher-level APIs, see the `tor-circmgr` crate: the ones here in
/// `tor-proto` are probably not what you need.
///
/// After a circuit is created, it will persist until it is closed in one of
/// five ways:
///    1. A remote error occurs.
///    2. Some hop on the circuit sends a `DESTROY` message to tear down the
///       circuit.
///    3. The circuit's channel is closed.
///    4. Someone calls [`ClientTunnel::terminate`] on the tunnel owning the circuit.
///    5. The last reference to the `ClientCirc` is dropped. (Note that every stream
///       on a `ClientCirc` keeps a reference to it, which will in turn keep the
///       circuit from closing until all those streams have gone away.)
///
/// Note that in cases 1-4 the [`ClientCirc`] object itself will still exist: it
/// will just be unusable for most purposes.  Most operations on it will fail
/// with an error.
//
// Effectively, this struct contains two Arcs: one for `path` and one for
// `control` (which surely has something Arc-like in it).  We cannot unify
// these by putting a single Arc around the whole struct, and passing
// an Arc strong reference to the `Reactor`, because then `control` would
// not be dropped when the last user of the circuit goes away.  We could
// make the reactor have a weak reference but weak references are more
// expensive to dereference.
//
// Because of the above, cloning this struct is always going to involve
// two atomic refcount changes/checks.  Wrapping it in another Arc would
// be overkill.
//
pub struct ClientCirc {
    /// Mutable state shared with the `Reactor`.
    pub(super) mutable: Arc<TunnelMutableState>,
    /// A unique identifier for this circuit.
    unique_id: UniqId,
    /// Channel to send control messages to the reactor.
    pub(super) control: mpsc::UnboundedSender<CtrlMsg>,
    /// Channel to send commands to the reactor.
    pub(super) command: mpsc::UnboundedSender<CtrlCmd>,
    /// A future that resolves to Cancelled once the reactor is shut down,
    /// meaning that the circuit is closed.
    #[cfg_attr(not(feature = "experimental-api"), allow(dead_code))]
    reactor_closed_rx: futures::future::Shared<oneshot::Receiver<void::Void>>,
    /// For testing purposes: the CircId, for use in peek_circid().
    #[cfg(test)]
    circid: CircId,
    /// Memory quota account
    pub(super) memquota: CircuitAccount,
    /// Time provider
    pub(super) time_provider: DynTimeProvider,
    /// Indicate if this reactor is a multi path or not. This is flagged at the very first
    /// LinkCircuit seen and never changed after.
    ///
    /// We can't just look at the number of legs because a multi path tunnel could have 1 leg only
    /// because the other(s) have collapsed.
    ///
    /// This is very important because it allows to make a quick efficient safety check by the
    /// circmgr higher level tunnel type without locking the mutable state or using the command
    /// channel.
    pub(super) is_multi_path: bool,
}

/// The mutable state of a tunnel, shared between [`ClientCirc`] and [`Reactor`].
///
/// NOTE(gabi): this mutex-inside-a-mutex might look suspicious,
/// but it is currently the best option we have for sharing
/// the circuit state with `ClientCirc` (and soon, with `ClientTunnel`).
/// In practice, these mutexes won't be accessed very often
/// (they're accessed for writing when a circuit is extended,
/// and for reading by the various `ClientCirc` APIs),
/// so they shouldn't really impact performance.
///
/// Alternatively, the circuit state information could be shared
/// outside the reactor through a channel (passed to the reactor via a `CtrlCmd`),
/// but in #1840 @opara notes that involves making the `ClientCirc` accessors
/// (`ClientCirc::path`, `ClientCirc::binding_key`, etc.)
/// asynchronous, which will significantly complicate their callsites,
/// which would in turn need to be made async too.
///
/// We should revisit this decision at some point, and decide whether an async API
/// would be preferable.
#[derive(Debug, Default)]
pub(super) struct TunnelMutableState(Mutex<HashMap<UniqId, Arc<MutableState>>>);

impl TunnelMutableState {
    /// Add the [`MutableState`] of a circuit.
    pub(super) fn insert(&self, unique_id: UniqId, mutable: Arc<MutableState>) {
        #[allow(unused)] // unused in non-debug builds
        let state = self
            .0
            .lock()
            .expect("lock poisoned")
            .insert(unique_id, mutable);

        debug_assert!(state.is_none());
    }

    /// Remove the [`MutableState`] of a circuit.
    pub(super) fn remove(&self, unique_id: UniqId) {
        #[allow(unused)] // unused in non-debug builds
        let state = self.0.lock().expect("lock poisoned").remove(&unique_id);

        debug_assert!(state.is_some());
    }

    /// Return a [`Path`] object describing all the circuits in this tunnel.
    fn all_paths(&self) -> Vec<Arc<Path>> {
        let lock = self.0.lock().expect("lock poisoned");
        lock.values().map(|mutable| mutable.path()).collect()
    }

    /// Return a list of [`Path`] objects describing the only circuit in this tunnel.
    ///
    /// Returns an error if the tunnel has more than one tunnel.
    fn single_path(&self) -> Result<Arc<Path>> {
        use itertools::Itertools as _;

        self.all_paths().into_iter().exactly_one().map_err(|_| {
            bad_api_usage!("requested the single path of a multi-path tunnel?!").into()
        })
    }

    /// Return a description of the first hop of this circuit.
    ///
    /// Returns an error if a circuit with the specified [`UniqId`] doesn't exist.
    /// Returns `Ok(None)` if the specified circuit doesn't have any hops.
    fn first_hop(&self, unique_id: UniqId) -> Result<Option<OwnedChanTarget>> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        let first_hop = mutable.first_hop().map(|first_hop| match first_hop {
            path::HopDetail::Relay(r) => r,
            #[cfg(feature = "hs-common")]
            path::HopDetail::Virtual => {
                panic!("somehow made a circuit with a virtual first hop.")
            }
        });

        Ok(first_hop)
    }

    /// Return the [`HopNum`] of the last hop of the specified circuit.
    ///
    /// Returns an error if a circuit with the specified [`UniqId`] doesn't exist.
    ///
    /// See [`MutableState::last_hop_num`].
    pub(super) fn last_hop_num(&self, unique_id: UniqId) -> Result<Option<HopNum>> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        Ok(mutable.last_hop_num())
    }

    /// Return the number of hops in the specified circuit.
    ///
    /// See [`MutableState::n_hops`].
    fn n_hops(&self, unique_id: UniqId) -> Result<usize> {
        let lock = self.0.lock().expect("lock poisoned");
        let mutable = lock
            .get(&unique_id)
            .ok_or_else(|| bad_api_usage!("no circuit with unique ID {unique_id}"))?;

        Ok(mutable.n_hops())
    }
}

/// The mutable state of a circuit.
#[derive(Educe, Default)]
#[educe(Debug)]
pub(super) struct MutableState(Mutex<CircuitState>);

impl MutableState {
    /// Add a hop to the path of this circuit.
    pub(super) fn add_hop(&self, peer_id: HopDetail, binding: Option<CircuitBinding>) {
        let mut mutable = self.0.lock().expect("poisoned lock");
        Arc::make_mut(&mut mutable.path).push_hop(peer_id);
        mutable.binding.push(binding);
    }

    /// Get a copy of the circuit's current [`path::Path`].
    pub(super) fn path(&self) -> Arc<path::Path> {
        let mutable = self.0.lock().expect("poisoned lock");
        Arc::clone(&mutable.path)
    }

    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    pub(super) fn binding_key(&self, hop: HopNum) -> Option<CircuitBinding> {
        let mutable = self.0.lock().expect("poisoned lock");

        mutable.binding.get::<usize>(hop.into()).cloned().flatten()
        // NOTE: I'm not thrilled to have to copy this information, but we use
        // it very rarely, so it's not _that_ bad IMO.
    }

    /// Return a description of the first hop of this circuit.
    fn first_hop(&self) -> Option<HopDetail> {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.first_hop()
    }

    /// Return the [`HopNum`] of the last hop of this circuit.
    ///
    /// NOTE: This function will return the [`HopNum`] of the hop
    /// that is _currently_ the last. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn last_hop_num(&self) -> Option<HopNum> {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.last_hop_num()
    }

    /// Return the number of hops in this circuit.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the circuit. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    fn n_hops(&self) -> usize {
        let mutable = self.0.lock().expect("poisoned lock");
        mutable.path.n_hops()
    }
}

/// The shared state of a circuit.
#[derive(Educe, Default)]
#[educe(Debug)]
pub(super) struct CircuitState {
    /// Information about this circuit's path.
    ///
    /// This is stored in an Arc so that we can cheaply give a copy of it to
    /// client code; when we need to add a hop (which is less frequent) we use
    /// [`Arc::make_mut()`].
    path: Arc<path::Path>,

    /// Circuit binding keys [q.v.][`CircuitBinding`] information for each hop
    /// in the circuit's path.
    ///
    /// NOTE: Right now, there is a `CircuitBinding` for every hop.  There's a
    /// fair chance that this will change in the future, and I don't want other
    /// code to assume that a `CircuitBinding` _must_ exist, so I'm making this
    /// an `Option`.
    #[educe(Debug(ignore))]
    binding: Vec<Option<CircuitBinding>>,
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call `create_firsthop_fast()` or `create_firsthop()`
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientTunnel {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: ClientCirc,
}

/// Description of the network's current rules for building circuits.
///
/// This type describes rules derived from the consensus,
/// and possibly amended by our own configuration.
///
/// Typically, this type created once for an entire circuit,
/// and any special per-hop information is derived
/// from each hop as a CircTarget.
/// Note however that callers _may_ provide different `CircParameters`
/// for different hops within a circuit if they have some reason to do so,
/// so we do not enforce that every hop in a circuit has the same `CircParameters`.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    pub extend_by_ed25519_id: bool,
    /// Congestion control parameters for this circuit.
    pub ccontrol: CongestionControlParams,

    /// Maximum number of permitted incoming relay cells for each hop.
    ///
    /// If we would receive more relay cells than this from a single hop,
    /// we close the circuit with [`ExcessInboundCells`](Error::ExcessInboundCells).
    ///
    /// If this value is None, then there is no limit to the number of inbound cells.
    ///
    /// Known limitation: If this value if `u32::MAX`,
    /// then a limit of `u32::MAX - 1` is enforced.
    pub n_incoming_cells_permitted: Option<u32>,

    /// Maximum number of permitted outgoing relay cells for each hop.
    ///
    /// If we would try to send more relay cells than this from a single hop,
    /// we close the circuit with [`ExcessOutboundCells`](Error::ExcessOutboundCells).
    /// It is the circuit-user's responsibility to make sure that this does not happen.
    ///
    /// This setting is used to ensure that we do not violate a limit
    /// imposed by `n_incoming_cells_permitted`
    /// on the other side of a circuit.
    ///
    /// If this value is None, then there is no limit to the number of outbound cells.
    ///
    /// Known limitation: If this value if `u32::MAX`,
    /// then a limit of `u32::MAX - 1` is enforced.
    pub n_outgoing_cells_permitted: Option<u32>,
}

/// Type of negotiation that we'll be performing as we establish a hop.
///
/// Determines what flavor of extensions we can send and receive, which in turn
/// limits the hop settings we can negotiate.
///
// TODO-CGO: This is likely to be refactored when we finally add support for
// HsV3+CGO, which will require refactoring
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum HopNegotiationType {
    /// We're using a handshake in which extension-based negotiation cannot occur.
    None,
    /// We're using the HsV3-ntor handshake, in which the client can send extensions,
    /// but the server cannot.
    ///
    /// As a special case, the default relay encryption protocol is the hsv3
    /// variant of Tor1.
    //
    // We would call this "HalfDuplex" or something, but we do not expect to add
    // any more handshakes of this type.
    HsV3,
    /// We're using a handshake in which both client and relay can send extensions.
    Full,
}

/// The settings we use for single hop of a circuit.
///
/// Unlike [`CircParameters`], this type is crate-internal.
/// We construct it based on our settings from the circuit,
/// and from the hop's actual capabilities.
/// Then, we negotiate with the hop as part of circuit
/// creation/extension to determine the actual settings that will be in use.
/// Finally, we use those settings to construct the negotiated circuit hop.
//
// TODO: Relays should probably derive an instance of this type too, as
// part of the circuit creation handshake.
#[derive(Clone, Debug)]
pub(super) struct HopSettings {
    /// The negotiated congestion control settings for this hop .
    pub(super) ccontrol: CongestionControlParams,

    /// Maximum number of permitted incoming relay cells for this hop.
    pub(super) n_incoming_cells_permitted: Option<u32>,

    /// Maximum number of permitted outgoing relay cells for this hop.
    pub(super) n_outgoing_cells_permitted: Option<u32>,

    /// The relay cell encryption algorithm and cell format for this hop.
    relay_crypt_protocol: RelayCryptLayerProtocol,
}

impl HopSettings {
    /// Construct a new `HopSettings` based on `params` (a set of circuit parameters)
    /// and `caps` (a set of protocol capabilities for a circuit target).
    ///
    /// The resulting settings will represent what the client would prefer to negotiate
    /// (determined by `params`),
    /// as modified by what the target relay is believed to support (represented by `caps`).
    ///
    /// This represents the `HopSettings` in a pre-negotiation state:
    /// the circuit negotiation process will modify it.
    #[allow(clippy::unnecessary_wraps)] // likely to become fallible in the future.
    pub(super) fn from_params_and_caps(
        hoptype: HopNegotiationType,
        params: &CircParameters,
        caps: &tor_protover::Protocols,
    ) -> Result<Self> {
        let mut ccontrol = params.ccontrol.clone();
        match ccontrol.alg() {
            crate::ccparams::Algorithm::FixedWindow(_) => {}
            crate::ccparams::Algorithm::Vegas(_) => {
                // If the target doesn't support FLOWCTRL_CC, we can't use Vegas.
                if !caps.supports_named_subver(named::FLOWCTRL_CC) {
                    ccontrol.use_fallback_alg();
                }
            }
        };
        if hoptype == HopNegotiationType::None {
            ccontrol.use_fallback_alg();
        } else if hoptype == HopNegotiationType::HsV3 {
            // TODO #2037, TODO-CGO: We need a way to send congestion control extensions
            // in this case too.  But since we aren't sending them, we
            // should use the fallback algorithm.
            ccontrol.use_fallback_alg();
        }
        let ccontrol = ccontrol; // drop mut

        // Negotiate CGO if it is supported, if CC is also supported,
        // and if CGO is available on this relay.
        let relay_crypt_protocol = match hoptype {
            HopNegotiationType::None => RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0),
            HopNegotiationType::HsV3 => {
                // TODO-CGO: Support CGO when available.
                cfg_if! {
                    if #[cfg(feature = "hs-common")] {
                        RelayCryptLayerProtocol::HsV3(RelayCellFormat::V0)
                    } else {
                        return Err(
                            internal!("Unexpectedly tried to negotiate HsV3 without support!").into(),
                        );
                    }
                }
            }
            HopNegotiationType::Full => {
                cfg_if! {
                    if #[cfg(all(feature = "flowctl-cc", feature = "counter-galois-onion"))] {
                        #[allow(clippy::overly_complex_bool_expr)]
                        if  ccontrol.alg().compatible_with_cgo()
                            && caps.supports_named_subver(named::RELAY_NEGOTIATE_SUBPROTO)
                            && caps.supports_named_subver(named::RELAY_CRYPT_CGO)
                            && false // TODO CGO REMOVE once we are ready to enable CGO.
                            // (We aren't enabling it yet because CC is not yet negotiable.)
                        {
                            RelayCryptLayerProtocol::Cgo
                        } else {
                            RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                        }
                    } else {
                        RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                    }
                }
            }
        };

        Ok(Self {
            ccontrol,
            relay_crypt_protocol,
            n_incoming_cells_permitted: params.n_incoming_cells_permitted,
            n_outgoing_cells_permitted: params.n_outgoing_cells_permitted,
        })
    }

    /// Return the negotiated relay crypto protocol.
    pub(super) fn relay_crypt_protocol(&self) -> RelayCryptLayerProtocol {
        // TODO CGO: Remove this once we are ready to enable CGO.
        // (We aren't enabling it yet because CC is not yet negotiable.)
        #[cfg(feature = "counter-galois-onion")]
        assert!(
            !matches!(self.relay_crypt_protocol, RelayCryptLayerProtocol::Cgo),
            "Somehow negotiated CGO, but CGO is not yet supported!!"
        );
        self.relay_crypt_protocol
    }
}

#[cfg(test)]
impl std::default::Default for CircParameters {
    fn default() -> Self {
        Self {
            extend_by_ed25519_id: true,
            ccontrol: crate::congestion::test_utils::params::build_cc_fixed_params(),
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}

impl CircParameters {
    /// Constructor
    pub fn new(extend_by_ed25519_id: bool, ccontrol: CongestionControlParams) -> Self {
        Self {
            extend_by_ed25519_id,
            ccontrol,
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}

impl ClientCirc {
    /// Convert this `ClientCirc` into a single circuit [`ClientTunnel`].
    pub fn into_tunnel(self) -> Result<ClientTunnel> {
        self.try_into()
    }

    /// Return a description of the first hop of this circuit.
    ///
    /// # Panics
    ///
    /// Panics if there is no first hop.  (This should be impossible outside of
    /// the tor-proto crate, but within the crate it's possible to have a
    /// circuit with no hops.)
    pub fn first_hop(&self) -> Result<OwnedChanTarget> {
        Ok(self
            .mutable
            .first_hop(self.unique_id)
            .map_err(|_| Error::CircuitClosed)?
            .expect("called first_hop on an un-constructed circuit"))
    }

    /// Return a description of the last hop of the tunnel.
    ///
    /// Return None if the last hop is virtual.
    ///
    /// # Panics
    ///
    /// Panics if there is no last hop.  (This should be impossible outside of
    /// the tor-proto crate, but within the crate it's possible to have a
    /// circuit with no hops.)
    pub fn last_hop_info(&self) -> Result<Option<OwnedChanTarget>> {
        let all_paths = self.all_paths();
        let path = all_paths.first().ok_or_else(|| {
            tor_error::bad_api_usage!("Called last_hop_info an an un-constructed tunnel")
        })?;
        Ok(path
            .hops()
            .last()
            .expect("Called last_hop an an un-constructed circuit")
            .as_chan_target()
            .map(OwnedChanTarget::from_chan_target))
    }

    /// Return the [`HopNum`] of the last hop of this circuit.
    ///
    /// Returns an error if there is no last hop.  (This should be impossible outside of the
    /// tor-proto crate, but within the crate it's possible to have a circuit with no hops.)
    ///
    /// NOTE: This function will return the [`HopNum`] of the hop
    /// that is _currently_ the last. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    pub fn last_hop_num(&self) -> Result<HopNum> {
        Ok(self
            .mutable
            .last_hop_num(self.unique_id)?
            .ok_or_else(|| internal!("no last hop index"))?)
    }

    /// Return a [`TargetHop`] representing precisely the last hop of the circuit as in set as a
    /// HopLocation with its id and hop number.
    ///
    /// Return an error if there is no last hop.
    pub fn last_hop(&self) -> Result<TargetHop> {
        let hop_num = self
            .mutable
            .last_hop_num(self.unique_id)?
            .ok_or_else(|| bad_api_usage!("no last hop"))?;
        Ok((self.unique_id, hop_num).into())
    }

    /// Return a list of [`Path`] objects describing all the circuits in this tunnel.
    ///
    /// Note that these `Path`s are not automatically updated if the underlying
    /// circuits are extended.
    pub fn all_paths(&self) -> Vec<Arc<Path>> {
        self.mutable.all_paths()
    }

    /// Return a list of [`Path`] objects describing the only circuit in this tunnel.
    ///
    /// Returns an error if the tunnel has more than one tunnel.
    pub fn single_path(&self) -> Result<Arc<Path>> {
        self.mutable.single_path()
    }

    /// Get the clock skew claimed by the first hop of the circuit.
    ///
    /// See [`Channel::clock_skew()`].
    pub async fn first_hop_clock_skew(&self) -> Result<ClockSkew> {
        let (tx, rx) = oneshot::channel();

        self.control
            .unbounded_send(CtrlMsg::FirstHopClockSkew { answer: tx })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx.await.map_err(|_| Error::CircuitClosed)??)
    }

    /// Return a reference to this circuit's memory quota account
    pub fn mq_account(&self) -> &CircuitAccount {
        &self.memquota
    }

    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    ///
    /// See [`CircuitBinding`] for more information on how this is used.
    ///
    /// Return None if we have no circuit binding information for the hop, or if
    /// the hop does not exist.
    #[cfg(feature = "hs-service")]
    pub async fn binding_key(&self, hop: TargetHop) -> Result<Option<CircuitBinding>> {
        let (sender, receiver) = oneshot::channel();
        let msg = CtrlCmd::GetBindingKey { hop, done: sender };
        self.command
            .unbounded_send(msg)
            .map_err(|_| Error::CircuitClosed)?;

        receiver.await.map_err(|_| Error::CircuitClosed)?
    }

    /// Extend the circuit, via the most appropriate circuit extension handshake,
    /// to the chosen `target` hop.
    pub async fn extend<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        // For now we use the simplest decision-making mechanism:
        // we use ntor_v3 whenever it is present; and otherwise we use ntor.
        //
        // This behavior is slightly different from C tor, which uses ntor v3
        // only whenever it want to send any extension in the circuit message.
        // But thanks to congestion control (named::FLOWCTRL_CC), we'll _always_
        // want to use an extension if we can, and so it doesn't make too much
        // sense to detect the case where we have no extensions.
        //
        // (As of April 2025, RELAY_NTORV3 is not yet listed as Required for relays
        // on the tor network, and so we cannot simply assume that everybody has it.)
        if target
            .protovers()
            .supports_named_subver(named::RELAY_NTORV3)
        {
            self.extend_ntor_v3(target, params).await
        } else {
            self.extend_ntor(target, params).await
        }
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    pub async fn extend_ntor<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        let key = NtorPublicKey {
            id: *target
                .rsa_identity()
                .ok_or(Error::MissingId(RelayIdType::Rsa))?,
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target
            .linkspecs()
            .map_err(into_internal!("Could not encode linkspecs for extend_ntor"))?;
        if !params.extend_by_ed25519_id {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        let settings = HopSettings::from_params_and_caps(
            HopNegotiationType::None,
            &params,
            target.protovers(),
        )?;
        self.control
            .unbounded_send(CtrlMsg::ExtendNtor {
                peer_id,
                public_key: key,
                linkspecs,
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.
    pub async fn extend_ntor_v3<Tg>(&self, target: &Tg, params: CircParameters) -> Result<()>
    where
        Tg: CircTarget,
    {
        let key = NtorV3PublicKey {
            id: *target
                .ed_identity()
                .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target
            .linkspecs()
            .map_err(into_internal!("Could not encode linkspecs for extend_ntor"))?;
        if !params.extend_by_ed25519_id {
            linkspecs.retain(|ls| ls.lstype() != LinkSpecType::ED25519ID);
        }

        let (tx, rx) = oneshot::channel();

        let peer_id = OwnedChanTarget::from_chan_target(target);
        let settings = HopSettings::from_params_and_caps(
            HopNegotiationType::Full,
            &params,
            target.protovers(),
        )?;
        self.control
            .unbounded_send(CtrlMsg::ExtendNtorV3 {
                peer_id,
                public_key: key,
                linkspecs,
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        Ok(())
    }

    /// Extend this circuit by a single, "virtual" hop.
    ///
    /// A virtual hop is one for which we do not add an actual network connection
    /// between separate hosts (such as Relays).  We only add a layer of
    /// cryptography.
    ///
    /// This is used to implement onion services: the client and the service
    /// both build a circuit to a single rendezvous point, and tell the
    /// rendezvous point to relay traffic between their two circuits.  Having
    /// completed a [`handshake`] out of band[^1], the parties each extend their
    /// circuits by a single "virtual" encryption hop that represents their
    /// shared cryptographic context.
    ///
    /// Once a circuit has been extended in this way, it is an error to try to
    /// extend it in any other way.
    ///
    /// [^1]: Technically, the handshake is only _mostly_ out of band: the
    ///     client sends their half of the handshake in an ` message, and the
    ///     service's response is inline in its `RENDEZVOUS2` message.
    //
    // TODO hs: let's try to enforce the "you can't extend a circuit again once
    // it has been extended this way" property.  We could do that with internal
    // state, or some kind of a type state pattern.
    #[cfg(feature = "hs-common")]
    pub async fn extend_virtual(
        &self,
        protocol: handshake::RelayProtocol,
        role: handshake::HandshakeRole,
        seed: impl handshake::KeyGenerator,
        params: &CircParameters,
        capabilities: &tor_protover::Protocols,
    ) -> Result<()> {
        use self::handshake::BoxedClientLayer;

        // TODO CGO: Possibly refactor this match into a separate method when we revisit this.
        let negotiation_type = match protocol {
            handshake::RelayProtocol::HsV3 => HopNegotiationType::HsV3,
        };
        let protocol = handshake::RelayCryptLayerProtocol::from(protocol);

        let BoxedClientLayer { fwd, back, binding } =
            protocol.construct_client_layers(role, seed)?;

        let settings = HopSettings::from_params_and_caps(negotiation_type, params, capabilities)?;
        let (tx, rx) = oneshot::channel();
        let message = CtrlCmd::ExtendVirtual {
            cell_crypto: (fwd, back, binding),
            settings,
            done: tx,
        };

        self.command
            .unbounded_send(message)
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)?
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.control.is_closed()
    }

    /// Return a process-unique identifier for this circuit.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }

    /// Return the number of hops in this circuit.
    ///
    /// NOTE: This function will currently return only the number of hops
    /// _currently_ in the circuit. If there is an extend operation in progress,
    /// the currently pending hop may or may not be counted, depending on whether
    /// the extend operation finishes before this call is done.
    pub fn n_hops(&self) -> Result<usize> {
        self.mutable
            .n_hops(self.unique_id)
            .map_err(|_| Error::CircuitClosed)
    }

    /// Return a future that will resolve once this circuit has closed.
    ///
    /// Note that this method does not itself cause the circuit to shut down.
    ///
    /// TODO: Perhaps this should return some kind of status indication instead
    /// of just ()
    pub fn wait_for_close(&self) -> impl futures::Future<Output = ()> + Send + Sync + 'static {
        self.reactor_closed_rx.clone().map(|_| ())
    }
}

impl PendingClientTunnel {
    /// Instantiate a new circuit object: used from Channel::new_tunnel().
    ///
    /// Does not send a CREATE* cell on its own.
    ///
    ///
    pub(crate) fn new(
        id: CircId,
        channel: Arc<Channel>,
        createdreceiver: oneshot::Receiver<CreateResponse>,
        input: CircuitRxReceiver,
        unique_id: UniqId,
        runtime: DynTimeProvider,
        memquota: CircuitAccount,
    ) -> (PendingClientTunnel, crate::tunnel::reactor::Reactor) {
        let time_provider = channel.time_provider().clone();
        let (reactor, control_tx, command_tx, reactor_closed_rx, mutable) =
            Reactor::new(channel, id, unique_id, input, runtime, memquota.clone());

        let circuit = ClientCirc {
            mutable,
            unique_id,
            control: control_tx,
            command: command_tx,
            reactor_closed_rx: reactor_closed_rx.shared(),
            #[cfg(test)]
            circid: id,
            memquota,
            time_provider,
            is_multi_path: false,
        };

        let pending = PendingClientTunnel {
            recvcreated: createdreceiver,
            circ: circuit,
        };
        (pending, reactor)
    }

    /// Extract the process-unique identifier for this pending circuit.
    pub fn peek_unique_id(&self) -> UniqId {
        self.circ.unique_id
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast(self, params: CircParameters) -> Result<ClientTunnel> {
        // We no nothing about this relay, so we assume it supports no protocol capabilities at all.
        //
        // TODO: If we had a consensus, we could assume it supported all required-relay-protocols.
        let protocols = tor_protover::Protocols::new();
        let settings =
            HopSettings::from_params_and_caps(HopNegotiationType::None, &params, &protocols)?;
        let (tx, rx) = oneshot::channel();
        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::CreateFast,
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        self.circ.into_tunnel()
    }

    /// Use the most appropriate handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<ClientTunnel>
    where
        Tg: tor_linkspec::CircTarget,
    {
        // (See note in ClientCirc::extend.)
        if target
            .protovers()
            .supports_named_subver(named::RELAY_NTORV3)
        {
            self.create_firsthop_ntor_v3(target, params).await
        } else {
            self.create_firsthop_ntor(target, params).await
        }
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop_ntor<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<ClientTunnel>
    where
        Tg: tor_linkspec::CircTarget,
    {
        let (tx, rx) = oneshot::channel();
        let settings = HopSettings::from_params_and_caps(
            HopNegotiationType::None,
            &params,
            target.protovers(),
        )?;

        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::Ntor {
                    public_key: NtorPublicKey {
                        id: *target
                            .rsa_identity()
                            .ok_or(Error::MissingId(RelayIdType::Rsa))?,
                        pk: *target.ntor_onion_key(),
                    },
                    ed_identity: *target
                        .ed_identity()
                        .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
                },
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        self.circ.into_tunnel()
    }

    /// Use the ntor_v3 handshake to connect to the first hop of this circuit.
    ///
    /// Assumes that the target supports ntor_v3. The caller should verify
    /// this before calling this function, e.g. by validating that the target
    /// has advertised ["Relay=4"](https://spec.torproject.org/tor-spec/subprotocol-versioning.html#relay).
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop_ntor_v3<Tg>(
        self,
        target: &Tg,
        params: CircParameters,
    ) -> Result<ClientTunnel>
    where
        Tg: tor_linkspec::CircTarget,
    {
        let settings = HopSettings::from_params_and_caps(
            HopNegotiationType::Full,
            &params,
            target.protovers(),
        )?;
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::Create {
                recv_created: self.recvcreated,
                handshake: CircuitHandshake::NtorV3 {
                    public_key: NtorV3PublicKey {
                        id: *target
                            .ed_identity()
                            .ok_or(Error::MissingId(RelayIdType::Ed25519))?,
                        pk: *target.ntor_onion_key(),
                    },
                },
                settings,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        rx.await.map_err(|_| Error::CircuitClosed)??;

        self.circ.into_tunnel()
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::channel::OpenChanCellS2C;
    use crate::channel::{test::new_reactor, CodecError};
    use crate::congestion::test_utils::params::build_cc_vegas_params;
    use crate::crypto::cell::RelayCellBody;
    use crate::crypto::handshake::ntor_v3::NtorV3Server;
    use crate::memquota::SpecificAccount as _;
    use crate::stream::DataStream;
    #[cfg(feature = "hs-service")]
    use crate::stream::IncomingStreamRequestFilter;
    use chanmsg::{AnyChanMsg, Created2, CreatedFast};
    use futures::channel::mpsc::{Receiver, Sender};
    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use futures::task::SpawnExt;
    use hex_literal::hex;
    use std::collections::{HashMap, VecDeque};
    use std::fmt::Debug;
    use std::time::Duration;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_cell::chancell::{msg as chanmsg, AnyChanCell, BoxedCellBody, ChanCell, ChanCmd};
    use tor_cell::relaycell::extend::{self as extend_ext, CircRequestExt, CircResponseExt};
    use tor_cell::relaycell::msg::SendmeTag;
    use tor_cell::relaycell::{
        msg as relaymsg, msg::AnyRelayMsg, AnyRelayMsgOuter, RelayCellFormat, RelayCmd,
        RelayMsg as _, StreamId,
    };
    use tor_linkspec::OwnedCircTarget;
    use tor_memquota::HasMemoryCost;
    use tor_rtcompat::Runtime;
    use tracing::trace;
    use tracing_test::traced_test;

    #[cfg(feature = "conflux")]
    use {
        crate::tunnel::reactor::ConfluxHandshakeResult,
        crate::util::err::ConfluxHandshakeError,
        futures::future::FusedFuture,
        futures::lock::Mutex as AsyncMutex,
        std::pin::Pin,
        std::result::Result as StdResult,
        tor_cell::relaycell::conflux::{V1DesiredUx, V1LinkPayload, V1Nonce},
        tor_cell::relaycell::msg::ConfluxLink,
        tor_rtmock::MockRuntime,
    };

    impl PendingClientTunnel {
        /// Testing only: Extract the circuit ID for this pending circuit.
        pub(crate) fn peek_circid(&self) -> CircId {
            self.circ.circid
        }
    }

    impl ClientCirc {
        /// Testing only: Extract the circuit ID of this circuit.
        pub(crate) fn peek_circid(&self) -> CircId {
            self.circid
        }
    }

    impl ClientTunnel {
        pub(crate) async fn resolve_last_hop(&self) -> TargetHop {
            let (sender, receiver) = oneshot::channel();
            let _ =
                self.as_single_circ()
                    .unwrap()
                    .command
                    .unbounded_send(CtrlCmd::ResolveTargetHop {
                        hop: TargetHop::LastHop,
                        done: sender,
                    });
            TargetHop::Hop(receiver.await.unwrap().unwrap())
        }
    }

    fn rmsg_to_ccmsg(id: Option<StreamId>, msg: relaymsg::AnyRelayMsg) -> ClientCircChanMsg {
        // TODO #1947: test other formats.
        let rfmt = RelayCellFormat::V0;
        let body: BoxedCellBody = AnyRelayMsgOuter::new(id, msg)
            .encode(rfmt, &mut testing_rng())
            .unwrap();
        let chanmsg = chanmsg::Relay::from(body);
        ClientCircChanMsg::Relay(chanmsg)
    }

    // Example relay IDs and keys
    const EXAMPLE_SK: [u8; 32] =
        hex!("7789d92a89711a7e2874c61ea495452cfd48627b3ca2ea9546aafa5bf7b55803");
    const EXAMPLE_PK: [u8; 32] =
        hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253");
    const EXAMPLE_ED_ID: [u8; 32] = [6; 32];
    const EXAMPLE_RSA_ID: [u8; 20] = [10; 20];

    /// Make an MPSC queue, of the type we use in Channels, but a fake one for testing
    #[cfg(test)]
    pub(crate) fn fake_mpsc<T: HasMemoryCost + Debug + Send>(
        buffer: usize,
    ) -> (StreamMpscSender<T>, StreamMpscReceiver<T>) {
        crate::fake_mpsc(buffer)
    }

    /// return an example OwnedCircTarget that can get used for an ntor handshake.
    fn example_target() -> OwnedCircTarget {
        let mut builder = OwnedCircTarget::builder();
        builder
            .chan_target()
            .ed_identity(EXAMPLE_ED_ID.into())
            .rsa_identity(EXAMPLE_RSA_ID.into());
        builder
            .ntor_onion_key(EXAMPLE_PK.into())
            .protocols("FlowCtrl=1-2".parse().unwrap())
            .build()
            .unwrap()
    }
    fn example_ntor_key() -> crate::crypto::handshake::ntor::NtorSecretKey {
        crate::crypto::handshake::ntor::NtorSecretKey::new(
            EXAMPLE_SK.into(),
            EXAMPLE_PK.into(),
            EXAMPLE_RSA_ID.into(),
        )
    }
    fn example_ntor_v3_key() -> crate::crypto::handshake::ntor_v3::NtorV3SecretKey {
        crate::crypto::handshake::ntor_v3::NtorV3SecretKey::new(
            EXAMPLE_SK.into(),
            EXAMPLE_PK.into(),
            EXAMPLE_ED_ID.into(),
        )
    }

    fn working_fake_channel<R: Runtime>(
        rt: &R,
    ) -> (
        Arc<Channel>,
        Receiver<AnyChanCell>,
        Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
    ) {
        let (channel, chan_reactor, rx, tx) = new_reactor(rt.clone());
        rt.spawn(async {
            let _ignore = chan_reactor.run().await;
        })
        .unwrap();
        (channel, rx, tx)
    }

    /// Which handshake type to use.
    #[derive(Copy, Clone)]
    enum HandshakeType {
        Fast,
        Ntor,
        NtorV3,
    }

    async fn test_create<R: Runtime>(rt: &R, handshake_type: HandshakeType, with_cc: bool) {
        // We want to try progressing from a pending circuit to a circuit
        // via a crate_fast handshake.

        use crate::crypto::handshake::{fast::CreateFastServer, ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel(rt);
        let circid = CircId::new(128).unwrap();
        let (created_send, created_recv) = oneshot::channel();
        let (_circmsg_send, circmsg_recv) = fake_mpsc(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, reactor) = PendingClientTunnel::new(
            circid,
            chan,
            created_recv,
            circmsg_recv,
            unique_id,
            DynTimeProvider::new(rt.clone()),
            CircuitAccount::new_noop(),
        );

        rt.spawn(async {
            let _ignore = reactor.run().await;
        })
        .unwrap();

        // Future to pretend to be a relay on the other end of the circuit.
        let simulate_relay_fut = async move {
            let mut rng = testing_rng();
            let create_cell = rx.next().await.unwrap();
            assert_eq!(create_cell.circid(), Some(circid));
            let reply = match handshake_type {
                HandshakeType::Fast => {
                    let cf = match create_cell.msg() {
                        AnyChanMsg::CreateFast(cf) => cf,
                        other => panic!("{:?}", other),
                    };
                    let (_, rep) = CreateFastServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[()],
                        cf.handshake(),
                    )
                    .unwrap();
                    CreateResponse::CreatedFast(CreatedFast::new(rep))
                }
                HandshakeType::Ntor => {
                    let c2 = match create_cell.msg() {
                        AnyChanMsg::Create2(c2) => c2,
                        other => panic!("{:?}", other),
                    };
                    let (_, rep) = NtorServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[example_ntor_key()],
                        c2.body(),
                    )
                    .unwrap();
                    CreateResponse::Created2(Created2::new(rep))
                }
                HandshakeType::NtorV3 => {
                    let c2 = match create_cell.msg() {
                        AnyChanMsg::Create2(c2) => c2,
                        other => panic!("{:?}", other),
                    };
                    let mut reply_fn = if with_cc {
                        |client_exts: &[CircRequestExt]| {
                            let _ = client_exts
                                .iter()
                                .find(|e| matches!(e, CircRequestExt::CcRequest(_)))
                                .expect("Client failed to request CC");
                            // This needs to be aligned to test_utils params
                            // value due to validation that needs it in range.
                            Some(vec![CircResponseExt::CcResponse(
                                extend_ext::CcResponse::new(31),
                            )])
                        }
                    } else {
                        |_: &_| Some(vec![])
                    };
                    let (_, rep) = NtorV3Server::server(
                        &mut rng,
                        &mut reply_fn,
                        &[example_ntor_v3_key()],
                        c2.body(),
                    )
                    .unwrap();
                    CreateResponse::Created2(Created2::new(rep))
                }
            };
            created_send.send(reply).unwrap();
        };
        // Future to pretend to be a client.
        let client_fut = async move {
            let target = example_target();
            let params = CircParameters::default();
            let ret = match handshake_type {
                HandshakeType::Fast => {
                    trace!("doing fast create");
                    pending.create_firsthop_fast(params).await
                }
                HandshakeType::Ntor => {
                    trace!("doing ntor create");
                    pending.create_firsthop_ntor(&target, params).await
                }
                HandshakeType::NtorV3 => {
                    let params = if with_cc {
                        // Setup CC vegas parameters.
                        CircParameters::new(true, build_cc_vegas_params())
                    } else {
                        params
                    };
                    trace!("doing ntor_v3 create");
                    pending.create_firsthop_ntor_v3(&target, params).await
                }
            };
            trace!("create done: result {:?}", ret);
            ret
        };

        let (circ, _) = futures::join!(client_fut, simulate_relay_fut);

        let _circ = circ.unwrap();

        // pfew!  We've build a circuit!  Let's make sure it has one hop.
        assert_eq!(_circ.n_hops().unwrap(), 1);
    }

    #[traced_test]
    #[test]
    fn test_create_fast() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Fast, false).await;
        });
    }
    #[traced_test]
    #[test]
    fn test_create_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::Ntor, false).await;
        });
    }
    #[traced_test]
    #[test]
    fn test_create_ntor_v3() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::NtorV3, false).await;
        });
    }
    #[traced_test]
    #[test]
    #[cfg(feature = "flowctl-cc")]
    fn test_create_ntor_v3_with_cc() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_create(&rt, HandshakeType::NtorV3, true).await;
        });
    }

    // An encryption layer that doesn't do any crypto.   Can be used
    // as inbound or outbound, but not both at once.
    pub(crate) struct DummyCrypto {
        counter_tag: [u8; 20],
        counter: u32,
        lasthop: bool,
    }
    impl DummyCrypto {
        fn next_tag(&mut self) -> SendmeTag {
            #![allow(clippy::identity_op)]
            self.counter_tag[0] = ((self.counter >> 0) & 255) as u8;
            self.counter_tag[1] = ((self.counter >> 8) & 255) as u8;
            self.counter_tag[2] = ((self.counter >> 16) & 255) as u8;
            self.counter_tag[3] = ((self.counter >> 24) & 255) as u8;
            self.counter += 1;
            self.counter_tag.into()
        }
    }

    impl crate::crypto::cell::OutboundClientLayer for DummyCrypto {
        fn originate_for(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) -> SendmeTag {
            self.next_tag()
        }
        fn encrypt_outbound(&mut self, _cmd: ChanCmd, _cell: &mut RelayCellBody) {}
    }
    impl crate::crypto::cell::InboundClientLayer for DummyCrypto {
        fn decrypt_inbound(
            &mut self,
            _cmd: ChanCmd,
            _cell: &mut RelayCellBody,
        ) -> Option<SendmeTag> {
            if self.lasthop {
                Some(self.next_tag())
            } else {
                None
            }
        }
    }
    impl DummyCrypto {
        pub(crate) fn new(lasthop: bool) -> Self {
            DummyCrypto {
                counter_tag: [0; 20],
                counter: 0,
                lasthop,
            }
        }
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newtunnel_ext<R: Runtime>(
        rt: &R,
        unique_id: UniqId,
        chan: Arc<Channel>,
        hops: Vec<path::HopDetail>,
        next_msg_from: HopNum,
        params: CircParameters,
    ) -> (ClientTunnel, CircuitRxSender) {
        let circid = CircId::new(128).unwrap();
        let (_created_send, created_recv) = oneshot::channel();
        let (circmsg_send, circmsg_recv) = fake_mpsc(64);

        let (pending, reactor) = PendingClientTunnel::new(
            circid,
            chan,
            created_recv,
            circmsg_recv,
            unique_id,
            DynTimeProvider::new(rt.clone()),
            CircuitAccount::new_noop(),
        );

        rt.spawn(async {
            let _ignore = reactor.run().await;
        })
        .unwrap();
        let PendingClientTunnel {
            circ,
            recvcreated: _,
        } = pending;

        // TODO #1067: Support other formats
        let relay_cell_format = RelayCellFormat::V0;

        let last_hop_num = u8::try_from(hops.len() - 1).unwrap();
        for (idx, peer_id) in hops.into_iter().enumerate() {
            let (tx, rx) = oneshot::channel();
            let idx = idx as u8;

            circ.command
                .unbounded_send(CtrlCmd::AddFakeHop {
                    relay_cell_format,
                    fwd_lasthop: idx == last_hop_num,
                    rev_lasthop: idx == u8::from(next_msg_from),
                    peer_id,
                    params: params.clone(),
                    done: tx,
                })
                .unwrap();
            rx.await.unwrap().unwrap();
        }
        (circ.into_tunnel().unwrap(), circmsg_send)
    }

    // Helper: set up a 3-hop circuit with no encryption, where the
    // next inbound message seems to come from hop next_msg_from
    async fn newtunnel<R: Runtime>(
        rt: &R,
        chan: Arc<Channel>,
    ) -> (Arc<ClientTunnel>, CircuitRxSender) {
        let hops = std::iter::repeat_with(|| {
            let peer_id = tor_linkspec::OwnedChanTarget::builder()
                .ed_identity([4; 32].into())
                .rsa_identity([5; 20].into())
                .build()
                .expect("Could not construct fake hop");

            path::HopDetail::Relay(peer_id)
        })
        .take(3)
        .collect();

        let unique_id = UniqId::new(23, 17);
        let (tunnel, circmsg_send) = newtunnel_ext(
            rt,
            unique_id,
            chan,
            hops,
            2.into(),
            CircParameters::default(),
        )
        .await;

        (Arc::new(tunnel), circmsg_send)
    }

    /// Create `n` distinct [`path::HopDetail`]s,
    /// with the specified `start_idx` for the dummy identities.
    fn hop_details(n: u8, start_idx: u8) -> Vec<path::HopDetail> {
        (0..n)
            .map(|idx| {
                let peer_id = tor_linkspec::OwnedChanTarget::builder()
                    .ed_identity([idx + start_idx; 32].into())
                    .rsa_identity([idx + start_idx + 1; 20].into())
                    .build()
                    .expect("Could not construct fake hop");

                path::HopDetail::Relay(peer_id)
            })
            .collect()
    }

    async fn test_extend<R: Runtime>(rt: &R, handshake_type: HandshakeType) {
        use crate::crypto::handshake::{ntor::NtorServer, ServerHandshake};

        let (chan, mut rx, _sink) = working_fake_channel(rt);
        let (tunnel, mut sink) = newtunnel(rt, chan).await;
        let circ = Arc::new(tunnel.as_single_circ().unwrap());
        let circid = circ.peek_circid();
        let params = CircParameters::default();

        let extend_fut = async move {
            let target = example_target();
            match handshake_type {
                HandshakeType::Fast => panic!("Can't extend with Fast handshake"),
                HandshakeType::Ntor => circ.extend_ntor(&target, params).await.unwrap(),
                HandshakeType::NtorV3 => circ.extend_ntor_v3(&target, params).await.unwrap(),
            };
            circ // gotta keep the circ alive, or the reactor would exit.
        };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the extend2 cell.
            let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, Some(circid));
            let rmsg = match chmsg {
                AnyChanMsg::RelayEarly(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                other => panic!("{:?}", other),
            };
            let e2 = match rmsg.msg() {
                AnyRelayMsg::Extend2(e2) => e2,
                other => panic!("{:?}", other),
            };
            let mut rng = testing_rng();
            let reply = match handshake_type {
                HandshakeType::Fast => panic!("Can't extend with Fast handshake"),
                HandshakeType::Ntor => {
                    let (_keygen, reply) = NtorServer::server(
                        &mut rng,
                        &mut |_: &()| Some(()),
                        &[example_ntor_key()],
                        e2.handshake(),
                    )
                    .unwrap();
                    reply
                }
                HandshakeType::NtorV3 => {
                    let (_keygen, reply) = NtorV3Server::server(
                        &mut rng,
                        &mut |_: &[CircRequestExt]| Some(vec![]),
                        &[example_ntor_v3_key()],
                        e2.handshake(),
                    )
                    .unwrap();
                    reply
                }
            };

            let extended2 = relaymsg::Extended2::new(reply).into();
            sink.send(rmsg_to_ccmsg(None, extended2)).await.unwrap();
            (sink, rx) // gotta keep the sink and receiver alive, or the reactor will exit.
        };

        let (circ, (_sink, _rx)) = futures::join!(extend_fut, reply_fut);

        // Did we really add another hop?
        assert_eq!(circ.n_hops().unwrap(), 4);

        // Do the path accessors report a reasonable outcome?
        {
            let path = circ.single_path().unwrap();
            let path = path
                .all_hops()
                .filter_map(|hop| match hop {
                    path::HopDetail::Relay(r) => Some(r),
                    #[cfg(feature = "hs-common")]
                    path::HopDetail::Virtual => None,
                })
                .collect::<Vec<_>>();

            assert_eq!(path.len(), 4);
            use tor_linkspec::HasRelayIds;
            assert_eq!(path[3].ed_identity(), example_target().ed_identity());
            assert_ne!(path[0].ed_identity(), example_target().ed_identity());
        }
        {
            let path = circ.single_path().unwrap();
            assert_eq!(path.n_hops(), 4);
            use tor_linkspec::HasRelayIds;
            assert_eq!(
                path.hops()[3].as_chan_target().unwrap().ed_identity(),
                example_target().ed_identity()
            );
            assert_ne!(
                path.hops()[0].as_chan_target().unwrap().ed_identity(),
                example_target().ed_identity()
            );
        }
    }

    #[traced_test]
    #[test]
    fn test_extend_ntor() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_extend(&rt, HandshakeType::Ntor).await;
        });
    }

    #[traced_test]
    #[test]
    fn test_extend_ntor_v3() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            test_extend(&rt, HandshakeType::NtorV3).await;
        });
    }

    async fn bad_extend_test_impl<R: Runtime>(
        rt: &R,
        reply_hop: HopNum,
        bad_reply: ClientCircChanMsg,
    ) -> Error {
        let (chan, _rx, _sink) = working_fake_channel(rt);
        let hops = std::iter::repeat_with(|| {
            let peer_id = tor_linkspec::OwnedChanTarget::builder()
                .ed_identity([4; 32].into())
                .rsa_identity([5; 20].into())
                .build()
                .expect("Could not construct fake hop");

            path::HopDetail::Relay(peer_id)
        })
        .take(3)
        .collect();

        let unique_id = UniqId::new(23, 17);
        let (tunnel, mut sink) = newtunnel_ext(
            rt,
            unique_id,
            chan,
            hops,
            reply_hop,
            CircParameters::default(),
        )
        .await;
        let params = CircParameters::default();

        let target = example_target();
        #[allow(clippy::clone_on_copy)]
        let rtc = rt.clone();
        let sink_handle = rt
            .spawn_with_handle(async move {
                rtc.sleep(Duration::from_millis(100)).await;
                sink.send(bad_reply).await.unwrap();
                sink
            })
            .unwrap();
        let outcome = tunnel
            .as_single_circ()
            .unwrap()
            .extend_ntor(&target, params)
            .await;
        let _sink = sink_handle.await;

        assert_eq!(tunnel.n_hops().unwrap(), 3);
        assert!(outcome.is_err());
        outcome.unwrap_err()
    }

    #[traced_test]
    #[test]
    fn bad_extend_wronghop() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended2 = relaymsg::Extended2::new(vec![]).into();
            let cc = rmsg_to_ccmsg(None, extended2);

            let error = bad_extend_test_impl(&rt, 1.into(), cc).await;
            // This case shows up as a CircDestroy, since a message sent
            // from the wrong hop won't even be delivered to the extend
            // code's meta-handler.  Instead the unexpected message will cause
            // the circuit to get torn down.
            match error {
                Error::CircuitClosed => {}
                x => panic!("got other error: {}", x),
            }
        });
    }

    #[traced_test]
    #[test]
    fn bad_extend_wrongtype() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended = relaymsg::Extended::new(vec![7; 200]).into();
            let cc = rmsg_to_ccmsg(None, extended);

            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            match error {
                Error::BytesErr {
                    err: tor_bytes::Error::InvalidMessage(_),
                    object: "extended2 message",
                } => {}
                other => panic!("{:?}", other),
            }
        });
    }

    #[traced_test]
    #[test]
    fn bad_extend_destroy() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let cc = ClientCircChanMsg::Destroy(chanmsg::Destroy::new(4.into()));
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            match error {
                Error::CircuitClosed => {}
                other => panic!("{:?}", other),
            }
        });
    }

    #[traced_test]
    #[test]
    fn bad_extend_crypto() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let extended2 = relaymsg::Extended2::new(vec![99; 256]).into();
            let cc = rmsg_to_ccmsg(None, extended2);
            let error = bad_extend_test_impl(&rt, 2.into(), cc).await;
            assert!(matches!(error, Error::BadCircHandshakeAuth));
        });
    }

    #[traced_test]
    #[test]
    fn begindir() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut sink) = newtunnel(&rt, chan).await;
            let circ = tunnel.as_single_circ().unwrap();
            let circid = circ.peek_circid();

            let begin_and_send_fut = async move {
                // Here we'll say we've got a circuit, and we want to
                // make a simple BEGINDIR request with it.
                let mut stream = tunnel.begin_dir_stream().await.unwrap();
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
                assert_eq!(id, Some(circid));
                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    other => panic!("{:?}", other),
                };
                let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                assert!(matches!(rmsg, AnyRelayMsg::BeginDir(_)));

                // Reply with a Connected cell to indicate success.
                let connected = relaymsg::Connected::new_empty().into();
                sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();

                // Now read a DATA cell...
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, Some(circid));
                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    other => panic!("{:?}", other),
                };
                let (streamid_2, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(streamid_2, streamid);
                if let AnyRelayMsg::Data(d) = rmsg {
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

                (rx, sink) // gotta keep these alive, or the reactor will exit.
            };

            let (_stream, (_rx, _sink)) = futures::join!(begin_and_send_fut, reply_fut);
        });
    }

    // Test: close a stream, either by dropping it or by calling AsyncWriteExt::close.
    fn close_stream_helper(by_drop: bool) {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut sink) = newtunnel(&rt, chan).await;

            let stream_fut = async move {
                let stream = tunnel
                    .begin_stream("www.example.com", 80, None)
                    .await
                    .unwrap();

                let (r, mut w) = stream.split();
                if by_drop {
                    // Drop the writer and the reader, which should close the stream.
                    drop(r);
                    drop(w);
                    (None, tunnel) // make sure to keep the circuit alive
                } else {
                    // Call close on the writer, while keeping the reader alive.
                    w.close().await.unwrap();
                    (Some(r), tunnel)
                }
            };
            let handler_fut = async {
                // Read the BEGIN message.
                let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                let rmsg = match msg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    other => panic!("{:?}", other),
                };
                let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(rmsg.cmd(), RelayCmd::BEGIN);

                // Reply with a CONNECTED.
                let connected =
                    relaymsg::Connected::new_with_addr("10.0.0.1".parse().unwrap(), 1234).into();
                sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();

                // Expect an END.
                let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                let rmsg = match msg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    other => panic!("{:?}", other),
                };
                let (_, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(rmsg.cmd(), RelayCmd::END);

                (rx, sink) // keep these alive or the reactor will exit.
            };

            let ((_opt_reader, _circ), (_rx, _sink)) = futures::join!(stream_fut, handler_fut);
        });
    }

    #[traced_test]
    #[test]
    fn drop_stream() {
        close_stream_helper(true);
    }

    #[traced_test]
    #[test]
    fn close_stream() {
        close_stream_helper(false);
    }

    // Set up a circuit and stream that expects some incoming SENDMEs.
    async fn setup_incoming_sendme_case<R: Runtime>(
        rt: &R,
        n_to_send: usize,
    ) -> (
        Arc<ClientTunnel>,
        DataStream,
        CircuitRxSender,
        Option<StreamId>,
        usize,
        Receiver<AnyChanCell>,
        Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
    ) {
        let (chan, mut rx, sink2) = working_fake_channel(rt);
        let (tunnel, mut sink) = newtunnel(rt, chan).await;
        let circid = tunnel.as_single_circ().unwrap().peek_circid();

        let begin_and_send_fut = {
            let tunnel = tunnel.clone();
            async move {
                // Take our circuit and make a stream on it.
                let mut stream = tunnel
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
            }
        };

        let receive_fut = async move {
            // Read the begin cell.
            let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
            let rmsg = match chmsg {
                AnyChanMsg::Relay(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                other => panic!("{:?}", other),
            };
            let (streamid, rmsg) = rmsg.into_streamid_and_msg();
            assert!(matches!(rmsg, AnyRelayMsg::Begin(_)));
            // Reply with a connected cell...
            let connected = relaymsg::Connected::new_empty().into();
            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();
            // Now read bytes from the stream until we have them all.
            let mut bytes_received = 0_usize;
            let mut cells_received = 0_usize;
            while bytes_received < n_to_send {
                // Read a data cell, and remember how much we got.
                let (id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
                assert_eq!(id, Some(circid));

                let rmsg = match chmsg {
                    AnyChanMsg::Relay(r) => {
                        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                            .unwrap()
                    }
                    other => panic!("{:?}", other),
                };
                let (streamid2, rmsg) = rmsg.into_streamid_and_msg();
                assert_eq!(streamid2, streamid);
                if let AnyRelayMsg::Data(dat) = rmsg {
                    cells_received += 1;
                    bytes_received += dat.as_ref().len();
                } else {
                    panic!();
                }
            }

            (sink, streamid, cells_received, rx)
        };

        let (stream, (sink, streamid, cells_received, rx)) =
            futures::join!(begin_and_send_fut, receive_fut);

        (tunnel, stream, sink, streamid, cells_received, rx, sink2)
    }

    #[traced_test]
    #[test]
    fn accept_valid_sendme() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (tunnel, _stream, mut sink, streamid, cells_received, _rx, _sink2) =
                setup_incoming_sendme_case(&rt, 300 * 498 + 3).await;
            let circ = tunnel.as_single_circ().unwrap();

            assert_eq!(cells_received, 301);

            // Make sure that the circuit is indeed expecting the right sendmes
            {
                let (tx, rx) = oneshot::channel();
                circ.command
                    .unbounded_send(CtrlCmd::QuerySendWindow {
                        hop: 2.into(),
                        leg: tunnel.unique_id(),
                        done: tx,
                    })
                    .unwrap();
                let (window, tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 301);
                assert_eq!(tags.len(), 3);
                // 100
                assert_eq!(
                    tags[0],
                    SendmeTag::from(hex!("6400000000000000000000000000000000000000"))
                );
                // 200
                assert_eq!(
                    tags[1],
                    SendmeTag::from(hex!("c800000000000000000000000000000000000000"))
                );
                // 300
                assert_eq!(
                    tags[2],
                    SendmeTag::from(hex!("2c01000000000000000000000000000000000000"))
                );
            }

            let reply_with_sendme_fut = async move {
                // make and send a circuit-level sendme.
                let c_sendme =
                    relaymsg::Sendme::new_tag(hex!("6400000000000000000000000000000000000000"))
                        .into();
                sink.send(rmsg_to_ccmsg(None, c_sendme)).await.unwrap();

                // Make and send a stream-level sendme.
                let s_sendme = relaymsg::Sendme::new_empty().into();
                sink.send(rmsg_to_ccmsg(streamid, s_sendme)).await.unwrap();

                sink
            };

            let _sink = reply_with_sendme_fut.await;

            rt.advance_until_stalled().await;

            // Now make sure that the circuit is still happy, and its
            // window is updated.
            {
                let (tx, rx) = oneshot::channel();
                circ.command
                    .unbounded_send(CtrlCmd::QuerySendWindow {
                        hop: 2.into(),
                        leg: tunnel.unique_id(),
                        done: tx,
                    })
                    .unwrap();
                let (window, _tags) = rx.await.unwrap().unwrap();
                assert_eq!(window, 1000 - 201);
            }
        });
    }

    #[traced_test]
    #[test]
    fn invalid_circ_sendme() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            // Same setup as accept_valid_sendme() test above but try giving
            // a sendme with the wrong tag.

            let (tunnel, _stream, mut sink, _streamid, _cells_received, _rx, _sink2) =
                setup_incoming_sendme_case(&rt, 300 * 498 + 3).await;

            let reply_with_sendme_fut = async move {
                // make and send a circuit-level sendme with a bad tag.
                let c_sendme =
                    relaymsg::Sendme::new_tag(hex!("FFFF0000000000000000000000000000000000FF"))
                        .into();
                sink.send(rmsg_to_ccmsg(None, c_sendme)).await.unwrap();
                sink
            };

            let _sink = reply_with_sendme_fut.await;

            // Check whether the reactor dies as a result of receiving invalid data.
            rt.advance_until_stalled().await;
            assert!(tunnel.is_closed());
        });
    }

    #[traced_test]
    #[test]
    fn test_busy_stream_fairness() {
        // Number of streams to use.
        const N_STREAMS: usize = 3;
        // Number of cells (roughly) for each stream to send.
        const N_CELLS: usize = 20;
        // Number of bytes that *each* stream will send, and that we'll read
        // from the channel.
        const N_BYTES: usize = relaymsg::Data::MAXLEN_V0 * N_CELLS;
        // Ignoring cell granularity, with perfect fairness we'd expect
        // `N_BYTES/N_STREAMS` bytes from each stream.
        //
        // We currently allow for up to a full cell less than that.  This is
        // somewhat arbitrary and can be changed as needed, since we don't
        // provide any specific fairness guarantees.
        const MIN_EXPECTED_BYTES_PER_STREAM: usize =
            N_BYTES / N_STREAMS - relaymsg::Data::MAXLEN_V0;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, mut rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut sink) = newtunnel(&rt, chan).await;

            // Run clients in a single task, doing our own round-robin
            // scheduling of writes to the reactor. Conversely, if we were to
            // put each client in its own task, we would be at the the mercy of
            // how fairly the runtime schedules the client tasks, which is outside
            // the scope of this test.
            rt.spawn({
                // Clone the circuit to keep it alive after writers have
                // finished with it.
                let tunnel = tunnel.clone();
                async move {
                    let mut clients = VecDeque::new();
                    struct Client {
                        stream: DataStream,
                        to_write: &'static [u8],
                    }
                    for _ in 0..N_STREAMS {
                        clients.push_back(Client {
                            stream: tunnel
                                .begin_stream("www.example.com", 80, None)
                                .await
                                .unwrap(),
                            to_write: &[0_u8; N_BYTES][..],
                        });
                    }
                    while let Some(mut client) = clients.pop_front() {
                        if client.to_write.is_empty() {
                            // Client is done. Don't put back in queue.
                            continue;
                        }
                        let written = client.stream.write(client.to_write).await.unwrap();
                        client.to_write = &client.to_write[written..];
                        clients.push_back(client);
                    }
                }
            })
            .unwrap();

            let channel_handler_fut = async {
                let mut stream_bytes_received = HashMap::<StreamId, usize>::new();
                let mut total_bytes_received = 0;

                loop {
                    let (_, msg) = rx.next().await.unwrap().into_circid_and_msg();
                    let rmsg = match msg {
                        AnyChanMsg::Relay(r) => AnyRelayMsgOuter::decode_singleton(
                            RelayCellFormat::V0,
                            r.into_relay_body(),
                        )
                        .unwrap(),
                        other => panic!("Unexpected chanmsg: {other:?}"),
                    };
                    let (streamid, rmsg) = rmsg.into_streamid_and_msg();
                    match rmsg.cmd() {
                        RelayCmd::BEGIN => {
                            // Add an entry for this stream.
                            let prev = stream_bytes_received.insert(streamid.unwrap(), 0);
                            assert_eq!(prev, None);
                            // Reply with a CONNECTED.
                            let connected = relaymsg::Connected::new_with_addr(
                                "10.0.0.1".parse().unwrap(),
                                1234,
                            )
                            .into();
                            sink.send(rmsg_to_ccmsg(streamid, connected)).await.unwrap();
                        }
                        RelayCmd::DATA => {
                            let data_msg = relaymsg::Data::try_from(rmsg).unwrap();
                            let nbytes = data_msg.as_ref().len();
                            total_bytes_received += nbytes;
                            let streamid = streamid.unwrap();
                            let stream_bytes = stream_bytes_received.get_mut(&streamid).unwrap();
                            *stream_bytes += nbytes;
                            if total_bytes_received >= N_BYTES {
                                break;
                            }
                        }
                        RelayCmd::END => {
                            // Stream is done. If fair scheduling is working as
                            // expected we *probably* shouldn't get here, but we
                            // can ignore it and save the failure until we
                            // actually have the final stats.
                            continue;
                        }
                        other => {
                            panic!("Unexpected command {other:?}");
                        }
                    }
                }

                // Return our stats, along with the `rx` and `sink` to keep the
                // reactor alive (since clients could still be writing).
                (total_bytes_received, stream_bytes_received, rx, sink)
            };

            let (total_bytes_received, stream_bytes_received, _rx, _sink) =
                channel_handler_fut.await;
            assert_eq!(stream_bytes_received.len(), N_STREAMS);
            for (sid, stream_bytes) in stream_bytes_received {
                assert!(
                    stream_bytes >= MIN_EXPECTED_BYTES_PER_STREAM,
                    "Only {stream_bytes} of {total_bytes_received} bytes received from {N_STREAMS} came from {sid:?}; expected at least {MIN_EXPECTED_BYTES_PER_STREAM}"
                );
            }
        });
    }

    #[test]
    fn basic_params() {
        use super::CircParameters;
        let mut p = CircParameters::default();
        assert!(p.extend_by_ed25519_id);

        p.extend_by_ed25519_id = false;
        assert!(!p.extend_by_ed25519_id);
    }

    #[cfg(feature = "hs-service")]
    struct AllowAllStreamsFilter;
    #[cfg(feature = "hs-service")]
    impl IncomingStreamRequestFilter for AllowAllStreamsFilter {
        fn disposition(
            &mut self,
            _ctx: &crate::stream::IncomingStreamRequestContext<'_>,
            _circ: &crate::tunnel::reactor::syncview::ClientCircSyncView<'_>,
        ) -> Result<crate::stream::IncomingStreamRequestDisposition> {
            Ok(crate::stream::IncomingStreamRequestDisposition::Accept)
        }
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests_twice() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (tunnel, _send) = newtunnel(&rt, chan).await;

            let _incoming = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    tunnel.resolve_last_hop().await,
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let incoming = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    tunnel.resolve_last_hop().await,
                    AllowAllStreamsFilter,
                )
                .await;

            // There can only be one IncomingStream at a time on any given circuit.
            assert!(incoming.is_err());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn allow_stream_requests() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut send) = newtunnel(&rt, chan).await;

            let rfmt = RelayCellFormat::V0;

            // A helper channel for coordinating the "client"/"service" interaction
            let (tx, rx) = oneshot::channel();
            let mut incoming = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    tunnel.resolve_last_hop().await,
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                let stream = incoming.next().await.unwrap();
                let mut data_stream = stream
                    .accept_data(relaymsg::Connected::new_empty())
                    .await
                    .unwrap();
                // Notify the client task we're ready to accept DATA cells
                tx.send(()).unwrap();

                // Read the data the client sent us
                let mut buf = [0_u8; TEST_DATA.len()];
                data_stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, TEST_DATA);

                tunnel
            };

            let simulate_client = async move {
                let begin = relaymsg::Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending a begin cell
                send.send(ClientCircChanMsg::Relay(begin_msg))
                    .await
                    .unwrap();

                // Wait until the service is ready to accept data
                // TODO: we shouldn't need to wait! This is needed because the service will reject
                // any DATA cells that aren't associated with a known stream. We need to wait until
                // the service receives our BEGIN cell (and the reactor updates hop.map with the
                // new stream).
                rx.await.unwrap();
                // Now send some data along the newly established circuit..
                let data = relaymsg::Data::new(TEST_DATA).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Data(data))
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn accept_stream_after_reject() {
        use tor_cell::relaycell::msg::AnyRelayMsg;
        use tor_cell::relaycell::msg::BeginFlags;
        use tor_cell::relaycell::msg::EndReason;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            const TEST_DATA: &[u8] = b"ping";
            const STREAM_COUNT: usize = 2;
            let rfmt = RelayCellFormat::V0;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut send) = newtunnel(&rt, chan).await;

            // A helper channel for coordinating the "client"/"service" interaction
            let (mut tx, mut rx) = mpsc::channel(STREAM_COUNT);

            let mut incoming = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    tunnel.resolve_last_hop().await,
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                // Process 2 incoming streams
                for i in 0..STREAM_COUNT {
                    let stream = incoming.next().await.unwrap();

                    // Reject the first one
                    if i == 0 {
                        stream
                            .reject(relaymsg::End::new_with_reason(EndReason::INTERNAL))
                            .await
                            .unwrap();
                        // Notify the client
                        tx.send(()).await.unwrap();
                        continue;
                    }

                    let mut data_stream = stream
                        .accept_data(relaymsg::Connected::new_empty())
                        .await
                        .unwrap();
                    // Notify the client task we're ready to accept DATA cells
                    tx.send(()).await.unwrap();

                    // Read the data the client sent us
                    let mut buf = [0_u8; TEST_DATA.len()];
                    data_stream.read_exact(&mut buf).await.unwrap();
                    assert_eq!(&buf, TEST_DATA);
                }

                tunnel
            };

            let simulate_client = async move {
                let begin = relaymsg::Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending 2 identical begin
                // cells (the first one will be rejected by the test service).
                for _ in 0..STREAM_COUNT {
                    send.send(ClientCircChanMsg::Relay(begin_msg.clone()))
                        .await
                        .unwrap();

                    // Wait until the service rejects our request
                    rx.next().await.unwrap();
                }

                // Now send some data along the newly established circuit..
                let data = relaymsg::Data::new(TEST_DATA).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Data(data))
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let data_msg = chanmsg::Relay::from(body);

                send.send(ClientCircChanMsg::Relay(data_msg)).await.unwrap();
                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "hs-service")]
    fn incoming_stream_bad_hop() {
        use tor_cell::relaycell::msg::BeginFlags;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            /// Expect the originator of the BEGIN cell to be hop 1.
            const EXPECTED_HOP: u8 = 1;
            let rfmt = RelayCellFormat::V0;

            let (chan, _rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut send) = newtunnel(&rt, chan).await;

            // Expect to receive incoming streams from hop EXPECTED_HOP
            let mut incoming = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    // Build the precise HopLocation with the underlying circuit.
                    (
                        tunnel.as_single_circ().unwrap().unique_id(),
                        EXPECTED_HOP.into(),
                    )
                        .into(),
                    AllowAllStreamsFilter,
                )
                .await
                .unwrap();

            let simulate_service = async move {
                // The originator of the cell is actually the last hop on the circuit, not hop 1,
                // so we expect the reactor to shut down.
                assert!(incoming.next().await.is_none());
                tunnel
            };

            let simulate_client = async move {
                let begin = relaymsg::Begin::new("localhost", 80, BeginFlags::IPV6_OKAY).unwrap();
                let body: BoxedCellBody =
                    AnyRelayMsgOuter::new(StreamId::new(12), AnyRelayMsg::Begin(begin))
                        .encode(rfmt, &mut testing_rng())
                        .unwrap();
                let begin_msg = chanmsg::Relay::from(body);

                // Pretend to be a client at the other end of the circuit sending a begin cell
                send.send(ClientCircChanMsg::Relay(begin_msg))
                    .await
                    .unwrap();

                send
            };

            let (_circ, _send) = futures::join!(simulate_service, simulate_client);
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn multipath_circ_validation() {
        use std::error::Error as _;

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let params = CircParameters::default();
            let invalid_tunnels = [
                setup_bad_conflux_tunnel(&rt).await,
                setup_conflux_tunnel(&rt, true, params).await,
            ];

            for tunnel in invalid_tunnels {
                let TestTunnelCtx {
                    tunnel: _tunnel,
                    circs: _circs,
                    conflux_link_rx,
                } = tunnel;

                let conflux_hs_err = conflux_link_rx.await.unwrap().unwrap_err();
                let err_src = conflux_hs_err.source().unwrap();

                // The two circuits don't end in the same hop (no join point),
                // so the reactor will refuse to link them
                assert!(err_src
                    .to_string()
                    .contains("one more more conflux circuits are invalid"));
            }
        });
    }

    // TODO: this structure could be reused for the other tests,
    // to address nickm's comment:
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3005#note_3202362
    #[derive(Debug)]
    #[allow(unused)]
    #[cfg(feature = "conflux")]
    struct TestCircuitCtx {
        chan_rx: Receiver<AnyChanCell>,
        chan_tx: Sender<std::result::Result<OpenChanCellS2C, CodecError>>,
        circ_tx: CircuitRxSender,
        unique_id: UniqId,
    }

    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct TestTunnelCtx {
        tunnel: Arc<ClientTunnel>,
        circs: Vec<TestCircuitCtx>,
        conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
    }

    /// Wait for a LINK cell to arrive on the specified channel and return its payload.
    #[cfg(feature = "conflux")]
    async fn await_link_payload(rx: &mut Receiver<AnyChanCell>) -> ConfluxLink {
        // Wait for the LINK cell...
        let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
        let rmsg = match chmsg {
            AnyChanMsg::Relay(r) => {
                AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                    .unwrap()
            }
            other => panic!("{:?}", other),
        };
        let (streamid, rmsg) = rmsg.into_streamid_and_msg();

        let link = match rmsg {
            AnyRelayMsg::ConfluxLink(link) => link,
            _ => panic!("unexpected relay message {rmsg:?}"),
        };

        assert!(streamid.is_none());

        link
    }

    #[cfg(feature = "conflux")]
    async fn setup_conflux_tunnel(
        rt: &MockRuntime,
        same_hops: bool,
        params: CircParameters,
    ) -> TestTunnelCtx {
        let hops1 = hop_details(3, 0);
        let hops2 = if same_hops {
            hops1.clone()
        } else {
            hop_details(3, 10)
        };

        let (chan1, rx1, chan_sink1) = working_fake_channel(rt);
        let (mut tunnel1, sink1) = newtunnel_ext(
            rt,
            UniqId::new(1, 3),
            chan1,
            hops1,
            2.into(),
            params.clone(),
        )
        .await;

        let (chan2, rx2, chan_sink2) = working_fake_channel(rt);

        let (tunnel2, sink2) =
            newtunnel_ext(rt, UniqId::new(2, 4), chan2, hops2, 2.into(), params).await;

        let (answer_tx, answer_rx) = oneshot::channel();
        tunnel2
            .as_single_circ()
            .unwrap()
            .command
            .unbounded_send(CtrlCmd::ShutdownAndReturnCircuit { answer: answer_tx })
            .unwrap();

        let circuit = answer_rx.await.unwrap().unwrap();
        // The circuit should be shutting down its reactor
        rt.advance_until_stalled().await;
        assert!(tunnel2.is_closed());

        let (conflux_link_tx, conflux_link_rx) = oneshot::channel();
        // Tell the first circuit to link with the second and form a multipath tunnel
        tunnel1
            .as_single_circ()
            .unwrap()
            .control
            .unbounded_send(CtrlMsg::LinkCircuits {
                circuits: vec![circuit],
                answer: conflux_link_tx,
            })
            .unwrap();

        let circ_ctx1 = TestCircuitCtx {
            chan_rx: rx1,
            chan_tx: chan_sink1,
            circ_tx: sink1,
            unique_id: tunnel1.unique_id(),
        };

        let circ_ctx2 = TestCircuitCtx {
            chan_rx: rx2,
            chan_tx: chan_sink2,
            circ_tx: sink2,
            unique_id: tunnel2.unique_id(),
        };

        // TODO(conflux): nothing currently sets this,
        // so we need to manually set it.
        //
        // Instead of doing this, we should have a ClientCirc
        // API that sends CtrlMsg::Link circuits and sets this to true
        tunnel1.circ.is_multi_path = true;
        TestTunnelCtx {
            tunnel: Arc::new(tunnel1),
            circs: vec![circ_ctx1, circ_ctx2],
            conflux_link_rx,
        }
    }

    #[cfg(feature = "conflux")]
    async fn setup_good_conflux_tunnel(rt: &MockRuntime) -> TestTunnelCtx {
        // Our 2 test circuits are identical, so they both have the same guards,
        // which technically violates the conflux set rule mentioned in prop354.
        // For testing purposes this is fine, but in production we'll need to ensure
        // the calling code prevents guard reuse (except in the case where
        // one of the guards happens to be Guard + Exit)
        let same_hops = true;
        let params = CircParameters::new(true, build_cc_vegas_params());
        setup_conflux_tunnel(rt, same_hops, params).await
    }

    #[cfg(feature = "conflux")]
    async fn setup_bad_conflux_tunnel(rt: &MockRuntime) -> TestTunnelCtx {
        // The two circuits don't share any hops,
        // so they won't end in the same hop (no join point),
        // causing the reactor to refuse to link them.
        let same_hops = false;
        let params = CircParameters::new(true, build_cc_vegas_params());
        setup_conflux_tunnel(rt, same_hops, params).await
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn reject_conflux_linked_before_hs() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let (chan, mut _rx, _sink) = working_fake_channel(&rt);
            let (tunnel, mut sink) = newtunnel(&rt, chan).await;

            let nonce = V1Nonce::new(&mut testing_rng());
            let payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            // Send a LINKED cell
            let linked = relaymsg::ConfluxLinked::new(payload).into();
            sink.send(rmsg_to_ccmsg(None, linked)).await.unwrap();

            rt.advance_until_stalled().await;
            assert!(tunnel.is_closed());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_hs_timeout() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let TestTunnelCtx {
                tunnel: _tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, _circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            // Wait for the LINK cell
            let link = await_link_payload(&mut circ1.chan_rx).await;

            // Send a LINK cell on the first leg...
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ1
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            // Do nothing, and wait for the handshake to timeout on the second leg
            rt.advance_by(Duration::from_secs(60)).await;

            let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();

            // Get the handshake results of each circuit
            let [res1, res2]: [StdResult<(), ConfluxHandshakeError>; 2] =
                conflux_hs_res.try_into().unwrap();

            assert!(res1.is_ok());

            let err = res2.unwrap_err();
            assert!(matches!(err, ConfluxHandshakeError::Timeout), "{err:?}");
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_hs() {
        use crate::util::err::ConfluxHandshakeError;

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let nonce = V1Nonce::new(&mut testing_rng());
            let bad_link_payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            //let extended2 = relaymsg::Extended2::new(vec![]).into();
            let bad_hs_responses = [
                (
                    rmsg_to_ccmsg(
                        None,
                        relaymsg::ConfluxLinked::new(bad_link_payload.clone()).into(),
                    ),
                    "Received CONFLUX_LINKED cell with mismatched nonce",
                ),
                (
                    rmsg_to_ccmsg(None, relaymsg::ConfluxLink::new(bad_link_payload).into()),
                    "Unexpected CONFLUX_LINK cell from hop #3 on client circuit",
                ),
                (
                    rmsg_to_ccmsg(None, relaymsg::ConfluxSwitch::new(0).into()),
                    "Received CONFLUX_SWITCH on unlinked circuit?!",
                ),
                // TODO: this currently causes the reactor to shut down immediately,
                // without sending a response on the handshake channel
                /*
                (
                    rmsg_to_ccmsg(None, extended2),
                    "Received CONFLUX_LINKED cell with mismatched nonce",
                ),
                */
            ];

            for (bad_cell, expected_err) in bad_hs_responses {
                let TestTunnelCtx {
                    tunnel,
                    circs,
                    conflux_link_rx,
                } = setup_good_conflux_tunnel(&rt).await;

                let [mut _circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

                // Respond with a bogus cell on one of the legs
                circ2.circ_tx.send(bad_cell).await.unwrap();

                let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
                // Get the handshake results (the handshake results are reported early,
                // without waiting for the second circuit leg's handshake to timeout,
                // because this is a protocol violation causing the entire tunnel to shut down)
                let [res2]: [StdResult<(), ConfluxHandshakeError>; 1] =
                    conflux_hs_res.try_into().unwrap();

                match res2.unwrap_err() {
                    ConfluxHandshakeError::Link(Error::CircProto(e)) => {
                        assert_eq!(e, expected_err);
                    }
                    e => panic!("unexpected error: {e:?}"),
                }

                assert!(tunnel.is_closed());
            }
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn unexpected_conflux_cell() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let nonce = V1Nonce::new(&mut testing_rng());
            let link_payload = V1LinkPayload::new(nonce, V1DesiredUx::NO_OPINION);
            let bad_cells = [
                rmsg_to_ccmsg(
                    None,
                    relaymsg::ConfluxLinked::new(link_payload.clone()).into(),
                ),
                rmsg_to_ccmsg(
                    None,
                    relaymsg::ConfluxLink::new(link_payload.clone()).into(),
                ),
                rmsg_to_ccmsg(None, relaymsg::ConfluxSwitch::new(0).into()),
            ];

            for bad_cell in bad_cells {
                let (chan, mut _rx, _sink) = working_fake_channel(&rt);
                let (tunnel, mut sink) = newtunnel(&rt, chan).await;

                sink.send(bad_cell).await.unwrap();
                rt.advance_until_stalled().await;

                // Note: unfortunately we can't assert the circuit is
                // closing for the reason, because the reactor just logs
                // the error and then exits.
                assert!(tunnel.is_closed());
            }
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_linked() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx: _,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            let link = await_link_payload(&mut circ1.chan_rx).await;

            // Send a LINK cell on the first leg...
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ1
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            // ...and two LINKED cells on the second
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ2
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();
            let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
            circ2
                .circ_tx
                .send(rmsg_to_ccmsg(None, linked))
                .await
                .unwrap();

            rt.advance_until_stalled().await;

            // Receiving a LINKED cell on an already linked leg causes
            // the tunnel to be torn down
            assert!(tunnel.is_closed());
        });
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn conflux_bad_switch() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let bad_switch = [
                // SWITCH cells with seqno = 0 are not allowed
                relaymsg::ConfluxSwitch::new(0),
                // TODO(#2031): from c-tor:
                //
                // We have to make sure that the switch command is truly
                // incrementing the sequence number, or else it becomes
                // a side channel that can be spammed for traffic analysis.
                //
                // We should figure out what this check is supposed to look like,
                // and have a test for it
            ];

            for bad_cell in bad_switch {
                let TestTunnelCtx {
                    tunnel,
                    circs,
                    conflux_link_rx,
                } = setup_good_conflux_tunnel(&rt).await;

                let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

                let link = await_link_payload(&mut circ1.chan_rx).await;

                // Send a LINKED cell on both legs
                for circ in [&mut circ1, &mut circ2] {
                    let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
                    circ.circ_tx
                        .send(rmsg_to_ccmsg(None, linked))
                        .await
                        .unwrap();
                }

                let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
                assert!(conflux_hs_res.iter().all(|res| res.is_ok()));

                // Now send a bad SWITCH cell on *both* legs.
                // This will cause both legs to be removed from the conflux set,
                // which causes the tunnel reactor to shut down
                for circ in [&mut circ1, &mut circ2] {
                    let msg = rmsg_to_ccmsg(None, bad_cell.clone().into());
                    circ.circ_tx.send(msg).await.unwrap();
                }

                // The tunnel should be shutting down
                rt.advance_until_stalled().await;
                assert!(tunnel.is_closed());
            }
        });
    }

    // This test ensures CtrlMsg::ShutdownAndReturnCircuit returns an
    // error when called on a multi-path tunnel
    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn shutdown_and_return_circ_multipath() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx: _,
            } = setup_good_conflux_tunnel(&rt).await;

            rt.progress_until_stalled().await;

            let (answer_tx, answer_rx) = oneshot::channel();
            tunnel
                .circ
                .command
                .unbounded_send(CtrlCmd::ShutdownAndReturnCircuit { answer: answer_tx })
                .unwrap();

            // map explicitly returns () for clarity
            #[allow(clippy::unused_unit, clippy::semicolon_if_nothing_returned)]
            let err = answer_rx
                .await
                .unwrap()
                .map(|_| {
                    // Map to () so we can call unwrap
                    // (Circuit doesn't impl debug)
                    ()
                })
                .unwrap_err();

            const MSG: &str = "not a single leg conflux set (got at least 2 elements when exactly one was expected)";
            assert!(err.to_string().contains(MSG), "{err}");

            // The tunnel reactor should be shutting down,
            // regardless of the error
            rt.progress_until_stalled().await;
            assert!(tunnel.is_closed());

            // Keep circs alive, to prevent the reactor
            // from shutting down prematurely
            drop(circs);
        });
    }

    /// Run a conflux test endpoint.
    #[cfg(feature = "conflux")]
    #[derive(Debug)]
    enum ConfluxTestEndpoint<I: Iterator<Item = Option<Duration>>> {
        /// Pretend to be an exit relay.
        Relay(ConfluxExitState<I>),
        /// Client task.
        Client {
            /// Channel for receiving the outcome of the conflux handshakes.
            conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
            /// The tunnel reactor handle
            tunnel: Arc<ClientTunnel>,
            /// Data to send on a stream.
            send_data: Vec<u8>,
            /// Data we expect to receive on a stream.
            recv_data: Vec<u8>,
        },
    }

    /// Structure for returning the sinks, channels, etc. that must stay
    /// alive until the test is complete.
    #[allow(unused, clippy::large_enum_variant)]
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    enum ConfluxEndpointResult {
        Circuit {
            tunnel: Arc<ClientTunnel>,
            stream: DataStream,
        },
        Relay {
            circ: TestCircuitCtx,
        },
    }

    /// Stream data, shared by all the mock exit endpoints.
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ConfluxStreamState {
        /// The data received so far on this stream (at the exit).
        data_recvd: Vec<u8>,
        /// The total amount of data we expect to receive on this stream.
        expected_data_len: usize,
        /// Whether we have seen a BEGIN cell yet.
        begin_recvd: bool,
        /// Whether we have seen an END cell yet.
        end_recvd: bool,
        /// Whether we have sent an END cell yet.
        end_sent: bool,
    }

    #[cfg(feature = "conflux")]
    impl ConfluxStreamState {
        fn new(expected_data_len: usize) -> Self {
            Self {
                data_recvd: vec![],
                expected_data_len,
                begin_recvd: false,
                end_recvd: false,
                end_sent: false,
            }
        }
    }

    /// An object describing a SWITCH cell that we expect to receive
    /// in the mock exit
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ExpectedSwitch {
        /// The number of cells we've seen on this leg so far,
        /// up to and including the SWITCH.
        cells_so_far: usize,
        /// The expected seqno in SWITCH cell,
        seqno: u32,
    }

    /// Object dispatching cells for delivery on the appropriate
    /// leg in a multipath tunnel.
    ///
    /// Used to send out-of-order cells from the mock exit
    /// to the client under test.
    #[cfg(feature = "conflux")]
    struct CellDispatcher {
        /// Channels on which to send the [`CellToSend`] commands on.
        leg_tx: HashMap<UniqId, mpsc::Sender<CellToSend>>,
        /// The list of cells to send,
        cells_to_send: Vec<(UniqId, AnyRelayMsg)>,
    }

    #[cfg(feature = "conflux")]
    impl CellDispatcher {
        async fn run(mut self) {
            while !self.cells_to_send.is_empty() {
                let (circ_id, cell) = self.cells_to_send.remove(0);
                let cell_tx = self.leg_tx.get_mut(&circ_id).unwrap();
                let (done_tx, done_rx) = oneshot::channel();
                cell_tx.send(CellToSend { done_tx, cell }).await.unwrap();
                // Wait for the cell to be sent before sending the next one.
                let () = done_rx.await.unwrap();
            }
        }
    }

    /// A cell for the mock exit to send on one of its legs.
    #[cfg(feature = "conflux")]
    #[derive(Debug)]
    struct CellToSend {
        /// Channel for notifying the control task that the cell was sent.
        done_tx: oneshot::Sender<()>,
        /// The cell to send.
        cell: AnyRelayMsg,
    }

    /// The state of a mock exit.
    #[derive(Debug)]
    #[cfg(feature = "conflux")]
    struct ConfluxExitState<I: Iterator<Item = Option<Duration>>> {
        /// The runtime, shared by the test client and mock exit tasks.
        ///
        /// The mutex prevents the client and mock exit tasks from calling
        /// functions like [`MockRuntime::advance_until_stalled`]
        /// or [`MockRuntime::progress_until_stalled]` concurrently,
        /// as this is not supported by the mock runtime.
        runtime: Arc<AsyncMutex<MockRuntime>>,
        /// The client view of the tunnel.
        tunnel: Arc<ClientTunnel>,
        /// The circuit test context.
        circ: TestCircuitCtx,
        /// The RTT delay to introduce just before each SENDME.
        ///
        /// Used to trigger the client to send a SWITCH.
        rtt_delays: I,
        /// State of the (only) expected stream on this tunnel,
        /// shared by all the mock exit endpoints.
        stream_state: Arc<Mutex<ConfluxStreamState>>,
        /// The number of cells after which to expect a SWITCH
        /// cell from the client.
        expect_switch: Vec<ExpectedSwitch>,
        /// Channel for receiving notifications from the other leg.
        event_rx: mpsc::Receiver<MockExitEvent>,
        /// Channel for sending notifications to the other leg.
        event_tx: mpsc::Sender<MockExitEvent>,
        /// Whether this circuit leg should act as the primary (sending) leg.
        is_sending_leg: bool,
        /// A channel for receiving cells to send on this stream.
        cells_rx: mpsc::Receiver<CellToSend>,
    }

    #[cfg(feature = "conflux")]
    async fn good_exit_handshake(
        runtime: &Arc<AsyncMutex<MockRuntime>>,
        init_rtt_delay: Option<Duration>,
        rx: &mut Receiver<ChanCell<AnyChanMsg>>,
        sink: &mut CircuitRxSender,
    ) {
        // Wait for the LINK cell
        let link = await_link_payload(rx).await;

        // Introduce an artificial delay, to make one circ have a better initial RTT
        // than the other
        if let Some(init_rtt_delay) = init_rtt_delay {
            runtime.lock().await.advance_by(init_rtt_delay).await;
        }

        // Reply with a LINKED cell...
        let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
        sink.send(rmsg_to_ccmsg(None, linked)).await.unwrap();

        // Wait for the client to respond with LINKED_ACK...
        let (_id, chmsg) = rx.next().await.unwrap().into_circid_and_msg();
        let rmsg = match chmsg {
            AnyChanMsg::Relay(r) => {
                AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                    .unwrap()
            }
            other => panic!("{other:?}"),
        };
        let (_streamid, rmsg) = rmsg.into_streamid_and_msg();

        assert!(matches!(rmsg, AnyRelayMsg::ConfluxLinkedAck(_)));
    }

    /// An event sent by one mock conflux leg to another.
    #[derive(Copy, Clone, Debug)]
    enum MockExitEvent {
        /// Inform the other leg we are done.
        Done,
        /// Inform the other leg a stream was opened.
        BeginRecvd(StreamId),
    }

    #[cfg(feature = "conflux")]
    async fn run_mock_conflux_exit<I: Iterator<Item = Option<Duration>>>(
        state: ConfluxExitState<I>,
    ) -> ConfluxEndpointResult {
        let ConfluxExitState {
            runtime,
            tunnel,
            mut circ,
            rtt_delays,
            stream_state,
            mut expect_switch,
            mut event_tx,
            mut event_rx,
            is_sending_leg,
            mut cells_rx,
        } = state;

        let mut rtt_delays = rtt_delays.into_iter();

        // Expect the client to open a stream, and de-multiplex the received stream data
        let stream_len = stream_state.lock().unwrap().expected_data_len;
        let mut data_cells_received = 0_usize;
        let mut cell_count = 0_usize;
        let mut tags = vec![];
        let mut streamid = None;
        let mut done_writing = false;

        loop {
            let should_exit = {
                let stream_state = stream_state.lock().unwrap();
                let done_reading = stream_state.data_recvd.len() >= stream_len;

                (stream_state.begin_recvd || stream_state.end_recvd) && done_reading && done_writing
            };

            if should_exit {
                break;
            }

            use futures::select;

            // Only start reading from the dispatcher channel after the stream is open
            // and we're ready to start sending cells.
            let mut next_cell = if streamid.is_some() && !done_writing {
                Box::pin(cells_rx.next().fuse())
                    as Pin<Box<dyn FusedFuture<Output = Option<CellToSend>> + Send>>
            } else {
                Box::pin(std::future::pending().fuse())
            };

            // Wait for the BEGIN cell to arrive, or for the transfer to complete
            // (we need to bail if the other leg already completed);
            let res = select! {
                res = circ.chan_rx.next() => {
                    res.unwrap()
                },
                res = event_rx.next() => {
                    let Some(event) = res else {
                        break;
                    };

                    match event {
                        MockExitEvent::Done => {
                            break;
                        },
                        MockExitEvent::BeginRecvd(id) => {
                            // The stream is now open (the other leg received the BEGIN),
                            // so we're reading to start reading cells from the cell dispatcher.
                            streamid = Some(id);
                            continue;
                        },
                    }
                }
                res = next_cell => {
                    if let Some(cell_to_send) = res {
                        let CellToSend { cell, done_tx } = cell_to_send;

                        // SWITCH cells don't have a stream ID
                        let streamid = if matches!(cell, AnyRelayMsg::ConfluxSwitch(_)) {
                            None
                        } else {
                            streamid
                        };

                        circ.circ_tx
                            .send(rmsg_to_ccmsg(streamid, cell))
                            .await
                            .unwrap();

                        runtime.lock().await.advance_until_stalled().await;
                        done_tx.send(()).unwrap();
                    } else {
                        done_writing = true;
                    }

                    continue;
                }
            };

            let (_id, chmsg) = res.into_circid_and_msg();
            cell_count += 1;
            let rmsg = match chmsg {
                AnyChanMsg::Relay(r) => {
                    AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, r.into_relay_body())
                        .unwrap()
                }
                other => panic!("{:?}", other),
            };
            let (new_streamid, rmsg) = rmsg.into_streamid_and_msg();
            if streamid.is_none() {
                streamid = new_streamid;
            }

            let begin_recvd = stream_state.lock().unwrap().begin_recvd;
            let end_recvd = stream_state.lock().unwrap().end_recvd;
            match rmsg {
                AnyRelayMsg::Begin(_) if begin_recvd => {
                    panic!("client tried to open two streams?!");
                }
                AnyRelayMsg::Begin(_) if !begin_recvd => {
                    stream_state.lock().unwrap().begin_recvd = true;
                    // Reply with a connected cell...
                    let connected = relaymsg::Connected::new_empty().into();
                    circ.circ_tx
                        .send(rmsg_to_ccmsg(streamid, connected))
                        .await
                        .unwrap();
                    // Tell the other leg we received a BEGIN cell
                    event_tx
                        .send(MockExitEvent::BeginRecvd(streamid.unwrap()))
                        .await
                        .unwrap();
                }
                AnyRelayMsg::End(_) if !end_recvd => {
                    stream_state.lock().unwrap().end_recvd = true;
                    break;
                }
                AnyRelayMsg::End(_) if end_recvd => {
                    panic!("received two END cells for the same stream?!");
                }
                AnyRelayMsg::ConfluxSwitch(cell) => {
                    // Ensure we got the SWITCH after the expected number of cells
                    let expected = expect_switch.remove(0);

                    assert_eq!(expected.cells_so_far, cell_count);
                    assert_eq!(expected.seqno, cell.seqno());

                    // To keep the tests simple, we don't handle out of order cells,
                    // and simply sort the received data at the end.
                    // This ensures all the data was actually received,
                    // but it doesn't actually test that the SWITCH cells
                    // contain the appropriate seqnos.
                    continue;
                }
                AnyRelayMsg::Data(dat) => {
                    data_cells_received += 1;
                    stream_state
                        .lock()
                        .unwrap()
                        .data_recvd
                        .extend_from_slice(dat.as_ref());

                    let is_next_cell_sendme = data_cells_received % 31 == 0;
                    if is_next_cell_sendme {
                        if tags.is_empty() {
                            // Important: we need to make sure all the SENDMEs
                            // we sent so far have been processed by the reactor
                            // (otherwise the next QuerySendWindow call
                            // might return an outdated list of tags!)
                            runtime.lock().await.advance_until_stalled().await;
                            let (tx, rx) = oneshot::channel();
                            tunnel
                                .circ
                                .command
                                .unbounded_send(CtrlCmd::QuerySendWindow {
                                    hop: 2.into(),
                                    leg: circ.unique_id,
                                    done: tx,
                                })
                                .unwrap();

                            // Get a fresh batch of tags.
                            let (_window, new_tags) = rx.await.unwrap().unwrap();
                            tags = new_tags;
                        }

                        let tag = tags.remove(0);

                        // Introduce an artificial delay, to make one circ have worse RTT
                        // than the other, and thus trigger a SWITCH
                        if let Some(rtt_delay) = rtt_delays.next().flatten() {
                            runtime.lock().await.advance_by(rtt_delay).await;
                        }
                        // Make and send a circuit-level SENDME
                        let sendme = relaymsg::Sendme::from(tag).into();

                        circ.circ_tx
                            .send(rmsg_to_ccmsg(None, sendme))
                            .await
                            .unwrap();
                    }
                }
                _ => panic!("unexpected message {rmsg:?} on leg {}", circ.unique_id),
            }
        }

        let end_recvd = stream_state.lock().unwrap().end_recvd;

        // Close the stream if the other endpoint hasn't already done so
        if is_sending_leg && !end_recvd {
            let end = relaymsg::End::new_with_reason(relaymsg::EndReason::DONE).into();
            circ.circ_tx
                .send(rmsg_to_ccmsg(streamid, end))
                .await
                .unwrap();
            stream_state.lock().unwrap().end_sent = true;
        }

        // This is allowed to fail, because the other leg might have exited first.
        let _ = event_tx.send(MockExitEvent::Done).await;

        // Ensure we received all the switch cells we were expecting
        assert!(
            expect_switch.is_empty(),
            "expect_switch = {expect_switch:?}"
        );

        ConfluxEndpointResult::Relay { circ }
    }

    #[cfg(feature = "conflux")]
    async fn run_conflux_client(
        tunnel: Arc<ClientTunnel>,
        conflux_link_rx: oneshot::Receiver<Result<ConfluxHandshakeResult>>,
        send_data: Vec<u8>,
        recv_data: Vec<u8>,
    ) -> ConfluxEndpointResult {
        let res = conflux_link_rx.await;

        let res = res.unwrap().unwrap();
        assert_eq!(res.len(), 2);

        // All circuit legs have completed the conflux handshake,
        // so we now have a multipath tunnel

        // Now we're ready to open a stream
        let mut stream = tunnel
            .begin_stream("www.example.com", 443, None)
            .await
            .unwrap();

        stream.write_all(&send_data).await.unwrap();
        stream.flush().await.unwrap();

        let mut recv: Vec<u8> = Vec::new();
        let recv_len = stream.read_to_end(&mut recv).await.unwrap();
        assert_eq!(recv_len, recv_data.len());
        assert_eq!(recv_data, recv);

        ConfluxEndpointResult::Circuit { tunnel, stream }
    }

    #[cfg(feature = "conflux")]
    async fn run_conflux_endpoint<I: Iterator<Item = Option<Duration>>>(
        endpoint: ConfluxTestEndpoint<I>,
    ) -> ConfluxEndpointResult {
        match endpoint {
            ConfluxTestEndpoint::Relay(state) => run_mock_conflux_exit(state).await,
            ConfluxTestEndpoint::Client {
                tunnel,
                conflux_link_rx,
                send_data,
                recv_data,
            } => run_conflux_client(tunnel, conflux_link_rx, send_data, recv_data).await,
        }
    }

    // In this test, a `ConfluxTestEndpoint::Client` task creates a multipath tunnel
    // with 2 legs, opens a stream and sends 300 DATA cells on it.
    //
    // The test spawns two `ConfluxTestEndpoint::Relay` tasks (one for each leg),
    // which mock the behavior of an exit. The two relay tasks introduce
    // artificial delays before each SENDME sent to the client,
    // in order to trigger it to switch its sending leg predictably.
    //
    // The mock exit does not send any data on the stream.
    //
    // This test checks that the client sends SWITCH cells at the right time,
    // and that all the data it sent over the stream arrived at the exit.
    //
    // Note, however, that it doesn't check that the client sends the data in
    // the right order. For simplicity, the test concatenates the data received
    // on both legs, sorts it, and then compares it against the of the data sent
    // by the client (TODO: improve this)
    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn multipath_client_to_exit() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            /// The number of data cells to send.
            const NUM_CELLS: usize = 300;
            /// 498 bytes per DATA cell.
            const CELL_SIZE: usize = 498;

            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;
            let [circ1, circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            // The stream data we're going to send over the conflux tunnel
            let mut send_data = (0..255_u8)
                .cycle()
                .take(NUM_CELLS * CELL_SIZE)
                .collect::<Vec<_>>();
            let stream_state = Arc::new(Mutex::new(ConfluxStreamState::new(send_data.len())));

            let mut tasks = vec![];

            // Channels used by the mock relays to notify each other
            // of various events.
            let (tx1, rx1) = mpsc::channel(1);
            let (tx2, rx2) = mpsc::channel(1);

            // The 9 RTT delays to insert before each of the 9 SENDMEs
            // the exit will end up sending.
            //
            // Note: the first delay is the init_rtt delay (measured during the conflux HS).
            let circ1_rtt_delays = [
                // Initially, circ1 has better RTT, so we will start on this leg.
                Some(Duration::from_millis(100)),
                // But then its RTT takes a turn for the worse,
                // triggering a switch after the first SENDME is processed
                // (this happens after sending 123 DATA cells).
                Some(Duration::from_millis(500)),
                Some(Duration::from_millis(700)),
                Some(Duration::from_millis(900)),
                Some(Duration::from_millis(1100)),
                Some(Duration::from_millis(1300)),
                Some(Duration::from_millis(1500)),
                Some(Duration::from_millis(1700)),
                Some(Duration::from_millis(1900)),
                Some(Duration::from_millis(2100)),
            ]
            .into_iter();

            let circ2_rtt_delays = [
                Some(Duration::from_millis(200)),
                Some(Duration::from_millis(400)),
                Some(Duration::from_millis(600)),
                Some(Duration::from_millis(800)),
                Some(Duration::from_millis(1000)),
                Some(Duration::from_millis(1200)),
                Some(Duration::from_millis(1400)),
                Some(Duration::from_millis(1600)),
                Some(Duration::from_millis(1800)),
                Some(Duration::from_millis(2000)),
            ]
            .into_iter();

            let expected_switches1 = vec![ExpectedSwitch {
                // We start on this leg, and receive a BEGIN cell,
                // followed by (4 * 31 - 1) = 123 DATA cells.
                // Then it becomes blocked on CC, then finally the reactor
                // realizes it has some SENDMEs to process, and
                // then as a result of the new RTT measurement, we switch to circ1,
                // and then finally we switch back here, and get another SWITCH
                // as the 126th cell.
                cells_so_far: 126,
                // Leg 2 switches back to this leg after the 249th cell
                // (just before sending the 250th one):
                // seqno = 125 carried over from leg 1 (see the seqno of the
                // SWITCH expected on leg 2 below), plus 1 SWITCH, plus
                // 4 * 31 = 124 DATA cells after which the RTT of the first leg
                // is deemed favorable again.
                //
                // 249 - 125 (last_seq_sent of leg 1) = 124
                seqno: 124,
            }];

            let expected_switches2 = vec![ExpectedSwitch {
                // The SWITCH is the first cell we received after the conflux HS
                // on this leg.
                cells_so_far: 1,
                // See explanation on the ExpectedSwitch from circ1 above.
                seqno: 125,
            }];

            let relay_runtime = Arc::new(AsyncMutex::new(rt.clone()));

            // Drop the senders and close the channels,
            // we have nothing to send in this test.
            let (_, cells_rx1) = mpsc::channel(1);
            let (_, cells_rx2) = mpsc::channel(1);

            let relay1 = ConfluxExitState {
                runtime: Arc::clone(&relay_runtime),
                tunnel: Arc::clone(&tunnel),
                circ: circ1,
                rtt_delays: circ1_rtt_delays,
                stream_state: Arc::clone(&stream_state),
                expect_switch: expected_switches1,
                event_tx: tx1,
                event_rx: rx2,
                is_sending_leg: true,
                cells_rx: cells_rx1,
            };

            let relay2 = ConfluxExitState {
                runtime: Arc::clone(&relay_runtime),
                tunnel: Arc::clone(&tunnel),
                circ: circ2,
                rtt_delays: circ2_rtt_delays,
                stream_state: Arc::clone(&stream_state),
                expect_switch: expected_switches2,
                event_tx: tx2,
                event_rx: rx1,
                is_sending_leg: false,
                cells_rx: cells_rx2,
            };

            for mut mock_relay in [relay1, relay2] {
                let leg = mock_relay.circ.unique_id;

                // Do the conflux handshake
                //
                // We do this outside of run_conflux_endpoint,
                // toa void running both handshakes at concurrently
                // (this gives more predictable RTT delays:
                // if both handshake tasks run at once, they race
                // to advance the mock runtime's clock)
                good_exit_handshake(
                    &relay_runtime,
                    mock_relay.rtt_delays.next().flatten(),
                    &mut mock_relay.circ.chan_rx,
                    &mut mock_relay.circ.circ_tx,
                )
                .await;

                let relay = ConfluxTestEndpoint::Relay(mock_relay);

                tasks.push(rt.spawn_join(format!("relay task {leg}"), run_conflux_endpoint(relay)));
            }

            tasks.push(rt.spawn_join(
                "client task".to_string(),
                run_conflux_endpoint(ConfluxTestEndpoint::Client {
                    tunnel,
                    conflux_link_rx,
                    send_data: send_data.clone(),
                    recv_data: vec![],
                }),
            ));
            let _sinks = futures::future::join_all(tasks).await;
            let mut stream_state = stream_state.lock().unwrap();
            assert!(stream_state.begin_recvd);

            stream_state.data_recvd.sort();
            send_data.sort();
            assert_eq!(stream_state.data_recvd, send_data);
        });
    }

    // In this test, a `ConfluxTestEndpoint::Client` task creates a multipath tunnel
    // with 2 legs, opens a stream and reads from the stream until the stream is closed.
    //
    // The test spawns two `ConfluxTestEndpoint::Relay` tasks (one for each leg),
    // which mock the behavior of an exit. The two tasks send DATA and SWITCH
    // cells on the two circuit "legs" such that some cells arrive out of order.
    // This forces the client to buffer some cells, and then reorder them when
    // the missing cells finally arrive.
    //
    // The client does not send any data on the stream.
    #[cfg(feature = "conflux")]
    async fn run_multipath_exit_to_client_test(
        rt: MockRuntime,
        tunnel: TestTunnelCtx,
        cells_to_send: Vec<(UniqId, AnyRelayMsg)>,
        send_data: Vec<u8>,
        recv_data: Vec<u8>,
    ) -> Arc<Mutex<ConfluxStreamState>> {
        let TestTunnelCtx {
            tunnel,
            circs,
            conflux_link_rx,
        } = tunnel;
        let [circ1, circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

        let stream_state = Arc::new(Mutex::new(ConfluxStreamState::new(send_data.len())));

        let mut tasks = vec![];
        let relay_runtime = Arc::new(AsyncMutex::new(rt.clone()));
        let (cells_tx1, cells_rx1) = mpsc::channel(1);
        let (cells_tx2, cells_rx2) = mpsc::channel(1);

        let dispatcher = CellDispatcher {
            leg_tx: [(circ1.unique_id, cells_tx1), (circ2.unique_id, cells_tx2)]
                .into_iter()
                .collect(),
            cells_to_send,
        };

        // Channels used by the mock relays to notify each other
        // of various events.
        let (tx1, rx1) = mpsc::channel(1);
        let (tx2, rx2) = mpsc::channel(1);

        let relay1 = ConfluxExitState {
            runtime: Arc::clone(&relay_runtime),
            tunnel: Arc::clone(&tunnel),
            circ: circ1,
            rtt_delays: [].into_iter(),
            stream_state: Arc::clone(&stream_state),
            // Expect no SWITCH cells from the client
            expect_switch: vec![],
            event_tx: tx1,
            event_rx: rx2,
            is_sending_leg: false,
            cells_rx: cells_rx1,
        };

        let relay2 = ConfluxExitState {
            runtime: Arc::clone(&relay_runtime),
            tunnel: Arc::clone(&tunnel),
            circ: circ2,
            rtt_delays: [].into_iter(),
            stream_state: Arc::clone(&stream_state),
            // Expect no SWITCH cells from the client
            expect_switch: vec![],
            event_tx: tx2,
            event_rx: rx1,
            is_sending_leg: true,
            cells_rx: cells_rx2,
        };

        // Run the cell dispatcher, which tells each exit leg task
        // what cells to write.
        //
        // This enables us to write out-of-order cells deterministically.
        rt.spawn(dispatcher.run()).unwrap();

        for mut mock_relay in [relay1, relay2] {
            let leg = mock_relay.circ.unique_id;

            good_exit_handshake(
                &relay_runtime,
                mock_relay.rtt_delays.next().flatten(),
                &mut mock_relay.circ.chan_rx,
                &mut mock_relay.circ.circ_tx,
            )
            .await;

            let relay = ConfluxTestEndpoint::Relay(mock_relay);

            tasks.push(rt.spawn_join(format!("relay task {leg}"), run_conflux_endpoint(relay)));
        }

        tasks.push(rt.spawn_join(
            "client task".to_string(),
            run_conflux_endpoint(ConfluxTestEndpoint::Client {
                tunnel,
                conflux_link_rx,
                send_data: send_data.clone(),
                recv_data,
            }),
        ));

        // Wait for all the tasks to complete
        let _sinks = futures::future::join_all(tasks).await;

        stream_state
    }

    #[traced_test]
    #[test]
    #[cfg(feature = "conflux")]
    fn multipath_exit_to_client() {
        // The data we expect the client to read from the stream
        const TO_SEND: &[u8] =
            b"But something about Buster Friendly irritated John Isidore, one specific thing";

        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            // The indices of the tunnel legs.
            const CIRC1: usize = 0;
            const CIRC2: usize = 1;

            // The client receives the following cells, in the order indicated
            // by the t0-t8 "timestamps" (where C = CONNECTED, D = DATA, E = END,
            // S = SWITCH):
            //
            //  Leg 1 (CIRC1):   -----------D--------------------- D -- D -- C
            //                              |                      |    |    | \
            //                              |                      |    |    |  v
            //                              |                      |    |    | client
            //                              |                      |    |    |  ^
            //                              |                      |    |    |/
            //  Leg 2 (CIRC2): E - D -- D --\--- D* -- S (seqno=4)-/----/----/
            //                 |   |    |   |    |       |         |    |    |
            //                 |   |    |   |    |       |         |    |    |
            //                 |   |    |   |    |       |         |    |    |
            //  Time:          t8  t7   t6  t5   t4      t3        t2   t1  t0
            //
            //
            //  The cells marked with * are out of order.
            //
            // Note: t0 is the time when the client receives the first cell,
            // and t8 is the time when it receives the last one.
            // In other words, this test simulates a mock exit that "sent" the cells
            // in the order t0, t1, t2, t5, t4, t6, t7, t8
            let simple_switch = vec![
                (CIRC1, relaymsg::Data::new(&TO_SEND[0..5]).unwrap().into()),
                (CIRC1, relaymsg::Data::new(&TO_SEND[5..10]).unwrap().into()),
                // Switch to sending on the second leg
                (CIRC2, relaymsg::ConfluxSwitch::new(4).into()),
                // An out of order cell!
                (CIRC2, relaymsg::Data::new(&TO_SEND[20..30]).unwrap().into()),
                // The missing cell (as indicated by seqno = 4 from the switch cell above)
                // is finally arriving on leg1
                (CIRC1, relaymsg::Data::new(&TO_SEND[10..20]).unwrap().into()),
                (CIRC2, relaymsg::Data::new(&TO_SEND[30..40]).unwrap().into()),
                (CIRC2, relaymsg::Data::new(&TO_SEND[40..]).unwrap().into()),
            ];

            //  Leg 1 (CIRC1): ---------------- D  ------D* --- S(seqno = 3) -- D - D ---------------------------- C
            //                                  |        |          |           |   |                              | \
            //                                  |        |          |           |   |                              |  v
            //                                  |        |          |           |   |                              |  client
            //                                  |        |          |           |   |                              |  ^
            //                                  |        |          |           |   |                              | /
            //  Leg 2 (CIRC2): E - S(seqno = 2) \ -- D --\----------\---------- \ --\--- D* -- D* - S(seqno = 3) --/
            //                 |        |       |    |   |          |           |   |    |     |         |         |
            //                 |        |       |    |   |          |           |   |    |     |         |         |
            //                 |        |       |    |   |          |           |   |    |     |         |         |
            //  Time:          t11      t10     t9   t8  t7         t6          t5  t4   t3    t2        t1        t0
            //  =====================================================================================================
            //  Leg 1 LSR:      8        8      8 7  7   7          6           3   2    1      1        1         1
            //  Leg 2 LSR:      9        8      6 6  6   5          5           5   5    5      4        3         0
            //  LSD:            9        8      8 7  6   5          5       5   3   2    1      1        1         1
            //                                    ^ OOO cell is delivered   ^ the OOO cells are delivered to the stream
            //
            //
            //  (LSR = last seq received, LSD = last seq delivered, both from the client's POV)
            //
            //
            // The client keeps track of the `last_seqno_received` (LSR) on each leg.
            // This is incremented for each cell that counts towards the seqnos (BEGIN, DATA, etc.)
            // that is received on the leg. The client also tracks the `last_seqno_delivered` (LSD),
            // which is the seqno of the last cell delivered to a stream
            // (this is global for the whole tunnel, whereas the LSR is different for each leg).
            //
            // When switching to leg `N`, the seqno in the switch is, from the POV of the sender,
            // the delta between the absolute seqno (i.e. the total number of cells[^1] sent)
            // and the value of this absolute seqno when leg `N` was last used.
            //
            // At the time of the first SWITCH from `t1`, the exit "sent" 3 cells:
            // a `CONNECTED` cell, which was received by the client at `t0`, and 2 `DATA` cells that
            // haven't been received yet. At this point, the exit decides to switch to leg 2,
            // on which it hasn't sent any cells yet, so the seqno is set to `3 - 0 = 3`.
            //
            // At `t6` when the exit sends the second switch (leg 2 -> leg 1), has "sent" 6 cells
            // (`C` plus the data cells that are received at `t1 - 5` and `t8`.
            // The seqno is `6 - 3 = 3`, because when it last sent on leg 1,
            // the absolute seqno was `3`.
            //
            // At `t10`, the absolute seqno is 8 (8 qualifying cells have been sent so far).
            // When the exit last sent on leg 2 (which we are switching to),
            // the absolute seqno was `6`, so the `SWITCH` cell will have `8 - 6 = 2` as the seqno.
            //
            // [^1]: only counting the cells that count towards sequence numbers
            let multiple_switches = vec![
                // Immediately switch to sending on the second leg
                // (indicating that we've already sent 3 cells (including the CONNECTED)
                (CIRC2, relaymsg::ConfluxSwitch::new(3).into()),
                // Two out of order cells!
                (CIRC2, relaymsg::Data::new(&TO_SEND[15..20]).unwrap().into()),
                (CIRC2, relaymsg::Data::new(&TO_SEND[20..30]).unwrap().into()),
                // The missing cells finally arrive on the first leg
                (CIRC1, relaymsg::Data::new(&TO_SEND[0..10]).unwrap().into()),
                (CIRC1, relaymsg::Data::new(&TO_SEND[10..15]).unwrap().into()),
                // Switch back to the first leg
                (CIRC1, relaymsg::ConfluxSwitch::new(3).into()),
                // OOO cell
                (CIRC1, relaymsg::Data::new(&TO_SEND[31..40]).unwrap().into()),
                // Missing cell is received
                (CIRC2, relaymsg::Data::new(&TO_SEND[30..31]).unwrap().into()),
                // The remaining cells are in-order
                (CIRC1, relaymsg::Data::new(&TO_SEND[40..]).unwrap().into()),
                // Switch right after we've sent all the data we had to send
                (CIRC2, relaymsg::ConfluxSwitch::new(2).into()),
            ];

            // TODO: give these tests the ability to control when END cells are sent
            // (currently we have ensure the is_sending_leg is set to true
            // on the leg that ends up sending the last data cell).
            //
            // TODO: test the edge cases
            let tests = [simple_switch, multiple_switches];

            for cells_to_send in tests {
                let tunnel = setup_good_conflux_tunnel(&rt).await;
                assert_eq!(tunnel.circs.len(), 2);
                let circ_ids = [tunnel.circs[0].unique_id, tunnel.circs[1].unique_id];
                let cells_to_send = cells_to_send
                    .into_iter()
                    .map(|(i, cell)| (circ_ids[i], cell))
                    .collect();

                // The client won't be sending any DATA cells on this stream
                let send_data = vec![];
                let stream_state = run_multipath_exit_to_client_test(
                    rt.clone(),
                    tunnel,
                    cells_to_send,
                    send_data.clone(),
                    TO_SEND.into(),
                )
                .await;
                let stream_state = stream_state.lock().unwrap();
                assert!(stream_state.begin_recvd);
                // We don't expect the client to have sent anything
                assert!(stream_state.data_recvd.is_empty());
            }
        });
    }

    #[traced_test]
    #[test]
    #[cfg(all(feature = "conflux", feature = "hs-service"))]
    fn conflux_incoming_stream() {
        tor_rtmock::MockRuntime::test_with_various(|rt| async move {
            use std::error::Error as _;

            const EXPECTED_HOP: u8 = 1;

            let TestTunnelCtx {
                tunnel,
                circs,
                conflux_link_rx,
            } = setup_good_conflux_tunnel(&rt).await;

            let [mut circ1, mut circ2]: [TestCircuitCtx; 2] = circs.try_into().unwrap();

            let link = await_link_payload(&mut circ1.chan_rx).await;
            for circ in [&mut circ1, &mut circ2] {
                let linked = relaymsg::ConfluxLinked::new(link.payload().clone()).into();
                circ.circ_tx
                    .send(rmsg_to_ccmsg(None, linked))
                    .await
                    .unwrap();
            }

            let conflux_hs_res = conflux_link_rx.await.unwrap().unwrap();
            assert!(conflux_hs_res.iter().all(|res| res.is_ok()));

            // TODO(#2002): we don't currently support conflux for onion services
            let err = tunnel
                .allow_stream_requests(
                    &[tor_cell::relaycell::RelayCmd::BEGIN],
                    (tunnel.circ.unique_id(), EXPECTED_HOP.into()).into(),
                    AllowAllStreamsFilter,
                )
                .await
                // IncomingStream doesn't impl Debug, so we need to map to a different type
                .map(|_| ())
                .unwrap_err();

            let err_src = err.source().unwrap().to_string();
            assert!(
                err_src.contains("Cannot allow stream requests on a multi-path tunnel"),
                "{err_src}"
            );
        });
    }
}
