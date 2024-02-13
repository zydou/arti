#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod err;
#[cfg(feature = "hs-common")]
mod hsdir_params;
#[cfg(feature = "hs-common")]
mod hsdir_ring;
pub mod params;
mod weight;

#[cfg(any(test, feature = "testing"))]
pub mod testnet;
#[cfg(feature = "testing")]
pub mod testprovider;

#[cfg(feature = "hs-service")]
use itertools::chain;
use static_assertions::const_assert;
use tor_linkspec::{
    ChanTarget, DirectChanMethodsHelper, HasAddrs, HasRelayIds, RelayIdRef, RelayIdType,
};
use tor_llcrypto as ll;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_netdoc::doc::microdesc::{MdDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MdConsensus, MdConsensusRouterStatus, RouterStatus};
use tor_netdoc::types::policy::PortPolicy;
#[cfg(feature = "hs-common")]
use {hsdir_ring::HsDirRing, std::iter};

use derive_more::{From, Into};
use futures::stream::BoxStream;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::seq::SliceRandom;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use strum::{EnumCount, EnumIter};
use tracing::warn;
use typed_index_collections::{TiSlice, TiVec};

#[cfg(feature = "hs-common")]
use {
    itertools::Itertools,
    std::collections::HashSet,
    tor_error::{internal, Bug},
    tor_hscrypto::{pk::HsBlindId, time::TimePeriod},
};

pub use err::Error;
pub use weight::WeightRole;
/// A Result using the Error type from the tor-netdir crate
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "hs-common")]
pub use err::OnionDirLookupError;

use params::NetParameters;
#[cfg(feature = "geoip")]
use tor_geoip::{CountryCode, GeoipDb, HasCountryCode};

#[cfg(feature = "hs-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-common")))]
pub use hsdir_params::HsDirParams;

/// Index into the consensus relays
///
/// This is an index into the list of relays returned by
/// [`.c_relays()`](ConsensusRelays::c_relays)
/// (on the corresponding consensus or netdir).
///
/// This is just a `usize` inside, but using a newtype prevents getting a relay index
/// confused with other kinds of slice indices or counts.
///
/// If you are in a part of the code which needs to work with multiple consensuses,
/// the typechecking cannot tell if you try to index into the wrong consensus.
#[derive(Debug, From, Into, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct RouterStatusIdx(usize);

/// Extension trait to provide index-type-safe `.c_relays()` method
//
// TODO: Really it would be better to have MdConsensns::relays() return TiSlice,
// but that would be an API break there.
pub(crate) trait ConsensusRelays {
    /// Obtain the list of relays in the consensus
    //
    fn c_relays(&self) -> &TiSlice<RouterStatusIdx, MdConsensusRouterStatus>;
}
impl ConsensusRelays for MdConsensus {
    fn c_relays(&self) -> &TiSlice<RouterStatusIdx, MdConsensusRouterStatus> {
        TiSlice::from_ref(MdConsensus::relays(self))
    }
}
impl ConsensusRelays for NetDir {
    fn c_relays(&self) -> &TiSlice<RouterStatusIdx, MdConsensusRouterStatus> {
        self.consensus.c_relays()
    }
}

/// Configuration for determining when two relays have addresses "too close" in
/// the network.
///
/// Used by [`Relay::in_same_subnet()`].
#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct SubnetConfig {
    /// Consider IPv4 nodes in the same /x to be the same family.
    ///
    /// If this value is 0, all nodes with IPv4 addresses will be in the
    /// same family.  If this value is above 32, then no nodes will be
    /// placed im the same family based on their IPv4 addresses.
    subnets_family_v4: u8,
    /// Consider IPv6 nodes in the same /x to be the same family.
    ///
    /// If this value is 0, all nodes with IPv6 addresses will be in the
    /// same family.  If this value is above 128, then no nodes will be
    /// placed im the same family based on their IPv6 addresses.
    subnets_family_v6: u8,
}

impl Default for SubnetConfig {
    fn default() -> Self {
        Self::new(16, 32)
    }
}

impl SubnetConfig {
    /// Construct a new SubnetConfig from a pair of bit prefix lengths.
    ///
    /// The values are clamped to the appropriate ranges if they are
    /// out-of-bounds.
    pub fn new(subnets_family_v4: u8, subnets_family_v6: u8) -> Self {
        Self {
            subnets_family_v4,
            subnets_family_v6,
        }
    }

    /// Return true if the two addresses in the same subnet, according to this
    /// configuration.
    pub fn addrs_in_same_subnet(&self, a: &IpAddr, b: &IpAddr) -> bool {
        match (a, b) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let bits = self.subnets_family_v4;
                if bits > 32 {
                    return false;
                }
                let a = u32::from_be_bytes(a.octets());
                let b = u32::from_be_bytes(b.octets());
                (a >> (32 - bits)) == (b >> (32 - bits))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let bits = self.subnets_family_v6;
                if bits > 128 {
                    return false;
                }
                let a = u128::from_be_bytes(a.octets());
                let b = u128::from_be_bytes(b.octets());
                (a >> (128 - bits)) == (b >> (128 - bits))
            }
            _ => false,
        }
    }

    /// Return true if any of the addresses in `a` shares a subnet with any of
    /// the addresses in `b`, according to this configuration.
    pub fn any_addrs_in_same_subnet<T, U>(&self, a: &T, b: &U) -> bool
    where
        T: tor_linkspec::HasAddrs,
        U: tor_linkspec::HasAddrs,
    {
        a.addrs().iter().any(|aa| {
            b.addrs()
                .iter()
                .any(|bb| self.addrs_in_same_subnet(&aa.ip(), &bb.ip()))
        })
    }
}

/// An opaque type representing the weight with which a relay or set of
/// relays will be selected for a given role.
///
/// Most users should ignore this type, and just use pick_relay instead.
#[derive(
    Copy,
    Clone,
    Debug,
    derive_more::Add,
    derive_more::Sum,
    derive_more::AddAssign,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
)]
pub struct RelayWeight(u64);

impl RelayWeight {
    /// Try to divide this weight by `rhs`.
    ///
    /// Return a ratio on success, or None on division-by-zero.
    pub fn checked_div(&self, rhs: RelayWeight) -> Option<f64> {
        if rhs.0 == 0 {
            None
        } else {
            Some((self.0 as f64) / (rhs.0 as f64))
        }
    }

    /// Compute a ratio `frac` of this weight.
    ///
    /// Return None if frac is less than zero, since negative weights
    /// are impossible.
    pub fn ratio(&self, frac: f64) -> Option<RelayWeight> {
        let product = (self.0 as f64) * frac;
        if product >= 0.0 && product.is_finite() {
            Some(RelayWeight(product as u64))
        } else {
            None
        }
    }
}

impl From<u64> for RelayWeight {
    fn from(val: u64) -> Self {
        RelayWeight(val)
    }
}

/// An operation for which we might be requesting a hidden service directory.
#[derive(Copy, Clone, Debug, PartialEq)]
// TODO: make this pub(crate) once NetDir::hs_dirs is removed
#[non_exhaustive]
pub enum HsDirOp {
    /// Uploading an onion service descriptor.
    #[cfg(feature = "hs-service")]
    Upload,
    /// Downloading an onion service descriptor.
    Download,
}

/// A view of the Tor directory, suitable for use in building circuits.
///
/// Abstractly, a [`NetDir`] is a set of usable public [`Relay`]s, each of which
/// has its own properties, identity, and correct weighted probability for use
/// under different circumstances.
///
/// A [`NetDir`] is constructed by making a [`PartialNetDir`] from a consensus
/// document, and then adding enough microdescriptors to that `PartialNetDir` so
/// that it can be used to build paths. (Thus, if you have a NetDir, it is
/// definitely adequate to build paths.)
///
/// # "Usable" relays
///
/// Many methods on NetDir are defined in terms of <a name="usable">"Usable"</a> relays.  Unless
/// otherwise stated, a relay is "usable" if it is listed in the consensus,
/// if we have full directory information for that relay (including a
/// microdescriptor), and if that relay does not have any flags indicating that
/// we should never use it. (Currently, `NoEdConsensus` is the only such flag.)
///
/// # Limitations
///
/// The current NetDir implementation assumes fairly strongly that every relay
/// has an Ed25519 identity and an RSA identity, that the consensus is indexed
/// by RSA identities, and that the Ed25519 identities are stored in
/// microdescriptors.
///
/// If these assumptions someday change, then we'll have to revise the
/// implementation.
#[derive(Debug, Clone)]
pub struct NetDir {
    /// A microdescriptor consensus that lists the members of the network,
    /// and maps each one to a 'microdescriptor' that has more information
    /// about it
    consensus: Arc<MdConsensus>,
    /// A map from keys to integer values, distributed in the consensus,
    /// and clamped to certain defaults.
    params: NetParameters,
    /// Map from routerstatus index, to that routerstatus's microdescriptor (if we have one.)
    mds: TiVec<RouterStatusIdx, Option<Arc<Microdesc>>>,
    /// Map from SHA256 of _missing_ microdescriptors to the index of their
    /// corresponding routerstatus.
    rsidx_by_missing: HashMap<MdDigest, RouterStatusIdx>,
    /// Map from ed25519 identity to index of the routerstatus.
    ///
    /// Note that we don't know the ed25519 identity of a relay until
    /// we get the microdescriptor for it, so this won't be filled in
    /// until we get the microdescriptors.
    ///
    /// # Implementation note
    ///
    /// For this field, and for `rsidx_by_rsa`,
    /// it might be cool to have references instead.
    /// But that would make this into a self-referential structure,
    /// which isn't possible in safe rust.
    rsidx_by_ed: HashMap<Ed25519Identity, RouterStatusIdx>,
    /// Map from RSA identity to index of the routerstatus.
    ///
    /// This is constructed at the same time as the NetDir object, so it
    /// can be immutable.
    rsidx_by_rsa: Arc<HashMap<RsaIdentity, RouterStatusIdx>>,

    /// Hash ring(s) describing the onion service directory.
    ///
    /// This is empty in a PartialNetDir, and is filled in before the NetDir is
    /// built.
    //
    // TODO hs: It is ugly to have this exist in a partially constructed state
    // in a PartialNetDir.
    // Ideally, a PartialNetDir would contain only an HsDirs<HsDirParams>,
    // or perhaps nothing at all, here.
    #[cfg(feature = "hs-common")]
    hsdir_rings: Arc<HsDirs<HsDirRing>>,

    /// Weight values to apply to a given relay when deciding how frequently
    /// to choose it for a given role.
    weights: weight::WeightSet,

    #[cfg(feature = "geoip")]
    /// Country codes for each router in our consensus.
    ///
    /// This is indexed by the `RouterStatusIdx` (i.e. a router idx of zero has
    /// the country code at position zero in this array).
    country_codes: Vec<Option<CountryCode>>,
}

/// Collection of hidden service directories (or parameters for them)
///
/// In [`NetDir`] this is used to store the actual hash rings.
/// (But, in a NetDir in a [`PartialNetDir`], it contains [`HsDirRing`]s
/// where only the `params` are populated, and the `ring` is empty.)
///
/// This same generic type is used as the return type from
/// [`HsDirParams::compute`](HsDirParams::compute),
/// where it contains the *parameters* for the primary and secondary rings.
#[derive(Debug, Clone)]
#[cfg(feature = "hs-common")]
pub(crate) struct HsDirs<D> {
    /// The current ring
    ///
    /// It corresponds to the time period containing the `valid-after` time in
    /// the consensus. Its SRV is whatever SRV was most current at the time when
    /// that time period began.
    ///
    /// This is the hash ring that we should use whenever we are fetching an
    /// onion service descriptor.
    current: D,

    /// Secondary rings (based on the parameters for the previous and next time periods)
    ///
    /// Onion services upload to positions on these ring as well, based on how
    /// far into the current time period this directory is, so that
    /// not-synchronized clients can still find their descriptor.
    ///
    /// Note that with the current (2023) network parameters, with
    /// `hsdir_interval = SRV lifetime = 24 hours` at most one of these
    /// secondary rings will be active at a time.  We have two here in order
    /// to conform with a more flexible regime in proposal 342.
    //
    // TODO: hs clients never need this; so I've made it not-present for thm.
    // But does that risk too much with respect to side channels?
    //
    // TODO: Perhaps we should refactor this so that it is clear that these
    // are immutable?  On the other hand, the documentation for this type
    // declares that it is immutable, so we are likely okay.
    //
    // TODO: this `Vec` is only ever 0,1,2 elements.
    // Maybe it should be an ArrayVec or something.
    #[cfg(feature = "hs-service")]
    secondary: Vec<D>,
}

#[cfg(feature = "hs-common")]
impl<D> HsDirs<D> {
    /// Convert an `HsDirs<D>` to `HsDirs<D2>` by mapping each contained `D`
    pub(crate) fn map<D2>(self, mut f: impl FnMut(D) -> D2) -> HsDirs<D2> {
        HsDirs {
            current: f(self.current),
            #[cfg(feature = "hs-service")]
            secondary: self.secondary.into_iter().map(f).collect(),
        }
    }

    /// Iterate over some of the contained hsdirs, according to `secondary`
    ///
    /// The current ring is always included.
    /// Secondary rings are included iff `secondary` and the `hs-service` feature is enabled.
    fn iter_filter_secondary(&self, secondary: bool) -> impl Iterator<Item = &D> {
        let i = iter::once(&self.current);

        // With "hs-service" disabled, there are no secondary rings,
        // so we don't care.
        let _ = secondary;

        #[cfg(feature = "hs-service")]
        let i = chain!(i, self.secondary.iter().filter(move |_| secondary));

        i
    }

    /// Iterate over all the contained hsdirs
    pub(crate) fn iter(&self) -> impl Iterator<Item = &D> {
        self.iter_filter_secondary(true)
    }

    /// Iterate over the hsdirs relevant for `op`
    pub(crate) fn iter_for_op(&self, op: HsDirOp) -> impl Iterator<Item = &D> {
        self.iter_filter_secondary(match op {
            #[cfg(feature = "hs-service")]
            HsDirOp::Upload => true,
            HsDirOp::Download => false,
        })
    }
}

/// An event that a [`NetDirProvider`] can broadcast to indicate that a change in
/// the status of its directory.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumCount, IntoPrimitive, TryFromPrimitive,
)]
#[non_exhaustive]
#[repr(u16)]
pub enum DirEvent {
    /// A new consensus has been received, and has enough information to be
    /// used.
    ///
    /// This event is also broadcast when a new set of consensus parameters is
    /// available, even if that set of parameters comes from a configuration
    /// change rather than from the latest consensus.
    NewConsensus,

    /// New descriptors have been received for the current consensus.
    ///
    /// (This event is _not_ broadcast when receiving new descriptors for a
    /// consensus which is not yet ready to replace the current consensus.)
    NewDescriptors,
}

/// How "timely" must a network directory be?
///
/// This enum is used as an argument when requesting a [`NetDir`] object from
/// [`NetDirProvider`] and other APIs, to specify how recent the information
/// must be in order to be useful.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[allow(clippy::exhaustive_enums)]
pub enum Timeliness {
    /// The network directory must be strictly timely.
    ///
    /// That is, it must be based on a consensus that valid right now, with no
    /// tolerance for skew or consensus problems.
    ///
    /// Avoid using this option if you could use [`Timeliness::Timely`] instead.
    Strict,
    /// The network directory must be roughly timely.
    ///
    /// This is, it must be be based on a consensus that is not _too_ far in the
    /// future, and not _too_ far in the past.
    ///
    /// (The tolerances for "too far" will depend on configuration.)
    ///
    /// This is almost always the option that you want to use.
    Timely,
    /// Any network directory is permissible, regardless of how untimely.
    ///
    /// Avoid using this option if you could use [`Timeliness::Timely`] instead.
    Unchecked,
}

/// An object that can provide [`NetDir`]s, as well as inform consumers when
/// they might have changed.
///
/// It is the responsibility of the implementor of `NetDirProvider`
/// to try to obtain an up-to-date `NetDir`,
/// and continuously to maintain and update it.
///
/// In usual configurations, Arti uses `tor_dirmgr::DirMgr`
/// as its `NetDirProvider`.
pub trait NetDirProvider: UpcastArcNetDirProvider + Send + Sync {
    /// Return a network directory that's live according to the provided
    /// `timeliness`.
    fn netdir(&self, timeliness: Timeliness) -> Result<Arc<NetDir>>;

    /// Return a reasonable netdir for general usage.
    ///
    /// This is an alias for
    /// [`NetDirProvider::netdir`]`(`[`Timeliness::Timely`]`)`.
    fn timely_netdir(&self) -> Result<Arc<NetDir>> {
        self.netdir(Timeliness::Timely)
    }

    /// Return a new asynchronous stream that will receive notification
    /// whenever the consensus has changed.
    ///
    /// Multiple events may be batched up into a single item: each time
    /// this stream yields an event, all you can assume is that the event has
    /// occurred at least once.
    fn events(&self) -> BoxStream<'static, DirEvent>;

    /// Return the latest network parameters.
    ///
    /// If we have no directory, return a reasonable set of defaults.
    fn params(&self) -> Arc<dyn AsRef<NetParameters>>;
}

impl<T> NetDirProvider for Arc<T>
where
    T: NetDirProvider,
{
    fn netdir(&self, timeliness: Timeliness) -> Result<Arc<NetDir>> {
        self.deref().netdir(timeliness)
    }

    fn timely_netdir(&self) -> Result<Arc<NetDir>> {
        self.deref().timely_netdir()
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        self.deref().events()
    }

    fn params(&self) -> Arc<dyn AsRef<NetParameters>> {
        self.deref().params()
    }
}

/// Helper trait: allows any `Arc<X>` to be upcast to a `Arc<dyn
/// NetDirProvider>` if X is an implementation or supertrait of NetDirProvider.
///
/// This trait exists to work around a limitation in rust: when trait upcasting
/// coercion is stable, this will be unnecessary.
///
/// The Rust tracking issue is <https://github.com/rust-lang/rust/issues/65991>.
pub trait UpcastArcNetDirProvider {
    /// Return a view of this object as an `Arc<dyn NetDirProvider>`
    fn upcast_arc<'a>(self: Arc<Self>) -> Arc<dyn NetDirProvider + 'a>
    where
        Self: 'a;
}

impl<T> UpcastArcNetDirProvider for T
where
    T: NetDirProvider + Sized,
{
    fn upcast_arc<'a>(self: Arc<Self>) -> Arc<dyn NetDirProvider + 'a>
    where
        Self: 'a,
    {
        self
    }
}

impl AsRef<NetParameters> for NetDir {
    fn as_ref(&self) -> &NetParameters {
        self.params()
    }
}

/// A partially build NetDir -- it can't be unwrapped until it has
/// enough information to build safe paths.
#[derive(Debug, Clone)]
pub struct PartialNetDir {
    /// The netdir that's under construction.
    netdir: NetDir,

    /// The previous netdir, if we had one
    ///
    /// Used as a cache, so we can reuse information
    #[cfg(feature = "hs-common")]
    prev_netdir: Option<Arc<NetDir>>,
}

/// A view of a relay on the Tor network, suitable for building circuits.
// TODO: This should probably be a more specific struct, with a trait
// that implements it.
#[derive(Clone)]
pub struct Relay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MdConsensusRouterStatus,
    /// A microdescriptor for this relay.
    md: &'a Microdesc,
    /// The country code this relay is in, if we know one.
    #[cfg(feature = "geoip")]
    cc: Option<CountryCode>,
}

/// A relay that we haven't checked for validity or usability in
/// routing.
#[derive(Debug)]
pub struct UncheckedRelay<'a> {
    /// A router descriptor for this relay.
    rs: &'a netstatus::MdConsensusRouterStatus,
    /// A microdescriptor for this relay, if there is one.
    md: Option<&'a Microdesc>,
    /// The country code this relay is in, if we know one.
    #[cfg(feature = "geoip")]
    cc: Option<CountryCode>,
}

/// A partial or full network directory that we can download
/// microdescriptors for.
pub trait MdReceiver {
    /// Return an iterator over the digests for all of the microdescriptors
    /// that this netdir is missing.
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_>;
    /// Add a microdescriptor to this netdir, if it was wanted.
    ///
    /// Return true if it was indeed wanted.
    fn add_microdesc(&mut self, md: Microdesc) -> bool;
    /// Return the number of missing microdescriptors.
    fn n_missing(&self) -> usize;
}

impl PartialNetDir {
    /// Create a new PartialNetDir with a given consensus, and no
    /// microdescriptors loaded.
    ///
    /// If `replacement_params` is provided, override network parameters from
    /// the consensus with those from `replacement_params`.
    pub fn new(
        consensus: MdConsensus,
        replacement_params: Option<&netstatus::NetParams<i32>>,
    ) -> Self {
        Self::new_inner(
            consensus,
            replacement_params,
            #[cfg(feature = "geoip")]
            None,
        )
    }

    /// Create a new PartialNetDir with GeoIP support.
    ///
    /// This does the same thing as `new()`, except the provided GeoIP database is used to add
    /// country codes to relays.
    #[cfg(feature = "geoip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "geoip")))]
    pub fn new_with_geoip(
        consensus: MdConsensus,
        replacement_params: Option<&netstatus::NetParams<i32>>,
        geoip_db: &GeoipDb,
    ) -> Self {
        Self::new_inner(consensus, replacement_params, Some(geoip_db))
    }

    /// Implementation of the `new()` functions.
    fn new_inner(
        consensus: MdConsensus,
        replacement_params: Option<&netstatus::NetParams<i32>>,
        #[cfg(feature = "geoip")] geoip_db: Option<&GeoipDb>,
    ) -> Self {
        let mut params = NetParameters::default();

        // (We ignore unrecognized options here, since they come from
        // the consensus, and we don't expect to recognize everything
        // there.)
        let _ = params.saturating_update(consensus.params().iter());

        // Now see if the user has any parameters to override.
        // (We have to do this now, or else changes won't be reflected in our
        // weights.)
        if let Some(replacement) = replacement_params {
            for u in params.saturating_update(replacement.iter()) {
                warn!("Unrecognized option: override_net_params.{}", u);
            }
        }

        // Compute the weights we'll want to use for these relays.
        let weights = weight::WeightSet::from_consensus(&consensus, &params);

        let n_relays = consensus.c_relays().len();

        let rsidx_by_missing = consensus
            .c_relays()
            .iter_enumerated()
            .map(|(rsidx, rs)| (*rs.md_digest(), rsidx))
            .collect();

        let rsidx_by_rsa = consensus
            .c_relays()
            .iter_enumerated()
            .map(|(rsidx, rs)| (*rs.rsa_identity(), rsidx))
            .collect();

        #[cfg(feature = "geoip")]
        let country_codes = if let Some(db) = geoip_db {
            consensus
                .c_relays()
                .iter()
                .map(|rs| {
                    let ret = db
                        .lookup_country_code_multi(rs.addrs().iter().map(|x| x.ip()))
                        .cloned();
                    ret
                })
                .collect()
        } else {
            Default::default()
        };

        #[cfg(feature = "hs-common")]
        let hsdir_rings = Arc::new({
            let params = HsDirParams::compute(&consensus, &params).expect("Invalid consensus!");
            // TODO: It's a bit ugly to use expect above, but this function does
            // not return a Result. On the other hand, the error conditions under which
            // HsDirParams::compute can return Err are _very_ narrow and hard to
            // hit; see documentation in that function.  As such, we probably
            // don't need to have this return a Result.

            params.map(HsDirRing::empty_from_params)
        });

        let netdir = NetDir {
            consensus: Arc::new(consensus),
            params,
            mds: vec![None; n_relays].into(),
            rsidx_by_missing,
            rsidx_by_rsa: Arc::new(rsidx_by_rsa),
            rsidx_by_ed: HashMap::with_capacity(n_relays),
            #[cfg(feature = "hs-common")]
            hsdir_rings,
            weights,
            #[cfg(feature = "geoip")]
            country_codes,
        };

        PartialNetDir {
            netdir,
            #[cfg(feature = "hs-common")]
            prev_netdir: None,
        }
    }

    /// Return the declared lifetime of this PartialNetDir.
    pub fn lifetime(&self) -> &netstatus::Lifetime {
        self.netdir.lifetime()
    }

    /// Record a previous netdir, which can be used for reusing cached information
    //
    // Fills in as many missing microdescriptors as possible in this
    // netdir, using the microdescriptors from the previous netdir.
    //
    // With HS enabled, stores the netdir for reuse of relay hash ring index values.
    #[allow(clippy::needless_pass_by_value)] // prev might, or might not, be stored
    pub fn fill_from_previous_netdir(&mut self, prev: Arc<NetDir>) {
        for md in prev.mds.iter().flatten() {
            self.netdir.add_arc_microdesc(md.clone());
        }

        #[cfg(feature = "hs-common")]
        {
            self.prev_netdir = Some(prev);
        }
    }

    /// Compute the hash ring(s) for this NetDir
    #[cfg(feature = "hs-common")]
    fn compute_rings(&mut self) {
        let params = HsDirParams::compute(&self.netdir.consensus, &self.netdir.params)
            .expect("Invalid consensus");
        // TODO: see TODO by similar expect in new()

        self.netdir.hsdir_rings =
            Arc::new(params.map(|params| {
                HsDirRing::compute(params, &self.netdir, self.prev_netdir.as_deref())
            }));
    }

    /// Return true if this are enough information in this directory
    /// to build multihop paths.
    pub fn have_enough_paths(&self) -> bool {
        self.netdir.have_enough_paths()
    }
    /// If this directory has enough information to build multihop
    /// circuits, return it.
    pub fn unwrap_if_sufficient(
        #[allow(unused_mut)] mut self,
    ) -> std::result::Result<NetDir, PartialNetDir> {
        if self.netdir.have_enough_paths() {
            #[cfg(feature = "hs-common")]
            self.compute_rings();
            Ok(self.netdir)
        } else {
            Err(self)
        }
    }
}

impl MdReceiver for PartialNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        self.netdir.missing_microdescs()
    }
    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        self.netdir.add_microdesc(md)
    }
    fn n_missing(&self) -> usize {
        self.netdir.n_missing()
    }
}

impl NetDir {
    /// Return the declared lifetime of this NetDir.
    pub fn lifetime(&self) -> &netstatus::Lifetime {
        self.consensus.lifetime()
    }

    /// Add `md` to this NetDir.
    ///
    /// Return true if we wanted it, and false otherwise.
    fn add_arc_microdesc(&mut self, md: Arc<Microdesc>) -> bool {
        if let Some(rsidx) = self.rsidx_by_missing.remove(md.digest()) {
            assert_eq!(self.c_relays()[rsidx].md_digest(), md.digest());

            // There should never be two approved MDs in the same
            // consensus listing the same ID... but if there is,
            // we'll let the most recent one win.
            self.rsidx_by_ed.insert(*md.ed25519_id(), rsidx);

            // Happy path: we did indeed want this one.
            self.mds[rsidx] = Some(md);

            // Save some space in the missing-descriptor list.
            if self.rsidx_by_missing.len() < self.rsidx_by_missing.capacity() / 4 {
                self.rsidx_by_missing.shrink_to_fit();
            }

            return true;
        }

        // Either we already had it, or we never wanted it at all.
        false
    }

    /// Construct a (possibly invalid) Relay object from a routerstatus and its
    /// index within the consensus.
    fn relay_from_rs_and_rsidx<'a>(
        &'a self,
        rs: &'a netstatus::MdConsensusRouterStatus,
        rsidx: RouterStatusIdx,
    ) -> UncheckedRelay<'a> {
        debug_assert_eq!(self.c_relays()[rsidx].rsa_identity(), rs.rsa_identity());
        let md = self.mds[rsidx].as_deref();
        if let Some(md) = md {
            debug_assert_eq!(rs.md_digest(), md.digest());
        }

        UncheckedRelay {
            rs,
            md,
            #[cfg(feature = "geoip")]
            cc: self.country_codes.get(rsidx.0).copied().flatten(),
        }
    }

    /// Return the value of the hsdir_n_replicas param.
    #[cfg(feature = "hs-common")]
    fn n_replicas(&self) -> u8 {
        self.params
            .hsdir_n_replicas
            .get()
            .try_into()
            .expect("BoundedInt did not enforce bounds")
    }

    /// Return the spread parameter for the specified `op`.
    #[cfg(feature = "hs-common")]
    fn spread(&self, op: HsDirOp) -> usize {
        let spread = match op {
            HsDirOp::Download => self.params.hsdir_spread_fetch,
            #[cfg(feature = "hs-service")]
            HsDirOp::Upload => self.params.hsdir_spread_store,
        };

        spread
            .get()
            .try_into()
            .expect("BoundedInt did not enforce bounds!")
    }

    /// Select `spread` hsdir relays for the specified `hsid` from a given `ring`.
    ///
    /// Algorithm:
    ///
    /// for idx in 1..=n_replicas:
    ///       - let H = hsdir_ring::onion_service_index(id, replica, rand,
    ///         period).
    ///       - Find the position of H within hsdir_ring.
    ///       - Take elements from hsdir_ring starting at that position,
    ///         adding them to Dirs until we have added `spread` new elements
    ///         that were not there before.
    #[cfg(feature = "hs-common")]
    fn select_hsdirs<'h, 'r: 'h>(
        &'r self,
        hsid: HsBlindId,
        ring: &'h HsDirRing,
        spread: usize,
    ) -> impl Iterator<Item = Relay<'r>> + 'h {
        let n_replicas = self.n_replicas();

        (1..=n_replicas) // 1-indexed !
            .flat_map({
                let mut selected_nodes = HashSet::new();

                move |replica: u8| {
                    let hsdir_idx = hsdir_ring::service_hsdir_index(&hsid, replica, ring.params());

                    let items = ring
                        .ring_items_at(hsdir_idx, spread, |(hsdir_idx, _)| {
                            // According to rend-spec 2.2.3:
                            //                                                  ... If any of those
                            // nodes have already been selected for a lower-numbered replica of the
                            // service, any nodes already chosen are disregarded (i.e. skipped over)
                            // when choosing a replica's hsdir_spread_store nodes.
                            selected_nodes.insert(*hsdir_idx)
                        })
                        .collect::<Vec<_>>();

                    items
                }
            })
            .filter_map(move |(_hsdir_idx, rs_idx)| {
                // This ought not to be None but let's not panic or bail if it is
                self.relay_by_rs_idx(*rs_idx)
            })
    }

    /// Replace the overridden parameters in this netdir with `new_replacement`.
    ///
    /// After this function is done, the netdir's parameters will be those in
    /// the consensus, overridden by settings from `new_replacement`.  Any
    /// settings in the old replacement parameters will be discarded.
    pub fn replace_overridden_parameters(&mut self, new_replacement: &netstatus::NetParams<i32>) {
        // TODO(nickm): This is largely duplicate code from PartialNetDir::new().
        let mut new_params = NetParameters::default();
        let _ = new_params.saturating_update(self.consensus.params().iter());
        for u in new_params.saturating_update(new_replacement.iter()) {
            warn!("Unrecognized option: override_net_params.{}", u);
        }

        self.params = new_params;
    }

    /// Return an iterator over all Relay objects, including invalid ones
    /// that we can't use.
    pub fn all_relays(&self) -> impl Iterator<Item = UncheckedRelay<'_>> {
        // TODO: I'd like if we could memoize this so we don't have to
        // do so many hashtable lookups.
        self.c_relays()
            .iter_enumerated()
            .map(move |(rsidx, rs)| self.relay_from_rs_and_rsidx(rs, rsidx))
    }
    /// Return an iterator over all [usable](NetDir#usable) Relays.
    pub fn relays(&self) -> impl Iterator<Item = Relay<'_>> {
        self.all_relays().filter_map(UncheckedRelay::into_relay)
    }

    /// Look up a relay's `MicroDesc` by its `RouterStatusIdx`
    #[cfg_attr(not(feature = "hs-common"), allow(dead_code))]
    pub(crate) fn md_by_rsidx(&self, rsidx: RouterStatusIdx) -> Option<&Microdesc> {
        self.mds.get(rsidx)?.as_deref()
    }

    /// Return a relay matching a given identity, if we have a
    /// _usable_ relay with that key.
    ///
    /// (Does not return [unusable](NetDir#usable) relays.)
    ///
    ///
    /// Note that a `None` answer is not always permanent: if a microdescriptor
    /// is subsequently added for a relay with this ID, the ID may become usable
    /// even if it was not usable before.
    pub fn by_id<'a, T>(&self, id: T) -> Option<Relay<'_>>
    where
        T: Into<RelayIdRef<'a>> + ?Sized,
    {
        let id = id.into();
        let answer = match id {
            RelayIdRef::Ed25519(ed25519) => {
                let rsidx = *self.rsidx_by_ed.get(ed25519)?;
                let rs = self.c_relays().get(rsidx).expect("Corrupt index");

                self.relay_from_rs_and_rsidx(rs, rsidx).into_relay()?
            }
            RelayIdRef::Rsa(rsa) => self
                .by_rsa_id_unchecked(rsa)
                .and_then(UncheckedRelay::into_relay)?,
            other_type => self.relays().find(|r| r.has_identity(other_type))?,
        };
        assert!(answer.has_identity(id));
        Some(answer)
    }

    /// Obtain a `Relay` given a `RouterStatusIdx`
    ///
    /// Differs from `relay_from_rs_and_rsi` as follows:
    ///  * That function expects the caller to already have an `MdConsensusRouterStatus`;
    ///    it checks with `debug_assert` that the relay in the netdir matches.
    ///  * That function panics if the `RouterStatusIdx` is invalid; this one returns `None`.
    ///  * That function returns an `UncheckedRelay`; this one a `Relay`.
    ///
    /// `None` could be returned here, even with a valid `rsi`,
    /// if `rsi` refers to an [unusable](NetDir#usable) relay.
    #[cfg_attr(not(feature = "hs-common"), allow(dead_code))]
    pub(crate) fn relay_by_rs_idx(&self, rs_idx: RouterStatusIdx) -> Option<Relay<'_>> {
        let rs = self.c_relays().get(rs_idx)?;
        let md = self.mds.get(rs_idx)?.as_deref();
        UncheckedRelay {
            rs,
            md,
            #[cfg(feature = "geoip")]
            cc: self.country_codes.get(rs_idx.0).copied().flatten(),
        }
        .into_relay()
    }

    /// Return a relay with the same identities as those in `target`, if one
    /// exists.
    ///
    /// Does not return [unusable](NetDir#usable) relays.
    ///
    /// # Limitations
    ///
    /// This will be very slow if `target` does not have an Ed25519 or RSA
    /// identity.
    pub fn by_ids<T>(&self, target: &T) -> Option<Relay<'_>>
    where
        T: HasRelayIds + ?Sized,
    {
        let mut identities = target.identities();
        // Don't try if there are no identities.
        let first_id = identities.next()?;

        // Since there is at most one relay with each given ID type,
        // we only need to check the first relay we find.
        let candidate = self.by_id(first_id)?;
        if identities.all(|wanted_id| candidate.has_identity(wanted_id)) {
            Some(candidate)
        } else {
            None
        }
    }

    /// Check whether there is a relay that has at least one identity from
    /// `target`, and which _could_ have every identity from `target`.
    /// If so, return such a relay.
    ///
    /// Return `Ok(None)` if we did not find a relay with any identity from `target`.
    ///
    /// Return `RelayLookupError::Impossible` if we found a relay with at least
    /// one identity from `target`, but that relay's other identities contradict
    /// what we learned from `target`.
    ///
    /// Does not return [unusable](NetDir#usable) relays.
    ///
    /// (This function is only useful if you need to distinguish the
    /// "impossible" case from the "no such relay known" case.)
    ///
    /// # Limitations
    ///
    /// This will be very slow if `target` does not have an Ed25519 or RSA
    /// identity.
    //
    // TODO HS: This function could use a better name.
    //
    // TODO: We could remove the feature restriction here once we think this API is
    // stable.
    #[cfg(feature = "hs-common")]
    pub fn by_ids_detailed<T>(
        &self,
        target: &T,
    ) -> std::result::Result<Option<Relay<'_>>, RelayLookupError>
    where
        T: HasRelayIds + ?Sized,
    {
        let candidate = target
            .identities()
            // Find all the relays that share any identity with this set of identities.
            .filter_map(|id| self.by_id(id))
            // We might find the same relay more than once under a different
            // identity, so we remove the duplicates.
            //
            // Since there is at most one relay per rsa identity per consensus,
            // this is a true uniqueness check under current construction rules.
            .unique_by(|r| r.rs.rsa_identity())
            // If we find two or more distinct relays, then have a contradiction.
            .at_most_one()
            .map_err(|_| RelayLookupError::Impossible)?;

        // If we have no candidate, return None early.
        let candidate = match candidate {
            Some(relay) => relay,
            None => return Ok(None),
        };

        // Now we know we have a single candidate.  Make sure that it does not have any
        // identity that does not match the target.
        if target
            .identities()
            .all(|wanted_id| match candidate.identity(wanted_id.id_type()) {
                None => true,
                Some(id) => id == wanted_id,
            })
        {
            Ok(Some(candidate))
        } else {
            Err(RelayLookupError::Impossible)
        }
    }

    /// Return a boolean if this consensus definitely has (or does not have) a
    /// relay matching the listed identities.
    ///
    ///
    /// If we can't yet tell for sure, return None. Once function has returned
    /// `Some(b)`, it will always return that value for the same `ed_id` and
    /// `rsa_id` on this `NetDir`.  A `None` answer may later become `Some(b)`
    /// if a microdescriptor arrives.
    fn id_pair_listed(&self, ed_id: &Ed25519Identity, rsa_id: &RsaIdentity) -> Option<bool> {
        let r = self.by_rsa_id_unchecked(rsa_id);
        match r {
            Some(unchecked) => {
                if !unchecked.rs.ed25519_id_is_usable() {
                    return Some(false);
                }
                // If md is present, then it's listed iff we have the right
                // ed id.  Otherwise we don't know if it's listed.
                unchecked.md.map(|md| md.ed25519_id() == ed_id)
            }
            None => {
                // Definitely not listed.
                Some(false)
            }
        }
    }

    /// As `id_pair_listed`, but check whether a relay exists (or may exist)
    /// with the same identities as those in `target`.
    ///
    /// # Limitations
    ///
    /// This can be inefficient if the target does not have both an ed25519 and
    /// an rsa identity key.
    pub fn ids_listed<T>(&self, target: &T) -> Option<bool>
    where
        T: HasRelayIds + ?Sized,
    {
        let rsa_id = target.rsa_identity();
        let ed25519_id = target.ed_identity();

        // TODO: If we later support more identity key types, this will
        // become incorrect.  This assertion might help us recognize that case.
        const_assert!(RelayIdType::COUNT == 2);

        match (rsa_id, ed25519_id) {
            (Some(r), Some(e)) => self.id_pair_listed(e, r),
            (Some(r), None) => Some(self.rsa_id_is_listed(r)),
            (None, Some(e)) => {
                if self.rsidx_by_ed.contains_key(e) {
                    Some(true)
                } else {
                    None
                }
            }
            (None, None) => None,
        }
    }

    /// Return a (possibly [unusable](NetDir#usable)) relay with a given RSA identity.
    ///
    /// This API can be used to find information about a relay that is listed in
    /// the current consensus, even if we don't yet have enough information
    /// (like a microdescriptor) about the relay to use it.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
    fn by_rsa_id_unchecked(&self, rsa_id: &RsaIdentity) -> Option<UncheckedRelay<'_>> {
        let rsidx = *self.rsidx_by_rsa.get(rsa_id)?;
        let rs = self.c_relays().get(rsidx).expect("Corrupt index");
        assert_eq!(rs.rsa_identity(), rsa_id);
        Some(self.relay_from_rs_and_rsidx(rs, rsidx))
    }
    /// Return the relay with a given RSA identity, if we have one
    /// and it is [usable](NetDir#usable).
    fn by_rsa_id(&self, rsa_id: &RsaIdentity) -> Option<Relay<'_>> {
        self.by_rsa_id_unchecked(rsa_id)?.into_relay()
    }
    /// Return true if `rsa_id` is listed in this directory, even if it isn't
    /// currently usable.
    ///
    /// (An "[unusable](NetDir#usable)" relay in this context is one for which we don't have full
    /// directory information.)
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental-api")))]
    fn rsa_id_is_listed(&self, rsa_id: &RsaIdentity) -> bool {
        self.by_rsa_id_unchecked(rsa_id).is_some()
    }

    /// List the hsdirs in this NetDir, that should be in the HSDir rings
    ///
    /// The results are not returned in any particular order.
    #[cfg(feature = "hs-common")]
    fn all_hsdirs(&self) -> impl Iterator<Item = (RouterStatusIdx, Relay<'_>)> {
        self.c_relays().iter_enumerated().filter_map(|(rsidx, rs)| {
            let relay = self.relay_from_rs_and_rsidx(rs, rsidx);
            relay.is_hsdir_for_ring().then_some(())?;
            let relay = relay.into_relay()?;
            Some((rsidx, relay))
        })
    }

    /// Return the parameters from the consensus, clamped to the
    /// correct ranges, with defaults filled in.
    ///
    /// NOTE: that unsupported parameters aren't returned here; only those
    /// values configured in the `params` module are available.
    pub fn params(&self) -> &NetParameters {
        &self.params
    }

    /// Return a [`ProtoStatus`](netstatus::ProtoStatus) that lists the
    /// network's current requirements and recommendations for the list of
    /// protocols that every relay must implement.
    //
    // TODO HS: I am not sure this is the right API; other alternatives would be:
    //    * To expose the _required_ relay protocol list instead (since that's all that
    //      onion service implementations need).
    //    * To expose the client protocol list as well (for symmetry).
    //    * To expose the MdConsensus instead (since that's more general, although
    //      it restricts the future evolution of this API).
    //
    // I think that this is a reasonably good compromise for now, but I'm going
    // to put it behind the `hs-common` feature to give us time to consider more.
    #[cfg(feature = "hs-common")]
    pub fn relay_protocol_status(&self) -> &netstatus::ProtoStatus {
        self.consensus.relay_protocol_status()
    }

    /// Return weighted the fraction of relays we can use.  We only
    /// consider relays that match the predicate `usable`.  We weight
    /// this bandwidth according to the provided `role`.
    ///
    /// If _no_ matching relays in the consensus have a nonzero
    /// weighted bandwidth value, we fall back to looking at the
    /// unweighted fraction of matching relays.
    ///
    /// If there are no matching relays in the consensus, we return 0.0.
    fn frac_for_role<'a, F>(&'a self, role: WeightRole, usable: F) -> f64
    where
        F: Fn(&UncheckedRelay<'a>) -> bool,
    {
        let mut total_weight = 0_u64;
        let mut have_weight = 0_u64;
        let mut have_count = 0_usize;
        let mut total_count = 0_usize;

        for r in self.all_relays() {
            if !usable(&r) {
                continue;
            }
            let w = self.weights.weight_rs_for_role(r.rs, role);
            total_weight += w;
            total_count += 1;
            if r.is_usable() {
                have_weight += w;
                have_count += 1;
            }
        }

        if total_weight > 0 {
            // The consensus lists some weighted bandwidth so return the
            // fraction of the weighted bandwidth for which we have
            // descriptors.
            (have_weight as f64) / (total_weight as f64)
        } else if total_count > 0 {
            // The consensus lists no weighted bandwidth for these relays,
            // but at least it does list relays. Return the fraction of
            // relays for which it we have descriptors.
            (have_count as f64) / (total_count as f64)
        } else {
            // There are no relays of this kind in the consensus.  Return
            // 0.0, to avoid dividing by zero and giving NaN.
            0.0
        }
    }
    /// Return the estimated fraction of possible paths that we have
    /// enough microdescriptors to build.
    fn frac_usable_paths(&self) -> f64 {
        let f_g = self.frac_for_role(WeightRole::Guard, |u| u.rs.is_flagged_guard());
        let f_m = self.frac_for_role(WeightRole::Middle, |_| true);
        let f_e = if self.all_relays().any(|u| u.rs.is_flagged_exit()) {
            self.frac_for_role(WeightRole::Exit, |u| u.rs.is_flagged_exit())
        } else {
            // If there are no exits at all, we use f_m here.
            f_m
        };
        f_g * f_m * f_e
    }
    /// Return true if there is enough information in this NetDir to build
    /// multihop circuits.

    fn have_enough_paths(&self) -> bool {
        // TODO-A001: This should check for our guards as well, and
        // make sure that if they're listed in the consensus, we have
        // the descriptors for them.

        // If we can build a randomly chosen path with at least this
        // probability, we know enough information to participate
        // on the network.

        let min_frac_paths: f64 = self.params().min_circuit_path_threshold.as_fraction();

        // What fraction of paths can we build?
        let available = self.frac_usable_paths();

        available >= min_frac_paths
    }
    /// Choose a relay at random.
    ///
    /// Each relay is chosen with probability proportional to its weight
    /// in the role `role`, and is only selected if the predicate `usable`
    /// returns true for it.
    ///
    /// This function returns None if (and only if) there are no relays
    /// with nonzero weight where `usable` returned true.
    //
    // TODO this API, with the `usable` closure, invites mistakes where we fail to
    // check conditions that are implied by the role we have selected for the relay:
    // call sites must include a call to `Relay::is_polarity_inverter()` or whatever.
    // IMO the `WeightRole` ought to imply a condition (and it should therefore probably
    // be renamed.)  -Diziet
    pub fn pick_relay<'a, R, P>(
        &'a self,
        rng: &mut R,
        role: WeightRole,
        usable: P,
    ) -> Option<Relay<'a>>
    where
        R: rand::Rng,
        P: FnMut(&Relay<'a>) -> bool,
    {
        let relays: Vec<_> = self.relays().filter(usable).collect();
        // This algorithm uses rand::distributions::WeightedIndex, and uses
        // gives O(n) time and space  to build the index, plus O(log n)
        // sampling time.
        //
        // We might be better off building a WeightedIndex in advance
        // for each `role`, and then sampling it repeatedly until we
        // get a relay that satisfies `usable`.  Or we might not --
        // that depends heavily on the actual particulars of our
        // inputs.  We probably shouldn't make any changes there
        // unless profiling tells us that this function is in a hot
        // path.
        //
        // The C Tor sampling implementation goes through some trouble
        // here to try to make its path selection constant-time.  I
        // believe that there is no actual remotely exploitable
        // side-channel here however.  It could be worth analyzing in
        // the future.
        //
        // This code will give the wrong result if the total of all weights
        // can exceed u64::MAX.  We make sure that can't happen when we
        // set up `self.weights`.
        relays[..]
            .choose_weighted(rng, |r| self.weights.weight_rs_for_role(r.rs, role))
            .ok()
            .cloned()
    }

    /// Choose `n` relay at random.
    ///
    /// Each relay is chosen with probability proportional to its weight
    /// in the role `role`, and is only selected if the predicate `usable`
    /// returns true for it.
    ///
    /// Relays are chosen without replacement: no relay will be
    /// returned twice. Therefore, the resulting vector may be smaller
    /// than `n` if we happen to have fewer than `n` appropriate relays.
    ///
    /// This function returns an empty vector if (and only if) there
    /// are no relays with nonzero weight where `usable` returned
    /// true.
    pub fn pick_n_relays<'a, R, P>(
        &'a self,
        rng: &mut R,
        n: usize,
        role: WeightRole,
        usable: P,
    ) -> Vec<Relay<'a>>
    where
        R: rand::Rng,
        P: FnMut(&Relay<'a>) -> bool,
    {
        let relays: Vec<_> = self.relays().filter(usable).collect();
        // NOTE: See discussion in pick_relay().
        let mut relays = match relays[..].choose_multiple_weighted(rng, n, |r| {
            self.weights.weight_rs_for_role(r.rs, role) as f64
        }) {
            Err(_) => Vec::new(),
            Ok(iter) => iter.map(Relay::clone).collect(),
        };
        relays.shuffle(rng);
        relays
    }

    /// Compute the weight with which `relay` will be selected for a given
    /// `role`.
    pub fn relay_weight<'a>(&'a self, relay: &Relay<'a>, role: WeightRole) -> RelayWeight {
        RelayWeight(self.weights.weight_rs_for_role(relay.rs, role))
    }

    /// Compute the total weight with which any relay matching `usable`
    /// will be selected for a given `role`.
    ///
    /// Note: because this function is used to assess the total
    /// properties of the consensus, the `usable` predicate takes a
    /// [`RouterStatus`] rather than a [`Relay`].
    pub fn total_weight<P>(&self, role: WeightRole, usable: P) -> RelayWeight
    where
        P: Fn(&UncheckedRelay<'_>) -> bool,
    {
        self.all_relays()
            .filter_map(|unchecked| {
                if usable(&unchecked) {
                    Some(RelayWeight(
                        self.weights.weight_rs_for_role(unchecked.rs, role),
                    ))
                } else {
                    None
                }
            })
            .sum()
    }

    /// Compute the weight with which a relay with ID `rsa_id` would be
    /// selected for a given `role`.
    ///
    /// Note that weight returned by this function assumes that the
    /// relay with that ID is actually [usable](NetDir#usable); if it isn't usable,
    /// then other weight-related functions will call its weight zero.
    pub fn weight_by_rsa_id(&self, rsa_id: &RsaIdentity, role: WeightRole) -> Option<RelayWeight> {
        self.by_rsa_id_unchecked(rsa_id)
            .map(|unchecked| RelayWeight(self.weights.weight_rs_for_role(unchecked.rs, role)))
    }

    /// Return all relays in this NetDir known to be in the same family as
    /// `relay`.
    ///
    /// This list of members will **not** necessarily include `relay` itself.
    ///
    /// # Limitations
    ///
    /// Two relays only belong to the same family if _each_ relay
    /// claims to share a family with the other.  But if we are
    /// missing a microdescriptor for one of the relays listed by this
    /// relay, we cannot know whether it acknowledges family
    /// membership with this relay or not.  Therefore, this function
    /// can omit family members for which there is not (as yet) any
    /// Relay object.
    pub fn known_family_members<'a>(
        &'a self,
        relay: &'a Relay<'a>,
    ) -> impl Iterator<Item = Relay<'a>> {
        let relay_rsa_id = relay.rsa_id();
        relay.md.family().members().filter_map(move |other_rsa_id| {
            self.by_rsa_id(other_rsa_id)
                .filter(|other_relay| other_relay.md.family().contains(relay_rsa_id))
        })
    }

    /// Return the current hidden service directory "time period".
    ///
    /// Specifically, this returns the time period that contains the beginning
    /// of the validity period of this `NetDir`'s consensus.  That time period
    /// is the one we use when acting as an hidden service client.
    #[cfg(feature = "hs-common")]
    pub fn hs_time_period(&self) -> TimePeriod {
        self.hsdir_rings.current.time_period()
    }

    /// Return the [`HsDirParams`] of all the relevant hidden service directory "time periods"
    ///
    /// This includes the current time period (as from
    /// [`.hs_time_period`](NetDir::hs_time_period))
    /// plus additional time periods that we publish descriptors for when we are
    /// acting as a hidden service.
    #[cfg(feature = "hs-service")]
    pub fn hs_all_time_periods(&self) -> Vec<HsDirParams> {
        self.hsdir_rings
            .iter()
            .map(|r| r.params().clone())
            .collect()
    }

    /// Return the relays in this network directory that will be used as hidden service directories
    ///
    /// These are suitable to retrieve a given onion service's descriptor at a given time period.
    #[cfg(feature = "hs-common")]
    pub fn hs_dirs_download<'r, R>(
        &'r self,
        hsid: HsBlindId,
        period: TimePeriod,
        rng: &mut R,
    ) -> std::result::Result<Vec<Relay<'r>>, Bug>
    where
        R: rand::Rng,
    {
        // Algorithm:
        //
        // 1. Determine which HsDirRing to use, based on the time period.
        // 2. Find the shared random value that's associated with that HsDirRing.
        // 3. Choose spread = the parameter `hsdir_spread_fetch`
        // 4. Let n_replicas = the parameter `hsdir_n_replicas`.
        // 5. Initialize Dirs = []
        // 6. for idx in 1..=n_replicas:
        //       - let H = hsdir_ring::onion_service_index(id, replica, rand,
        //         period).
        //       - Find the position of H within hsdir_ring.
        //       - Take elements from hsdir_ring starting at that position,
        //         adding them to Dirs until we have added `spread` new elements
        //         that were not there before.
        // 7. Shuffle Dirs
        // 8. return Dirs.

        let spread = self.spread(HsDirOp::Download);

        // When downloading, only look at relays on current ring.
        let ring = &self.hsdir_rings.current;

        if ring.params().time_period != period {
            return Err(internal!(
                "our current ring is not associated with the requested time period!"
            ));
        }

        let mut hs_dirs = self.select_hsdirs(hsid, ring, spread).collect_vec();

        // When downloading, the order of the returned relays is random.
        hs_dirs.shuffle(rng);

        Ok(hs_dirs)
    }

    /// Return the relays in this network directory that will be used as hidden service directories
    ///
    /// Returns the relays that are suitable for storing a given onion service's descriptors at the
    /// given time period.
    #[cfg(feature = "hs-service")]
    pub fn hs_dirs_upload(
        &self,
        hsid: HsBlindId,
        period: TimePeriod,
    ) -> std::result::Result<impl Iterator<Item = Relay<'_>>, Bug> {
        // Algorithm:
        //
        // 1. Choose spread = the parameter `hsdir_spread_store`
        // 2. Determine which HsDirRing to use, based on the time period.
        // 3. Find the shared random value that's associated with that HsDirRing.
        // 4. Let n_replicas = the parameter `hsdir_n_replicas`.
        // 5. Initialize Dirs = []
        // 6. for idx in 1..=n_replicas:
        //       - let H = hsdir_ring::onion_service_index(id, replica, rand,
        //         period).
        //       - Find the position of H within hsdir_ring.
        //       - Take elements from hsdir_ring starting at that position,
        //         adding them to Dirs until we have added `spread` new elements
        //         that were not there before.
        // 3. return Dirs.
        let spread = self.spread(HsDirOp::Upload);

        // For each HsBlindId, determine which HsDirRing to use.
        let rings = self
            .hsdir_rings
            .iter()
            .filter_map(move |ring| {
                // Make sure the ring matches the TP of the hsid it's matched with.
                (ring.params().time_period == period).then_some((ring, hsid, period))
            })
            .collect::<Vec<_>>();

        // The specified period should have an associated ring.
        if !rings.iter().any(|(_, _, tp)| *tp == period) {
            return Err(internal!(
                "the specified time period does not have an associated ring"
            ));
        };

        // Now that we've matched each `hsid` with the ring associated with its TP, we can start
        // selecting replicas from each ring.
        Ok(rings.into_iter().flat_map(move |(ring, hsid, period)| {
            assert_eq!(period, ring.params().time_period());
            self.select_hsdirs(hsid, ring, spread)
        }))
    }

    /// Return the relays in this network directory that will be used as hidden service directories
    ///
    /// Depending on `op`,
    /// these are suitable to either store, or retrieve, a
    /// given onion service's descriptor at a given time period.
    ///
    /// When `op` is `Download`, the order is random.
    /// When `op` is `Upload`, the order is not specified.
    ///
    /// Return an error if the time period is not one returned by
    /// `onion_service_time_period` or `onion_service_secondary_time_periods`.
    //
    // TODO: make HsDirOp pub(crate) once this is removed
    #[cfg(feature = "hs-common")]
    #[deprecated(note = "Use hs_dirs_upload or hs_dirs_download instead")]
    pub fn hs_dirs<'r, R>(&'r self, hsid: &HsBlindId, op: HsDirOp, rng: &mut R) -> Vec<Relay<'r>>
    where
        R: rand::Rng,
    {
        // Algorithm:
        //
        // 1. Determine which HsDirRing to use, based on the time period.
        // 2. Find the shared random value that's associated with that HsDirRing.
        // 3. Choose spread = the parameter `hsdir_spread_store` or
        //    `hsdir_spread_fetch` based on `op`.
        // 4. Let n_replicas = the parameter `hsdir_n_replicas`.
        // 5. Initialize Dirs = []
        // 6. for idx in 1..=n_replicas:
        //       - let H = hsdir_ring::onion_service_index(id, replica, rand,
        //         period).
        //       - Find the position of H within hsdir_ring.
        //       - Take elements from hsdir_ring starting at that position,
        //         adding them to Dirs until we have added `spread` new elements
        //         that were not there before.
        // 7. return Dirs.
        let n_replicas = self
            .params
            .hsdir_n_replicas
            .get()
            .try_into()
            .expect("BoundedInt did not enforce bounds");

        let spread = match op {
            HsDirOp::Download => self.params.hsdir_spread_fetch,
            #[cfg(feature = "hs-service")]
            HsDirOp::Upload => self.params.hsdir_spread_store,
        };

        let spread = spread
            .get()
            .try_into()
            .expect("BoundedInt did not enforce bounds!");

        // TODO: I may be wrong here but I suspect that this function may
        // need refactoring so that it does not look at _all_ of the HsDirRings,
        // but only at the ones that corresponds to time periods for which
        // HsBlindId is valid.  Or I could be mistaken, in which case we should
        // have a comment to explain why I am, since the logic is subtle.
        // (For clients, there is only one ring.) -nickm
        //
        // (Actually, there is no need to follow through with the above TODO,
        // since this function is deprecated, and not used anywhere but the
        // tests.)

        let mut hs_dirs = self
            .hsdir_rings
            .iter_for_op(op)
            .cartesian_product(1..=n_replicas) // 1-indexed !
            .flat_map({
                let mut selected_nodes = HashSet::new();

                move |(ring, replica): (&HsDirRing, u8)| {
                    let hsdir_idx = hsdir_ring::service_hsdir_index(hsid, replica, ring.params());

                    let items = ring
                        .ring_items_at(hsdir_idx, spread, |(hsdir_idx, _)| {
                            // According to rend-spec 2.2.3:
                            //                                                  ... If any of those
                            // nodes have already been selected for a lower-numbered replica of the
                            // service, any nodes already chosen are disregarded (i.e. skipped over)
                            // when choosing a replica's hsdir_spread_store nodes.
                            selected_nodes.insert(*hsdir_idx)
                        })
                        .collect::<Vec<_>>();

                    items
                }
            })
            .filter_map(|(_hsdir_idx, rs_idx)| {
                // This ought not to be None but let's not panic or bail if it is
                self.relay_by_rs_idx(*rs_idx)
            })
            .collect_vec();

        match op {
            HsDirOp::Download => {
                // When `op` is `Download`, the order is random.
                hs_dirs.shuffle(rng);
            }
            #[cfg(feature = "hs-service")]
            HsDirOp::Upload => {
                // When `op` is `Upload`, the order is not specified.
            }
        }

        hs_dirs
    }
}

impl MdReceiver for NetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        Box::new(self.rsidx_by_missing.keys())
    }
    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        self.add_arc_microdesc(Arc::new(md))
    }
    fn n_missing(&self) -> usize {
        self.rsidx_by_missing.len()
    }
}

impl<'a> UncheckedRelay<'a> {
    /// Return true if this relay is valid and [usable](NetDir#usable).
    ///
    /// This function should return `true` for every Relay we expose
    /// to the user.
    pub fn is_usable(&self) -> bool {
        // No need to check for 'valid' or 'running': they are implicit.
        self.md.is_some() && self.rs.ed25519_id_is_usable()
    }
    /// If this is [usable](NetDir#usable), return a corresponding Relay object.
    pub fn into_relay(self) -> Option<Relay<'a>> {
        if self.is_usable() {
            Some(Relay {
                rs: self.rs,
                md: self.md?,
                #[cfg(feature = "geoip")]
                cc: self.cc,
            })
        } else {
            None
        }
    }
    /// Return true if this relay has the guard flag.
    pub fn is_flagged_guard(&self) -> bool {
        self.rs.is_flagged_guard()
    }
    /// Return true if this relay is suitable for use as a newly sampled guard,
    /// or for continuing to use as a guard.
    pub fn is_suitable_as_guard(&self) -> bool {
        self.rs.is_flagged_guard() && self.rs.is_flagged_fast() && self.rs.is_flagged_stable()
    }
    /// Return true if this relay is a potential directory cache.
    pub fn is_dir_cache(&self) -> bool {
        rs_is_dir_cache(self.rs)
    }
    /// Return true if this relay is a hidden service directory
    ///
    /// Ie, if it is to be included in the hsdir ring.
    #[cfg(feature = "hs-common")]
    pub(crate) fn is_hsdir_for_ring(&self) -> bool {
        // TODO are there any other flags should we check?
        // rend-spec-v3 2.2.3 says just
        //   "each node listed in the current consensus with the HSDir flag"
        // Do we need to check ed25519_id_is_usable ?
        // See also https://gitlab.torproject.org/tpo/core/arti/-/issues/504
        self.rs.is_flagged_hsdir()
    }
}

impl<'a> Relay<'a> {
    /// Return the Ed25519 ID for this relay.
    pub fn id(&self) -> &Ed25519Identity {
        self.md.ed25519_id()
    }
    /// Return the RsaIdentity for this relay.
    pub fn rsa_id(&self) -> &RsaIdentity {
        self.rs.rsa_identity()
    }
    /// Return true if this relay and `other` seem to be the same relay.
    ///
    /// (Two relays are the same if they have the same identity.)
    pub fn same_relay(&self, other: &Relay<'_>) -> bool {
        self.id() == other.id() && self.rsa_id() == other.rsa_id()
    }
    /// Return true if this relay allows exiting to `port` on IPv4.
    pub fn supports_exit_port_ipv4(&self, port: u16) -> bool {
        self.ipv4_policy().allows_port(port)
    }
    /// Return true if this relay allows exiting to `port` on IPv6.
    pub fn supports_exit_port_ipv6(&self, port: u16) -> bool {
        self.ipv6_policy().allows_port(port)
    }
    /// Return true if this relay is suitable for use as a directory
    /// cache.
    pub fn is_dir_cache(&self) -> bool {
        rs_is_dir_cache(self.rs)
    }
    /// Return true if this relay is marked as a potential Guard node.
    pub fn is_flagged_guard(&self) -> bool {
        self.rs.is_flagged_guard()
    }
    /// Return true if this relay has the "Fast" flag.
    ///
    /// Most relays have this flag.  It indicates that the relay is suitable for
    /// circuits that need more than a minimal amount of bandwidth.
    pub fn is_flagged_fast(&self) -> bool {
        self.rs.is_flagged_fast()
    }
    /// Return true if this relay has the "Stable" flag.
    ///
    /// Most relays have this flag. It indicates that the relay is suitable for
    /// long-lived circuits.
    pub fn is_flagged_stable(&self) -> bool {
        self.rs.is_flagged_stable()
    }
    /// Return true if this relay is a potential HS introduction point
    pub fn is_hs_intro_point(&self) -> bool {
        self.is_flagged_fast() && self.rs.is_flagged_stable()
    }
    /// Return true if this relay is suitable for use as a newly sampled guard,
    /// or for continuing to use as a guard.
    pub fn is_suitable_as_guard(&self) -> bool {
        self.is_flagged_guard() && self.is_flagged_fast() && self.is_flagged_stable()
    }
    /// Return true if both relays are in the same subnet, as configured by
    /// `subnet_config`.
    ///
    /// Two relays are considered to be in the same subnet if they
    /// have IPv4 addresses with the same `subnets_family_v4`-bit
    /// prefix, or if they have IPv6 addresses with the same
    /// `subnets_family_v6`-bit prefix.
    pub fn in_same_subnet(&self, other: &Relay<'_>, subnet_config: &SubnetConfig) -> bool {
        subnet_config.any_addrs_in_same_subnet(self, other)
    }
    /// Return true if both relays are in the same family.
    ///
    /// (Every relay is considered to be in the same family as itself.)
    pub fn in_same_family(&self, other: &Relay<'_>) -> bool {
        if self.same_relay(other) {
            return true;
        }
        self.md.family().contains(other.rsa_id()) && other.md.family().contains(self.rsa_id())
    }

    /// Return true if there are any ports for which this Relay can be
    /// used for exit traffic.
    ///
    /// (Returns false if this relay doesn't allow exit traffic, or if it
    /// has been flagged as a bad exit.)
    pub fn policies_allow_some_port(&self) -> bool {
        if self.rs.is_flagged_bad_exit() {
            return false;
        }

        self.md.ipv4_policy().allows_some_port() || self.md.ipv6_policy().allows_some_port()
    }

    /// Return the IPv4 exit policy for this relay. If the relay has been marked BadExit, return an
    /// empty policy
    pub fn ipv4_policy(&self) -> Arc<PortPolicy> {
        if !self.rs.is_flagged_bad_exit() {
            Arc::clone(self.md.ipv4_policy())
        } else {
            Arc::new(PortPolicy::new_reject_all())
        }
    }
    /// Return the IPv6 exit policy for this relay. If the relay has been marked BadExit, return an
    /// empty policy
    pub fn ipv6_policy(&self) -> Arc<PortPolicy> {
        if !self.rs.is_flagged_bad_exit() {
            Arc::clone(self.md.ipv6_policy())
        } else {
            Arc::new(PortPolicy::new_reject_all())
        }
    }
    /// Return the IPv4 exit policy declared by this relay. Contrary to [`Relay::ipv4_policy`],
    /// this does not verify if the relay is marked BadExit.
    pub fn ipv4_declared_policy(&self) -> &Arc<PortPolicy> {
        self.md.ipv4_policy()
    }
    /// Return the IPv6 exit policy declared by this relay. Contrary to [`Relay::ipv6_policy`],
    /// this does not verify if the relay is marked BadExit.
    pub fn ipv6_declared_policy(&self) -> &Arc<PortPolicy> {
        self.md.ipv6_policy()
    }

    /// Return a reference to this relay's "router status" entry in
    /// the consensus.
    ///
    /// The router status entry contains information about the relay
    /// that the authorities voted on directly.  For most use cases,
    /// you shouldn't need them.
    ///
    /// This function is only available if the crate was built with
    /// its `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn rs(&self) -> &netstatus::MdConsensusRouterStatus {
        self.rs
    }
    /// Return a reference to this relay's "microdescriptor" entry in
    /// the consensus.
    ///
    /// A "microdescriptor" is a synopsis of the information about a relay,
    /// used to determine its capabilities and route traffic through it.
    /// For most use cases, you shouldn't need it.
    ///
    /// This function is only available if the crate was built with
    /// its `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn md(&self) -> &Microdesc {
        self.md
    }
}

/// An error value returned from [`NetDir::by_ids_detailed`].
#[cfg(feature = "hs-common")]
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayLookupError {
    /// We found a relay whose presence indicates that the provided set of
    /// identities is impossible to resolve.
    #[error("Provided set of identities is impossible according to consensus.")]
    Impossible,
}

impl<'a> HasAddrs for Relay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        self.rs.addrs()
    }
}
#[cfg(feature = "geoip")]
#[cfg_attr(docsrs, doc(cfg(feature = "geoip")))]
impl<'a> HasCountryCode for Relay<'a> {
    fn country_code(&self) -> Option<CountryCode> {
        self.cc
    }
}
impl<'a> tor_linkspec::HasRelayIdsLegacy for Relay<'a> {
    fn ed_identity(&self) -> &Ed25519Identity {
        self.id()
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        self.rsa_id()
    }
}

impl<'a> HasRelayIds for UncheckedRelay<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        match key_type {
            RelayIdType::Ed25519 if self.rs.ed25519_id_is_usable() => {
                self.md.map(|m| m.ed25519_id().into())
            }
            RelayIdType::Rsa => Some(self.rs.rsa_identity().into()),
            _ => None,
        }
    }
}
#[cfg(feature = "geoip")]
impl<'a> HasCountryCode for UncheckedRelay<'a> {
    fn country_code(&self) -> Option<CountryCode> {
        self.cc
    }
}

impl<'a> DirectChanMethodsHelper for Relay<'a> {}
impl<'a> ChanTarget for Relay<'a> {}

impl<'a> tor_linkspec::CircTarget for Relay<'a> {
    fn ntor_onion_key(&self) -> &ll::pk::curve25519::PublicKey {
        self.md.ntor_key()
    }
    fn protovers(&self) -> &tor_protover::Protocols {
        self.rs.protovers()
    }
}

/// Return true if `rs` is usable as a directory cache.
fn rs_is_dir_cache(rs: &netstatus::MdConsensusRouterStatus) -> bool {
    use tor_protover::ProtoKind;
    rs.is_flagged_v2dir() && rs.protovers().supports_known_subver(ProtoKind::DirCache, 2)
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::cognitive_complexity)]
    use super::*;
    use crate::testnet::*;
    use float_eq::assert_float_eq;
    use std::collections::HashSet;
    use std::time::Duration;
    use tor_basic_utils::test_rng;
    use tor_linkspec::{RelayIdType, RelayIds};

    #[cfg(feature = "hs-common")]
    fn dummy_hs_blind_id() -> HsBlindId {
        let hsid = [2, 1, 1, 1].iter().cycle().take(32).cloned().collect_vec();
        let hsid = Ed25519Identity::new(hsid[..].try_into().unwrap());
        HsBlindId::from(hsid)
    }

    // Basic functionality for a partial netdir: Add microdescriptors,
    // then you have a netdir.
    #[test]
    fn partial_netdir() {
        let (consensus, microdescs) = construct_network().unwrap();
        let dir = PartialNetDir::new(consensus, None);

        // Check the lifetime
        let lifetime = dir.lifetime();
        assert_eq!(
            lifetime
                .valid_until()
                .duration_since(lifetime.valid_after())
                .unwrap(),
            Duration::new(86400, 0)
        );

        // No microdescriptors, so we don't have enough paths, and can't
        // advance.
        assert!(!dir.have_enough_paths());
        let mut dir = match dir.unwrap_if_sufficient() {
            Ok(_) => panic!(),
            Err(d) => d,
        };

        let missing: HashSet<_> = dir.missing_microdescs().collect();
        assert_eq!(missing.len(), 40);
        assert_eq!(missing.len(), dir.netdir.c_relays().len());
        for md in &microdescs {
            assert!(missing.contains(md.digest()));
        }

        // Now add all the mds and try again.
        for md in microdescs {
            let wanted = dir.add_microdesc(md);
            assert!(wanted);
        }

        let missing: HashSet<_> = dir.missing_microdescs().collect();
        assert!(missing.is_empty());
        assert!(dir.have_enough_paths());
        let _complete = match dir.unwrap_if_sufficient() {
            Ok(d) => d,
            Err(_) => panic!(),
        };
    }

    #[test]
    fn override_params() {
        let (consensus, _microdescs) = construct_network().unwrap();
        let override_p = "bwweightscale=2 doesnotexist=77 circwindow=500"
            .parse()
            .unwrap();
        let dir = PartialNetDir::new(consensus.clone(), Some(&override_p));
        let params = &dir.netdir.params;
        assert_eq!(params.bw_weight_scale.get(), 2);
        assert_eq!(params.circuit_window.get(), 500_i32);

        // try again without the override.
        let dir = PartialNetDir::new(consensus, None);
        let params = &dir.netdir.params;
        assert_eq!(params.bw_weight_scale.get(), 1_i32);
        assert_eq!(params.circuit_window.get(), 1000_i32);
    }

    #[test]
    fn fill_from_previous() {
        let (consensus, microdescs) = construct_network().unwrap();

        let mut dir = PartialNetDir::new(consensus.clone(), None);
        for md in microdescs.iter().skip(2) {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir1 = dir.unwrap_if_sufficient().unwrap();
        assert_eq!(dir1.missing_microdescs().count(), 2);

        let mut dir = PartialNetDir::new(consensus, None);
        assert_eq!(dir.missing_microdescs().count(), 40);
        dir.fill_from_previous_netdir(Arc::new(dir1));
        assert_eq!(dir.missing_microdescs().count(), 2);
    }

    #[test]
    fn path_count() {
        let low_threshold = "min_paths_for_circs_pct=64".parse().unwrap();
        let high_threshold = "min_paths_for_circs_pct=65".parse().unwrap();

        let (consensus, microdescs) = construct_network().unwrap();

        let mut dir = PartialNetDir::new(consensus.clone(), Some(&low_threshold));
        for (pos, md) in microdescs.iter().enumerate() {
            if pos % 7 == 2 {
                continue; // skip a few relays.
            }
            dir.add_microdesc(md.clone());
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        // We  have 40 relays that we know about from the consensus.
        assert_eq!(dir.all_relays().count(), 40);

        // But only 34 are usable.
        assert_eq!(dir.relays().count(), 34);

        // For guards: mds 20..=39 correspond to Guard relays.
        // Their bandwidth is 2*(1000+2000+...10000) = 110_000.
        // We skipped 23, 30, and 37.  They have bandwidth
        // 4000 + 1000 + 8000 = 13_000.  So our fractional bandwidth
        // should be (110-13)/110.
        let f = dir.frac_for_role(WeightRole::Guard, |u| u.rs.is_flagged_guard());
        assert!(((97.0 / 110.0) - f).abs() < 0.000001);

        // For exits: mds 10..=19 and 30..=39 correspond to Exit relays.
        // We skipped 16, 30,  and 37. Per above our fractional bandwidth is
        // (110-16)/110.
        let f = dir.frac_for_role(WeightRole::Exit, |u| u.rs.is_flagged_exit());
        assert!(((94.0 / 110.0) - f).abs() < 0.000001);

        // For middles: all relays are middles. We skipped 2, 9, 16,
        // 23, 30, and 37. Per above our fractional bandwidth is
        // (220-33)/220
        let f = dir.frac_for_role(WeightRole::Middle, |_| true);
        assert!(((187.0 / 220.0) - f).abs() < 0.000001);

        // Multiplying those together, we get the fraction of paths we can
        // build at ~0.64052066, which is above the threshold we set above for
        // MinPathsForCircsPct.
        let f = dir.frac_usable_paths();
        assert!((f - 0.64052066).abs() < 0.000001);

        // But if we try again with a slightly higher threshold...
        let mut dir = PartialNetDir::new(consensus, Some(&high_threshold));
        for (pos, md) in microdescs.into_iter().enumerate() {
            if pos % 7 == 2 {
                continue; // skip a few relays.
            }
            dir.add_microdesc(md);
        }
        assert!(dir.unwrap_if_sufficient().is_err());
    }

    /// Return a 3-tuple for use by `test_pick_*()` of an Rng, a number of
    /// iterations, and a tolerance.
    ///
    /// If the Rng is deterministic (the default), we can use a faster setup,
    /// with a higher tolerance and fewer iterations.  But if you've explicitly
    /// opted into randomization (or are replaying a seed from an earlier
    /// randomized test), we give you more iterations and a tighter tolerance.
    fn testing_rng_with_tolerances() -> (impl rand::Rng, usize, f64) {
        // Use a deterministic RNG if none is specified, since this is slow otherwise.
        let config = test_rng::Config::from_env().unwrap_or(test_rng::Config::Deterministic);
        let (iters, tolerance) = match config {
            test_rng::Config::Deterministic => (5000, 0.02),
            _ => (50000, 0.01),
        };
        (config.into_rng(), iters, tolerance)
    }

    #[test]
    fn test_pick() {
        let (consensus, microdescs) = construct_network().unwrap();
        let mut dir = PartialNetDir::new(consensus, None);
        for md in microdescs.into_iter() {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        let (mut rng, total, tolerance) = testing_rng_with_tolerances();

        let mut picked = [0_isize; 40];
        for _ in 0..total {
            let r = dir.pick_relay(&mut rng, WeightRole::Middle, |r| {
                r.supports_exit_port_ipv4(80)
            });
            let r = r.unwrap();
            let id_byte = r.identity(RelayIdType::Rsa).unwrap().as_bytes()[0];
            picked[id_byte as usize] += 1;
        }
        // non-exits should never get picked.
        picked[0..10].iter().for_each(|x| assert_eq!(*x, 0));
        picked[20..30].iter().for_each(|x| assert_eq!(*x, 0));

        let picked_f: Vec<_> = picked.iter().map(|x| *x as f64 / total as f64).collect();

        // We didn't we any non-default weights, so the other relays get
        // weighted proportional to their bandwidth.
        assert_float_eq!(picked_f[19], (10.0 / 110.0), abs <= tolerance);
        assert_float_eq!(picked_f[38], (9.0 / 110.0), abs <= tolerance);
        assert_float_eq!(picked_f[39], (10.0 / 110.0), abs <= tolerance);
    }

    #[test]
    fn test_pick_multiple() {
        // This is mostly a copy of test_pick, except that it uses
        // pick_n_relays to pick several relays at once.

        let dir = construct_netdir().unwrap_if_sufficient().unwrap();

        let (mut rng, total, tolerance) = testing_rng_with_tolerances();

        let mut picked = [0_isize; 40];
        for _ in 0..total / 4 {
            let relays = dir.pick_n_relays(&mut rng, 4, WeightRole::Middle, |r| {
                r.supports_exit_port_ipv4(80)
            });
            assert_eq!(relays.len(), 4);
            for r in relays {
                let id_byte = r.identity(RelayIdType::Rsa).unwrap().as_bytes()[0];
                picked[id_byte as usize] += 1;
            }
        }
        // non-exits should never get picked.
        picked[0..10].iter().for_each(|x| assert_eq!(*x, 0));
        picked[20..30].iter().for_each(|x| assert_eq!(*x, 0));

        let picked_f: Vec<_> = picked.iter().map(|x| *x as f64 / total as f64).collect();

        // We didn't we any non-default weights, so the other relays get
        // weighted proportional to their bandwidth.
        assert_float_eq!(picked_f[19], (10.0 / 110.0), abs <= tolerance);
        assert_float_eq!(picked_f[36], (7.0 / 110.0), abs <= tolerance);
        assert_float_eq!(picked_f[39], (10.0 / 110.0), abs <= tolerance);
    }

    #[test]
    fn subnets() {
        let cfg = SubnetConfig::default();

        fn same_net(cfg: &SubnetConfig, a: &str, b: &str) -> bool {
            cfg.addrs_in_same_subnet(&a.parse().unwrap(), &b.parse().unwrap())
        }

        assert!(same_net(&cfg, "127.15.3.3", "127.15.9.9"));
        assert!(!same_net(&cfg, "127.15.3.3", "127.16.9.9"));

        assert!(!same_net(&cfg, "127.15.3.3", "127::"));

        assert!(same_net(&cfg, "ffff:ffff:90:33::", "ffff:ffff:91:34::"));
        assert!(!same_net(&cfg, "ffff:ffff:90:33::", "ffff:fffe:91:34::"));

        let cfg = SubnetConfig {
            subnets_family_v4: 32,
            subnets_family_v6: 128,
        };
        assert!(!same_net(&cfg, "127.15.3.3", "127.15.9.9"));
        assert!(!same_net(&cfg, "ffff:ffff:90:33::", "ffff:ffff:91:34::"));

        assert!(same_net(&cfg, "127.0.0.1", "127.0.0.1"));
        assert!(!same_net(&cfg, "127.0.0.1", "127.0.0.2"));
        assert!(same_net(&cfg, "ffff:ffff:90:33::", "ffff:ffff:90:33::"));

        let cfg = SubnetConfig {
            subnets_family_v4: 33,
            subnets_family_v6: 129,
        };
        assert!(!same_net(&cfg, "127.0.0.1", "127.0.0.1"));
        assert!(!same_net(&cfg, "::", "::"));
    }

    #[test]
    fn relay_funcs() {
        let (consensus, microdescs) = construct_custom_network(
            |pos, nb| {
                if pos == 15 {
                    nb.rs.add_or_port("[f0f0::30]:9001".parse().unwrap());
                } else if pos == 20 {
                    nb.rs.add_or_port("[f0f0::3131]:9001".parse().unwrap());
                }
            },
            None,
        )
        .unwrap();
        let subnet_config = SubnetConfig::default();
        let mut dir = PartialNetDir::new(consensus, None);
        for md in microdescs.into_iter() {
            let wanted = dir.add_microdesc(md.clone());
            assert!(wanted);
        }
        let dir = dir.unwrap_if_sufficient().unwrap();

        // Pick out a few relays by ID.
        let k0 = Ed25519Identity::from([0; 32]);
        let k1 = Ed25519Identity::from([1; 32]);
        let k2 = Ed25519Identity::from([2; 32]);
        let k3 = Ed25519Identity::from([3; 32]);
        let k10 = Ed25519Identity::from([10; 32]);
        let k15 = Ed25519Identity::from([15; 32]);
        let k20 = Ed25519Identity::from([20; 32]);

        let r0 = dir.by_id(&k0).unwrap();
        let r1 = dir.by_id(&k1).unwrap();
        let r2 = dir.by_id(&k2).unwrap();
        let r3 = dir.by_id(&k3).unwrap();
        let r10 = dir.by_id(&k10).unwrap();
        let r15 = dir.by_id(&k15).unwrap();
        let r20 = dir.by_id(&k20).unwrap();

        assert_eq!(r0.id(), &[0; 32].into());
        assert_eq!(r0.rsa_id(), &[0; 20].into());
        assert_eq!(r1.id(), &[1; 32].into());
        assert_eq!(r1.rsa_id(), &[1; 20].into());

        assert!(r0.same_relay(&r0));
        assert!(r1.same_relay(&r1));
        assert!(!r1.same_relay(&r0));

        assert!(r0.is_dir_cache());
        assert!(!r1.is_dir_cache());
        assert!(r2.is_dir_cache());
        assert!(!r3.is_dir_cache());

        assert!(!r0.supports_exit_port_ipv4(80));
        assert!(!r1.supports_exit_port_ipv4(80));
        assert!(!r2.supports_exit_port_ipv4(80));
        assert!(!r3.supports_exit_port_ipv4(80));

        assert!(!r0.policies_allow_some_port());
        assert!(!r1.policies_allow_some_port());
        assert!(!r2.policies_allow_some_port());
        assert!(!r3.policies_allow_some_port());
        assert!(r10.policies_allow_some_port());

        assert!(r0.in_same_family(&r0));
        assert!(r0.in_same_family(&r1));
        assert!(r1.in_same_family(&r0));
        assert!(r1.in_same_family(&r1));
        assert!(!r0.in_same_family(&r2));
        assert!(!r2.in_same_family(&r0));
        assert!(r2.in_same_family(&r2));
        assert!(r2.in_same_family(&r3));

        assert!(r0.in_same_subnet(&r10, &subnet_config));
        assert!(r10.in_same_subnet(&r10, &subnet_config));
        assert!(r0.in_same_subnet(&r0, &subnet_config));
        assert!(r1.in_same_subnet(&r1, &subnet_config));
        assert!(!r1.in_same_subnet(&r2, &subnet_config));
        assert!(!r2.in_same_subnet(&r3, &subnet_config));

        // Make sure IPv6 families work.
        let subnet_config = SubnetConfig {
            subnets_family_v4: 128,
            subnets_family_v6: 96,
        };
        assert!(r15.in_same_subnet(&r20, &subnet_config));
        assert!(!r15.in_same_subnet(&r1, &subnet_config));

        // Make sure that subnet configs can be disabled.
        let subnet_config = SubnetConfig {
            subnets_family_v4: 255,
            subnets_family_v6: 255,
        };
        assert!(!r15.in_same_subnet(&r20, &subnet_config));
    }

    #[test]
    fn test_badexit() {
        // make a netdir where relays 10-19 are badexit, and everybody
        // exits to 443 on IPv6.
        use tor_netdoc::doc::netstatus::RelayFlags;
        let netdir = construct_custom_netdir(|pos, nb| {
            if (10..20).contains(&pos) {
                nb.rs.add_flags(RelayFlags::BAD_EXIT);
            }
            nb.md.parse_ipv6_policy("accept 443").unwrap();
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        let e12 = netdir.by_id(&Ed25519Identity::from([12; 32])).unwrap();
        let e32 = netdir.by_id(&Ed25519Identity::from([32; 32])).unwrap();

        assert!(!e12.supports_exit_port_ipv4(80));
        assert!(e32.supports_exit_port_ipv4(80));

        assert!(!e12.supports_exit_port_ipv6(443));
        assert!(e32.supports_exit_port_ipv6(443));
        assert!(!e32.supports_exit_port_ipv6(555));

        assert!(!e12.policies_allow_some_port());
        assert!(e32.policies_allow_some_port());

        assert!(!e12.ipv4_policy().allows_some_port());
        assert!(!e12.ipv6_policy().allows_some_port());
        assert!(e32.ipv4_policy().allows_some_port());
        assert!(e32.ipv6_policy().allows_some_port());

        assert!(e12.ipv4_declared_policy().allows_some_port());
        assert!(e12.ipv6_declared_policy().allows_some_port());
    }

    #[cfg(feature = "experimental-api")]
    #[test]
    fn test_accessors() {
        let netdir = construct_netdir().unwrap_if_sufficient().unwrap();

        let r4 = netdir.by_id(&Ed25519Identity::from([4; 32])).unwrap();
        let r16 = netdir.by_id(&Ed25519Identity::from([16; 32])).unwrap();

        assert!(!r4.md().ipv4_policy().allows_some_port());
        assert!(r16.md().ipv4_policy().allows_some_port());

        assert!(!r4.rs().is_flagged_exit());
        assert!(r16.rs().is_flagged_exit());
    }

    #[test]
    fn test_by_id() {
        // Make a netdir that omits the microdescriptor for 0xDDDDDD...
        let netdir = construct_custom_netdir(|pos, nb| {
            nb.omit_md = pos == 13;
        })
        .unwrap();

        let netdir = netdir.unwrap_if_sufficient().unwrap();

        let r = netdir.by_id(&Ed25519Identity::from([0; 32])).unwrap();
        assert_eq!(r.id().as_bytes(), &[0; 32]);

        assert!(netdir.by_id(&Ed25519Identity::from([13; 32])).is_none());

        let r = netdir.by_rsa_id(&[12; 20].into()).unwrap();
        assert_eq!(r.rsa_id().as_bytes(), &[12; 20]);
        assert!(netdir.rsa_id_is_listed(&[12; 20].into()));

        assert!(netdir.by_rsa_id(&[13; 20].into()).is_none());

        assert!(netdir.by_rsa_id_unchecked(&[99; 20].into()).is_none());
        assert!(!netdir.rsa_id_is_listed(&[99; 20].into()));

        let r = netdir.by_rsa_id_unchecked(&[13; 20].into()).unwrap();
        assert_eq!(r.rs.rsa_identity().as_bytes(), &[13; 20]);
        assert!(netdir.rsa_id_is_listed(&[13; 20].into()));

        let pair_13_13 = RelayIds::builder()
            .ed_identity([13; 32].into())
            .rsa_identity([13; 20].into())
            .build()
            .unwrap();
        let pair_14_14 = RelayIds::builder()
            .ed_identity([14; 32].into())
            .rsa_identity([14; 20].into())
            .build()
            .unwrap();
        let pair_14_99 = RelayIds::builder()
            .ed_identity([14; 32].into())
            .rsa_identity([99; 20].into())
            .build()
            .unwrap();

        let r = netdir.by_ids(&pair_13_13);
        assert!(r.is_none());
        let r = netdir.by_ids(&pair_14_14).unwrap();
        assert_eq!(r.identity(RelayIdType::Rsa).unwrap().as_bytes(), &[14; 20]);
        assert_eq!(
            r.identity(RelayIdType::Ed25519).unwrap().as_bytes(),
            &[14; 32]
        );
        let r = netdir.by_ids(&pair_14_99);
        assert!(r.is_none());

        assert_eq!(
            netdir.id_pair_listed(&[13; 32].into(), &[13; 20].into()),
            None
        );
        assert_eq!(
            netdir.id_pair_listed(&[15; 32].into(), &[15; 20].into()),
            Some(true)
        );
        assert_eq!(
            netdir.id_pair_listed(&[15; 32].into(), &[99; 20].into()),
            Some(false)
        );
    }

    #[test]
    #[cfg(feature = "hs-common")]
    fn test_by_ids_detailed() {
        // Make a netdir that omits the microdescriptor for 0xDDDDDD...
        let netdir = construct_custom_netdir(|pos, nb| {
            nb.omit_md = pos == 13;
        })
        .unwrap();

        let netdir = netdir.unwrap_if_sufficient().unwrap();

        let id13_13 = RelayIds::builder()
            .ed_identity([13; 32].into())
            .rsa_identity([13; 20].into())
            .build()
            .unwrap();
        let id15_15 = RelayIds::builder()
            .ed_identity([15; 32].into())
            .rsa_identity([15; 20].into())
            .build()
            .unwrap();
        let id15_99 = RelayIds::builder()
            .ed_identity([15; 32].into())
            .rsa_identity([99; 20].into())
            .build()
            .unwrap();
        let id99_15 = RelayIds::builder()
            .ed_identity([99; 32].into())
            .rsa_identity([15; 20].into())
            .build()
            .unwrap();
        let id99_99 = RelayIds::builder()
            .ed_identity([99; 32].into())
            .rsa_identity([99; 20].into())
            .build()
            .unwrap();
        let id15_xx = RelayIds::builder()
            .ed_identity([15; 32].into())
            .build()
            .unwrap();
        let idxx_15 = RelayIds::builder()
            .rsa_identity([15; 20].into())
            .build()
            .unwrap();

        assert!(matches!(netdir.by_ids_detailed(&id13_13), Ok(None)));
        assert!(matches!(netdir.by_ids_detailed(&id15_15), Ok(Some(_))));
        assert!(matches!(
            netdir.by_ids_detailed(&id15_99),
            Err(RelayLookupError::Impossible)
        ));
        assert!(matches!(
            netdir.by_ids_detailed(&id99_15),
            Err(RelayLookupError::Impossible)
        ));
        assert!(matches!(netdir.by_ids_detailed(&id99_99), Ok(None)));
        assert!(matches!(netdir.by_ids_detailed(&id15_xx), Ok(Some(_))));
        assert!(matches!(netdir.by_ids_detailed(&idxx_15), Ok(Some(_))));
    }

    #[test]
    fn weight_type() {
        let r0 = RelayWeight(0);
        let r100 = RelayWeight(100);
        let r200 = RelayWeight(200);
        let r300 = RelayWeight(300);
        assert_eq!(r100 + r200, r300);
        assert_eq!(r100.checked_div(r200), Some(0.5));
        assert!(r100.checked_div(r0).is_none());
        assert_eq!(r200.ratio(0.5), Some(r100));
        assert!(r200.ratio(-1.0).is_none());
    }

    #[test]
    fn weight_accessors() {
        // Make a netdir that omits the microdescriptor for 0xDDDDDD...
        let netdir = construct_netdir().unwrap_if_sufficient().unwrap();

        let g_total = netdir.total_weight(WeightRole::Guard, |r| r.is_flagged_guard());
        // This is just the total guard weight, since all our Wxy = 1.
        assert_eq!(g_total, RelayWeight(110_000));

        let g_total = netdir.total_weight(WeightRole::Guard, |_| false);
        assert_eq!(g_total, RelayWeight(0));

        let relay = netdir.by_id(&Ed25519Identity::from([35; 32])).unwrap();
        assert!(relay.is_flagged_guard());
        let w = netdir.relay_weight(&relay, WeightRole::Guard);
        assert_eq!(w, RelayWeight(6_000));

        let w = netdir
            .weight_by_rsa_id(&[33; 20].into(), WeightRole::Guard)
            .unwrap();
        assert_eq!(w, RelayWeight(4_000));

        assert!(netdir
            .weight_by_rsa_id(&[99; 20].into(), WeightRole::Guard)
            .is_none());
    }

    #[test]
    fn family_list() {
        let netdir = construct_custom_netdir(|pos, n| {
            if pos == 0x0a {
                n.md.family(
                    "$0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B \
                     $0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C \
                     $0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D0D"
                        .parse()
                        .unwrap(),
                );
            } else if pos == 0x0c {
                n.md.family("$0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A".parse().unwrap());
            }
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        // In the testing netdir, adjacent members are in the same family by default...
        let r0 = netdir.by_id(&Ed25519Identity::from([0; 32])).unwrap();
        let family: Vec<_> = netdir.known_family_members(&r0).collect();
        assert_eq!(family.len(), 1);
        assert_eq!(family[0].id(), &Ed25519Identity::from([1; 32]));

        // But we've made this relay claim membership with several others.
        let r10 = netdir.by_id(&Ed25519Identity::from([10; 32])).unwrap();
        let family: HashSet<_> = netdir.known_family_members(&r10).map(|r| *r.id()).collect();
        assert_eq!(family.len(), 2);
        assert!(family.contains(&Ed25519Identity::from([11; 32])));
        assert!(family.contains(&Ed25519Identity::from([12; 32])));
        // Note that 13 doesn't get put in, even though it's listed, since it doesn't claim
        //  membership with 10.
    }
    #[test]
    #[cfg(feature = "geoip")]
    fn relay_has_country_code() {
        let src_v6 = r#"
        fe80:dead:beef::,fe80:dead:ffff::,US
        fe80:feed:eeee::1,fe80:feed:eeee::2,AT
        fe80:feed:eeee::2,fe80:feed:ffff::,DE
        "#;
        let db = GeoipDb::new_from_legacy_format("", src_v6).unwrap();

        let netdir = construct_custom_netdir_with_geoip(
            |pos, n| {
                if pos == 0x01 {
                    n.rs.add_or_port("[fe80:dead:beef::1]:42".parse().unwrap());
                }
                if pos == 0x02 {
                    n.rs.add_or_port("[fe80:feed:eeee::1]:42".parse().unwrap());
                    n.rs.add_or_port("[fe80:feed:eeee::2]:42".parse().unwrap());
                }
                if pos == 0x03 {
                    n.rs.add_or_port("[fe80:dead:beef::1]:42".parse().unwrap());
                    n.rs.add_or_port("[fe80:dead:beef::2]:42".parse().unwrap());
                }
            },
            &db,
        )
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();

        // No GeoIP data available -> None
        let r0 = netdir.by_id(&Ed25519Identity::from([0; 32])).unwrap();
        assert_eq!(r0.cc, None);

        // Exactly one match -> Some
        let r1 = netdir.by_id(&Ed25519Identity::from([1; 32])).unwrap();
        assert_eq!(r1.cc.as_ref().map(|x| x.as_ref()), Some("US"));

        // Conflicting matches -> None
        let r2 = netdir.by_id(&Ed25519Identity::from([2; 32])).unwrap();
        assert_eq!(r2.cc, None);

        // Multiple agreeing matches -> Some
        let r3 = netdir.by_id(&Ed25519Identity::from([3; 32])).unwrap();
        assert_eq!(r3.cc.as_ref().map(|x| x.as_ref()), Some("US"));
    }

    #[test]
    #[cfg(feature = "hs-common")]
    #[allow(deprecated)]
    fn hs_dirs_selection() {
        use tor_basic_utils::test_rng::testing_rng;

        const HSDIR_SPREAD_STORE: i32 = 6;
        const HSDIR_SPREAD_FETCH: i32 = 2;
        const PARAMS: [(&str, i32); 2] = [
            ("hsdir_spread_store", HSDIR_SPREAD_STORE),
            ("hsdir_spread_fetch", HSDIR_SPREAD_FETCH),
        ];

        let netdir: Arc<NetDir> =
            crate::testnet::construct_custom_netdir_with_params(|_, _| {}, PARAMS, None)
                .unwrap()
                .unwrap_if_sufficient()
                .unwrap()
                .into();
        let hsid = dummy_hs_blind_id();

        const OP_RELAY_COUNT: &[(HsDirOp, usize)] = &[
            // We can't upload to (hsdir_n_replicas * hsdir_spread_store) = 12, relays because there
            // are only 10 relays with the HsDir flag in the consensus.
            #[cfg(feature = "hs-service")]
            (HsDirOp::Upload, 10),
            (HsDirOp::Download, 4),
        ];

        for (op, relay_count) in OP_RELAY_COUNT {
            let relays = netdir.hs_dirs(&hsid, *op, &mut testing_rng());

            assert_eq!(relays.len(), *relay_count);

            // There should be no duplicates (the filtering function passed to
            // HsDirRing::ring_items_at() ensures the relays that are already in use for
            // lower-numbered replicas aren't considered a second time for a higher-numbered
            // replica).
            let unique = relays
                .iter()
                .map(|relay| relay.ed_identity())
                .collect::<HashSet<_>>();
            assert_eq!(unique.len(), relays.len());
        }

        // TODO: come up with a test that checks that HsDirRing::ring_items_at() skips over the
        // expected relays.
        //
        // For example, let's say we have the following hsdir ring:
        //
        //         A  -  B
        //        /       \
        //       F         C
        //        \       /
        //         E  -  D
        //
        // Let's also assume that:
        //
        //   * hsdir_spread_store = 3
        //   * the ordering of the relays on the ring is [A, B, C, D, E, F]
        //
        // If we use relays [A, B, C] for replica 1, and hs_index(2) = E, then replica 2 _must_ get
        // relays [E, F, D]. We should have a test that checks this.
    }
}
