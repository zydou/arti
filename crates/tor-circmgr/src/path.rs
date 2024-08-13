//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub(crate) mod dirpath;
pub(crate) mod exitpath;

// Care must be taken if/when we decide to make this pub.
//
// The `HsPathBuilder` exposes two path building functions,
// one that uses vanguards, and one that doesn't.
// We want to strongly encourage the use of the vanguards-aware
// version of the function whenever the `vanguards` feature is enabled,
// without breaking any of its existing non-vanguard uses.
#[cfg(feature = "hs-common")]
pub(crate) mod hspath;

use std::result::Result as StdResult;
use std::time::SystemTime;

use rand::Rng;

use tor_error::{bad_api_usage, internal, Bug};
#[cfg(feature = "geoip")]
use tor_geoip::{CountryCode, HasCountryCode};
use tor_guardmgr::fallback::FallbackDir;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_linkspec::{HasAddrs, HasRelayIds, OwnedChanTarget, OwnedCircTarget, RelayIdSet};
use tor_netdir::{NetDir, Relay};
use tor_relay_selection::{RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage};
use tor_rtcompat::Runtime;

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
use tor_guardmgr::vanguards::Vanguard;

use crate::usage::ExitPolicy;
use crate::{DirInfo, Error, PathConfig, Result};

/// A list of Tor relays through the network.
pub struct TorPath<'a> {
    /// The inner TorPath state.
    inner: TorPathInner<'a>,
}

/// Non-public helper type to represent the different kinds of Tor path.
///
/// (This is a separate type to avoid exposing its details to the user.)
///
/// NOTE: This type should NEVER be visible outside of path.rs and its
/// sub-modules.
enum TorPathInner<'a> {
    /// A single-hop path for use with a directory cache, when a relay is
    /// known.
    OneHop(Relay<'a>), // This could just be a routerstatus.
    /// A single-hop path for use with a directory cache, when we don't have
    /// a consensus.
    FallbackOneHop(&'a FallbackDir),
    /// A single-hop path taken from an OwnedChanTarget.
    OwnedOneHop(OwnedChanTarget),
    /// A multi-hop path, containing one or more relays.
    Path(Vec<MaybeOwnedRelay<'a>>),
}

/// Identifier for a relay that could be either known from a NetDir, or
/// specified as an OwnedCircTarget.
///
/// NOTE: This type should NEVER be visible outside of path.rs and its
/// sub-modules.
#[derive(Clone)]
enum MaybeOwnedRelay<'a> {
    /// A relay from the netdir.
    Relay(Relay<'a>),
    /// An owned description of a relay.
    //
    // TODO: I don't love boxing this, but it fixes a warning about
    // variant sizes and is probably not the worst thing we could do.  OTOH, we
    // could probably afford to use an Arc here and in guardmgr? -nickm
    //
    // TODO: Try using an Arc. -nickm
    Owned(Box<OwnedCircTarget>),
}

impl<'a> MaybeOwnedRelay<'a> {
    /// Extract an OwnedCircTarget from this relay.
    fn to_owned(&self) -> OwnedCircTarget {
        match self {
            MaybeOwnedRelay::Relay(r) => OwnedCircTarget::from_circ_target(r),
            MaybeOwnedRelay::Owned(o) => o.as_ref().clone(),
        }
    }
}

impl<'a> From<OwnedCircTarget> for MaybeOwnedRelay<'a> {
    fn from(ct: OwnedCircTarget) -> Self {
        MaybeOwnedRelay::Owned(Box::new(ct))
    }
}
impl<'a> From<Relay<'a>> for MaybeOwnedRelay<'a> {
    fn from(r: Relay<'a>) -> Self {
        MaybeOwnedRelay::Relay(r)
    }
}
impl<'a> HasAddrs for MaybeOwnedRelay<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        match self {
            MaybeOwnedRelay::Relay(r) => r.addrs(),
            MaybeOwnedRelay::Owned(r) => r.addrs(),
        }
    }
}
impl<'a> HasRelayIds for MaybeOwnedRelay<'a> {
    fn identity(
        &self,
        key_type: tor_linkspec::RelayIdType,
    ) -> Option<tor_linkspec::RelayIdRef<'_>> {
        match self {
            MaybeOwnedRelay::Relay(r) => r.identity(key_type),
            MaybeOwnedRelay::Owned(r) => r.identity(key_type),
        }
    }
}

#[cfg(all(feature = "vanguards", feature = "hs-common"))]
impl<'a> From<Vanguard<'a>> for MaybeOwnedRelay<'a> {
    fn from(r: Vanguard<'a>) -> Self {
        MaybeOwnedRelay::Relay(r.relay().clone())
    }
}

impl<'a> TorPath<'a> {
    /// Create a new one-hop path for use with a directory cache with a known
    /// relay.
    pub fn new_one_hop(relay: Relay<'a>) -> Self {
        Self {
            inner: TorPathInner::OneHop(relay),
        }
    }

    /// Create a new one-hop path for use with a directory cache when we don't
    /// have a consensus.
    pub fn new_fallback_one_hop(fallback_dir: &'a FallbackDir) -> Self {
        Self {
            inner: TorPathInner::FallbackOneHop(fallback_dir),
        }
    }

    /// Construct a new one-hop path for directory use from an arbitrarily
    /// chosen channel target.
    pub fn new_one_hop_owned<T: tor_linkspec::ChanTarget>(target: &T) -> Self {
        Self {
            inner: TorPathInner::OwnedOneHop(OwnedChanTarget::from_chan_target(target)),
        }
    }

    /// Create a new multi-hop path with a given number of ordered relays.
    pub fn new_multihop(relays: impl IntoIterator<Item = Relay<'a>>) -> Self {
        Self {
            inner: TorPathInner::Path(relays.into_iter().map(MaybeOwnedRelay::from).collect()),
        }
    }
    /// Construct a new multi-hop path from a vector of `MaybeOwned`.
    ///
    /// Internal only; do not expose without fixing up this API a bit.
    fn new_multihop_from_maybe_owned(relays: Vec<MaybeOwnedRelay<'a>>) -> Self {
        Self {
            inner: TorPathInner::Path(relays),
        }
    }

    /// Return the final relay in this path, if this is a path for use
    /// with exit circuits.
    fn exit_relay(&self) -> Option<&MaybeOwnedRelay<'a>> {
        match &self.inner {
            TorPathInner::Path(relays) if !relays.is_empty() => Some(&relays[relays.len() - 1]),
            _ => None,
        }
    }

    /// Return the exit policy of the final relay in this path, if this is a
    /// path for use with exit circuits with an exit taken from the network
    /// directory.
    pub(crate) fn exit_policy(&self) -> Option<ExitPolicy> {
        self.exit_relay().and_then(|r| match r {
            MaybeOwnedRelay::Relay(r) => Some(ExitPolicy::from_relay(r)),
            MaybeOwnedRelay::Owned(_) => None,
        })
    }

    /// Return the country code of the final relay in this path, if this is a
    /// path for use with exit circuits with an exit taken from the network
    /// directory.
    #[cfg(feature = "geoip")]
    pub(crate) fn country_code(&self) -> Option<CountryCode> {
        self.exit_relay().and_then(|r| match r {
            MaybeOwnedRelay::Relay(r) => r.country_code(),
            MaybeOwnedRelay::Owned(_) => None,
        })
    }

    /// Return the number of relays in this path.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        use TorPathInner::*;
        match &self.inner {
            OneHop(_) => 1,
            FallbackOneHop(_) => 1,
            OwnedOneHop(_) => 1,
            Path(p) => p.len(),
        }
    }

    /// Return true if every `Relay` in this path has the stable flag.
    ///
    /// Assumes that Owned elements of this path are stable.
    pub(crate) fn appears_stable(&self) -> bool {
        // TODO #504: this looks at low_level_details() in questionable way.
        match &self.inner {
            TorPathInner::OneHop(r) => r.low_level_details().is_flagged_stable(),
            TorPathInner::FallbackOneHop(_) => true,
            TorPathInner::OwnedOneHop(_) => true,
            TorPathInner::Path(relays) => relays.iter().all(|maybe_owned| match maybe_owned {
                MaybeOwnedRelay::Relay(r) => r.low_level_details().is_flagged_stable(),
                MaybeOwnedRelay::Owned(_) => true,
            }),
        }
    }
}

/// A path composed entirely of owned components.
#[derive(Clone, Debug)]
pub(crate) enum OwnedPath {
    /// A path where we only know how to make circuits via CREATE_FAST.
    ChannelOnly(OwnedChanTarget),
    /// A path of one or more hops created via normal Tor handshakes.
    Normal(Vec<OwnedCircTarget>),
}

impl<'a> TryFrom<&TorPath<'a>> for OwnedPath {
    type Error = crate::Error;
    fn try_from(p: &TorPath<'a>) -> Result<OwnedPath> {
        use TorPathInner::*;

        Ok(match &p.inner {
            FallbackOneHop(h) => OwnedPath::ChannelOnly(OwnedChanTarget::from_chan_target(*h)),
            OneHop(h) => OwnedPath::Normal(vec![OwnedCircTarget::from_circ_target(h)]),
            OwnedOneHop(owned) => OwnedPath::ChannelOnly(owned.clone()),
            Path(p) if !p.is_empty() => {
                OwnedPath::Normal(p.iter().map(MaybeOwnedRelay::to_owned).collect())
            }
            Path(_) => {
                return Err(bad_api_usage!("Path with no entries!").into());
            }
        })
    }
}

impl OwnedPath {
    /// Return the number of hops in this path.
    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        match self {
            OwnedPath::ChannelOnly(_) => 1,
            OwnedPath::Normal(p) => p.len(),
        }
    }
}

/// A path builder that builds multi-hop, anonymous paths.
trait AnonymousPathBuilder<'a> {
    /// Return the relay to use as exit node.
    fn chosen_exit(&self) -> Option<&Relay<'_>>;

    /// Return the "target" that every chosen relay must be able to share a circuit with with.
    fn compatible_with(&self) -> Option<&OwnedChanTarget>;

    /// Return a short description of the path we're trying to build,
    /// for error reporting purposes.
    fn path_kind(&self) -> &'static str;

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    ///
    /// Return the exit, along with the usage for a middle node corresponding
    /// to this exit.
    fn pick_exit<'s, R: Rng>(
        &'s self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard_exclusion: RelayExclusion<'a>,
        rs_cfg: &RelaySelectionConfig<'_>,
    ) -> Result<(Relay<'a>, RelayUsage)>;
}

/// Try to create and return a path corresponding to the requirements of
/// this builder.
fn pick_path<'a, B: AnonymousPathBuilder<'a>, R: Rng, RT: Runtime>(
    builder: &B,
    rng: &mut R,
    netdir: DirInfo<'a>,
    guards: &GuardMgr<RT>,
    config: &PathConfig,
    _now: SystemTime,
) -> Result<(TorPath<'a>, GuardMonitor, GuardUsable)> {
    let netdir = match netdir {
        DirInfo::Directory(d) => d,
        _ => {
            return Err(bad_api_usage!(
                "Tried to build a multihop path without a network directory"
            )
            .into())
        }
    };
    let rs_cfg = config.relay_selection_config();

    let target_exclusion = match builder.compatible_with() {
        Some(ct) => {
            // Exclude the target from appearing in other positions in the path.
            let ids = RelayIdSet::from_iter(ct.identities().map(|id_ref| id_ref.to_owned()));
            // TODO torspec#265: we do not apply same-family restrictions
            // (a relay in the same family as the target can occur in the path).
            //
            // We need to decide if this is the correct behavior,
            // and if so, document it in torspec.
            RelayExclusion::exclude_identities(ids)
        }
        None => RelayExclusion::no_relays_excluded(),
    };

    // TODO-SPEC: Because of limitations in guard selection, we have to
    // pick the guard before the exit, which is not what our spec says.
    let (guard, mon, usable) = select_guard(
        netdir,
        guards,
        builder.chosen_exit(),
        builder.compatible_with(),
    )?;

    let guard_exclusion = match &guard {
        MaybeOwnedRelay::Relay(r) => RelayExclusion::exclude_relays_in_same_family(
            &config.relay_selection_config(),
            vec![r.clone()],
        ),
        MaybeOwnedRelay::Owned(ct) => RelayExclusion::exclude_channel_target_family(
            &config.relay_selection_config(),
            ct.as_ref(),
            netdir,
        ),
    };

    let mut exclusion = guard_exclusion.clone();
    exclusion.extend(&target_exclusion);
    let (exit, middle_usage) = builder.pick_exit(rng, netdir, exclusion, &rs_cfg)?;

    let mut family_exclusion =
        RelayExclusion::exclude_relays_in_same_family(&rs_cfg, vec![exit.clone()]);
    family_exclusion.extend(&guard_exclusion);
    let mut exclusion = family_exclusion;
    exclusion.extend(&target_exclusion);

    let selector = RelaySelector::new(middle_usage, exclusion);
    let (middle, info) = selector.select_relay(rng, netdir);
    let middle = middle.ok_or_else(|| Error::NoRelay {
        path_kind: builder.path_kind(),
        role: "middle relay",
        problem: info.to_string(),
    })?;

    let hops = vec![
        guard,
        MaybeOwnedRelay::from(middle),
        MaybeOwnedRelay::from(exit),
    ];

    ensure_unique_hops(&hops)?;

    Ok((TorPath::new_multihop_from_maybe_owned(hops), mon, usable))
}

/// Returns an error if the specified hop list contains duplicates.
fn ensure_unique_hops<'a>(hops: &'a [MaybeOwnedRelay<'a>]) -> StdResult<(), Bug> {
    for (i, hop) in hops.iter().enumerate() {
        if let Some(hop2) = hops
            .iter()
            .skip(i + 1)
            .find(|hop2| hop.clone().has_any_relay_id_from(*hop2))
        {
            return Err(internal!(
                "invalid path: the IDs of hops {} and {} overlap?!",
                hop.display_relay_ids(),
                hop2.display_relay_ids()
            ));
        }
    }
    Ok(())
}

/// Try to select a guard corresponding to the requirements of
/// this builder.
fn select_guard<'a, RT: Runtime>(
    netdir: &'a NetDir,
    guardmgr: &GuardMgr<RT>,
    chosen_exit: Option<&Relay<'_>>,
    compatible_with: Option<&OwnedChanTarget>,
) -> Result<(MaybeOwnedRelay<'a>, GuardMonitor, GuardUsable)> {
    let path_is_fully_random = chosen_exit.is_none();
    // TODO: Extract this section into its own function, and see
    // what it can share with tor_relay_selection.
    let mut b = tor_guardmgr::GuardUsageBuilder::default();
    b.kind(tor_guardmgr::GuardUsageKind::Data);
    if let Some(exit_relay) = chosen_exit {
        // TODO(nickm): Our way of building a family here is
        // somewhat questionable. We're only adding the ed25519
        // identities of the exit relay and its family to the
        // RelayId set.  That's fine for now, since we will only use
        // relays at this point if they have a known Ed25519
        // identity.  But if in the future the ed25519 identity
        // becomes optional, this will need to change.
        // NOTE(opara): This only excludes close family members and
        // not extended family members (relays in the same network
        // range).
        let mut family = RelayIdSet::new();
        family.insert(*exit_relay.id());
        // TODO(nickm): See "limitations" note on `known_family_members`.
        family.extend(netdir.known_family_members(exit_relay).map(|r| *r.id()));
        b.restrictions()
            .push(tor_guardmgr::GuardRestriction::AvoidAllIds(family));
    }
    if let Some(avoid_target) = compatible_with {
        let mut family = RelayIdSet::new();
        family.extend(avoid_target.identities().map(|id| id.to_owned()));
        if let Some(avoid_relay) = netdir.by_ids(avoid_target) {
            family.extend(netdir.known_family_members(&avoid_relay).map(|r| *r.id()));
        }
        b.restrictions()
            .push(tor_guardmgr::GuardRestriction::AvoidAllIds(family));
    }
    let guard_usage = b.build().expect("Failed while building guard usage!");
    let (guard, mut mon, usable) = guardmgr.select_guard(guard_usage)?;
    let guard = if let Some(ct) = guard.as_circ_target() {
        // This is a bridge; we will not look for it in the network directory.
        MaybeOwnedRelay::from(ct.clone())
    } else {
        // Look this up in the network directory: we expect to find a relay.
        guard
            .get_relay(netdir)
            .ok_or_else(|| {
                internal!(
                    "Somehow the guardmgr gave us an unlisted guard {:?}!",
                    guard
                )
            })?
            .into()
    };
    if !path_is_fully_random {
        // We were given a specific exit relay to use, and
        // the choice of exit relay might be forced by
        // something outside of our control.
        //
        // Therefore, we must not blame the guard for any failure
        // to complete the circuit.
        mon.ignore_indeterminate_status();
    }
    Ok((guard, mon, usable))
}

/// For testing: make sure that `path` is the same when it is an owned
/// path.
#[cfg(test)]
fn assert_same_path_when_owned(path: &TorPath<'_>) {
    #![allow(clippy::unwrap_used)]
    let owned: OwnedPath = path.try_into().unwrap();

    match (&owned, &path.inner) {
        (OwnedPath::ChannelOnly(c), TorPathInner::FallbackOneHop(f)) => {
            assert!(c.same_relay_ids(*f));
        }
        (OwnedPath::Normal(p), TorPathInner::OneHop(h)) => {
            assert_eq!(p.len(), 1);
            assert!(p[0].same_relay_ids(h));
        }
        (OwnedPath::Normal(p1), TorPathInner::Path(p2)) => {
            assert_eq!(p1.len(), p2.len());
            for (n1, n2) in p1.iter().zip(p2.iter()) {
                assert!(n1.same_relay_ids(n2));
            }
        }
        (_, _) => {
            panic!("Mismatched path types.");
        }
    }
}
