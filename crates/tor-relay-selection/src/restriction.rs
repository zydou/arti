//! Define different restrictions that can be applied to relays.

#[cfg(feature = "geoip")]
use tor_geoip::HasCountryCode;
use tor_linkspec::{ChanTarget, HasAddrs, HasRelayIds, RelayIdSet};
use tor_netdir::{NetDir, Relay, SubnetConfig};
use tor_netdoc::types::policy::AddrPortPattern;

use crate::{LowLevelRelayPredicate, RelaySelectionConfig, RelayUsage};
use std::{fmt, net::IpAddr};

/// A restriction that we use when picking relays.
///
/// Differs from [`RelayUsage`] in that it does not say what
/// the relay is _used for_;
/// instead, it describes an additional set of requirements that a relay must
/// satisfy.
#[derive(Clone, Debug)]
pub struct RelayRestriction<'a> {
    /// The actual restriction object.
    inner: RestrictionInner<'a>,
}

/// Enumeration of possible [`RelayRestriction`]s.
///
/// This is a separate type so that we can hide its variants.
///
// TODO: I'm not sure about having this be relative to `'a``,
// but that is the only way to hold a `Relay<'a>`
//
// NOTE: Any time that you are extending this type, make sure that you are not
// describing a new _mandatory_ restriction that all `RelaySelector` users
// need to consider adding (or not).  If you *are* describing such a restriction,
// then it should have its own type, and it should become a new argument to
// RelaySelector::new().
#[derive(Clone, Debug)]
enum RestrictionInner<'a> {
    /// Do not restrict any relays.
    ///
    /// This is present so that we can construct a no-op restriction when
    /// relaxing a selector.
    NoRestriction,
    /// Require a given usage.
    SupportsUsage(crate::RelayUsage),
    /// Exclude a set of relays explicitly, by family, or by identity.
    Exclude(RelayExclusion<'a>),
    /// Require that, if the relay's contact method uses addresses, the relay
    /// has at least one address matching one of the provided patterns.
    HasAddrInSet(Vec<AddrPortPattern>),
    /// Require that the relay has a given country code.
    #[cfg(feature = "geoip")]
    RequireCountry(tor_geoip::CountryCode),
}

impl<'a> RelayRestriction<'a> {
    /// Create a restriction that allows every relay.
    pub(crate) fn no_restriction() -> Self {
        RelayRestriction {
            inner: RestrictionInner::NoRestriction,
        }
    }

    /// Convert a usage into a restriction.
    ///
    /// This is crate-internal since we never want to support requiring a relay
    /// to provide multiple usages.
    pub(crate) fn for_usage(usage: crate::RelayUsage) -> Self {
        RelayRestriction {
            inner: RestrictionInner::SupportsUsage(usage),
        }
    }

    /// Require a relay that appears to be in the provided country,
    /// according ot our geoip subsystem.
    #[cfg(feature = "geoip")]
    pub fn require_country_code(cc: tor_geoip::CountryCode) -> Self {
        RelayRestriction {
            inner: RestrictionInner::RequireCountry(cc),
        }
    }

    /// Require that a relay has at least one address
    /// listed in `addr_patterns`.
    pub fn require_address(addr_patterns: Vec<AddrPortPattern>) -> Self {
        // TODO: It's plausible that this restriction should be mandatory
        // whenever we are picking new guards.
        RelayRestriction {
            inner: RestrictionInner::HasAddrInSet(addr_patterns),
        }
    }

    /// Return a restriction that represents having "relaxed" this restriction.
    ///
    /// (Relaxing a restriction replaces it with a no-op, or with an almost-no-op.)
    pub(crate) fn relax(&self) -> Self {
        use RestrictionInner::*;
        match &self.inner {
            // We must always have a usage, so relaxing a usage must always
            // return a usage.
            SupportsUsage(usage) => Self::for_usage(RelayUsage::middle_relay(Some(usage))),
            // Relaxing any other restriction returns a no-op
            _ => Self::no_restriction(),
        }
    }

    /// If this restriction represents a usage, return a reference to that usage.
    pub(crate) fn as_usage(&self) -> Option<&RelayUsage> {
        use RestrictionInner::*;
        match &self.inner {
            SupportsUsage(usage) => Some(usage),
            _ => None,
        }
    }

    /// Return a string describing why we rejected the relays that _don't_ match
    /// this restriction.
    pub(crate) fn rejection_description(&self) -> Option<&'static str> {
        use RestrictionInner::*;
        match &self.inner {
            NoRestriction => None,
            SupportsUsage(u) => Some(u.rejection_description()),
            Exclude(e) => e.rejection_description(),
            HasAddrInSet(_) => Some("not reachable (according to address filter)"),
            #[cfg(feature = "geoip")]
            RequireCountry(_) => Some("not in correct country"),
        }
    }
}

impl<'a> LowLevelRelayPredicate for RelayRestriction<'a> {
    fn low_level_predicate_permits_relay(&self, relay: &tor_netdir::Relay<'_>) -> bool {
        use RestrictionInner::*;
        match &self.inner {
            NoRestriction => true,
            SupportsUsage(usage) => usage.low_level_predicate_permits_relay(relay),
            Exclude(exclusion) => exclusion.low_level_predicate_permits_relay(relay),
            HasAddrInSet(patterns) => relay_has_addr_in_set(relay, patterns),
            #[cfg(feature = "geoip")]
            RequireCountry(cc) => relay.country_code() == Some(*cc),
        }
    }
}

impl<'a> From<RelayExclusion<'a>> for RelayRestriction<'a> {
    fn from(value: RelayExclusion<'a>) -> Self {
        RelayRestriction {
            inner: RestrictionInner::Exclude(value),
        }
    }
}

/// Return true if `relay` has at least one address matching at least one member
/// of `patterns`.
fn relay_has_addr_in_set(relay: &Relay<'_>, patterns: &[AddrPortPattern]) -> bool {
    // NOTE: If we ever make this apply to ChanTarget instead of Relay, we will
    // need it to call chan_method().socket_addrs() instead, and handle the case
    // where the transport doesn't use an address.
    relay
        .addrs()
        .iter()
        .any(|addr| patterns.iter().any(|pat| pat.matches_sockaddr(addr)))
}

/// A set of relays that we must not use when picking a given
/// relays.
///
/// Exclusions are generally used to make sure that we obey
/// family-based path-selection rules,
/// that we avoid putting the same relay into a set more than once,
/// or similar purposes.
///
/// (This is a separate type from [`RelayRestriction`] so that we can
/// enforce our rule that every [`RelaySelector`](crate::RelaySelector) must
/// have a `RelayExclusion`.)
#[derive(Clone, Debug)]
pub struct RelayExclusion<'a> {
    /// A list of identities to exclude.
    ///
    /// Any relay with any one of these identities is rejecteed.
    exclude_ids: RelayIdSet,
    /// A list of subnets from which to exclude addresses.
    ///
    /// The side of the subnet is determined by subnet_config.
    exclude_subnets: Vec<IpAddr>,
    /// A list of relays to exclude, along with their families.
    exclude_relay_families: RelayList<'a>,
    /// The configuration to use when deciding whether two addresses are in the
    /// same subnet.
    subnet_config: SubnetConfig,
}

/// Helper: wraps `Vec[Relay]`, but implements Debug.
#[derive(Clone)]
struct RelayList<'a>(Vec<Relay<'a>>);
impl<'a> fmt::Debug for RelayList<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ ")?;
        for r in &self.0 {
            write!(f, "{}, ", r.display_relay_ids())?;
        }
        write!(f, "]")
    }
}

impl<'a> RelayExclusion<'a> {
    /// Exclude no relays at all.
    ///
    /// This kind of restriction is useful when picking the first relay for
    /// something,
    ///
    // (Note that this is _not_ Default::default, since we don't want people
    // picking it by mistake.)
    pub fn no_relays_excluded() -> Self {
        RelayExclusion {
            exclude_ids: RelayIdSet::new(),
            exclude_subnets: Vec::new(),
            exclude_relay_families: RelayList(Vec::new()),
            subnet_config: SubnetConfig::no_addresses_match(),
        }
    }

    /// Exclude every relay that has an identity in `ids`.
    pub fn exclude_identities(ids: RelayIdSet) -> Self {
        RelayExclusion {
            exclude_ids: ids,
            ..RelayExclusion::no_relays_excluded()
        }
    }

    /// Exclude every relay that appears in `relays`.
    pub fn exclude_specific_relays(relays: &[Relay<'a>]) -> Self {
        let ids: RelayIdSet = relays
            .iter()
            .flat_map(Relay::identities)
            .map(|id_ref| id_ref.to_owned())
            .collect();

        Self::exclude_identities(ids)
    }

    /// Try to exclude every relay in the same family as the [`ChanTarget`]
    /// `ct`.
    ///
    /// # Limitations
    ///
    /// A ChanTarget does not have a listed family.  Thus, if it does not correspond
    /// to a relay listed in `netdir`, we can only exclude relays that share the
    /// same identity, or relays that are in the same subnet.
    ///
    /// Whenever possible, it's better to use exclude_relays_in_same_family.
    pub fn exclude_channel_target_family<CT: ChanTarget>(
        cfg: &RelaySelectionConfig,
        ct: &CT,
        netdir: &'a NetDir,
    ) -> Self {
        if let Some(r) = netdir.by_ids(ct) {
            return Self::exclude_relays_in_same_family(cfg, vec![r]);
        }

        let exclude_ids = ct.identities().map(|id_ref| id_ref.to_owned()).collect();
        let exclude_addr_families = ct.addrs().iter().map(|a| a.ip()).collect();

        Self {
            exclude_ids,
            exclude_subnets: exclude_addr_families,
            subnet_config: cfg.subnet_config,
            ..Self::no_relays_excluded()
        }
    }

    /// Exclude every relay that is in the same family as any member of
    /// `relays`.
    ///
    /// (Remember that every relay is considered to be in the same family as
    /// itself, so you don't typically need to use `exclude_specific_relays`
    /// along with this.)
    ///
    /// Considers relays that are in the same subnets (according to `cfg`) to
    /// belong to the same family.
    pub fn exclude_relays_in_same_family(
        cfg: &RelaySelectionConfig,
        relays: Vec<Relay<'a>>,
    ) -> Self {
        RelayExclusion {
            exclude_relay_families: RelayList(relays),
            subnet_config: cfg.subnet_config,
            ..RelayExclusion::no_relays_excluded()
        }
    }

    /// Modify this `RelayExclusion` by adding every exclusion from `other`.
    ///
    /// (Any subnet configuration becomes the _union_ of previous subnet
    /// configurations.)
    pub fn extend(&mut self, other: &RelayExclusion<'a>) {
        let RelayExclusion {
            exclude_ids,
            exclude_subnets: exclude_addr_families,
            exclude_relay_families,
            subnet_config,
        } = other;
        self.exclude_ids
            .extend(exclude_ids.iter().map(|id_ref| id_ref.to_owned()));
        self.exclude_subnets
            .extend_from_slice(&exclude_addr_families[..]);
        self.exclude_relay_families
            .0
            .extend_from_slice(&exclude_relay_families.0[..]);
        self.subnet_config = self.subnet_config.union(subnet_config);
    }

    /// Return a string describing why we rejected the relays that _don't_ match
    /// this exclusion.
    pub(crate) fn rejection_description(&self) -> Option<&'static str> {
        if self.exclude_relay_families.0.is_empty() && self.exclude_subnets.is_empty() {
            if self.exclude_ids.is_empty() {
                None
            } else {
                Some("already selected")
            }
        } else {
            Some("in same family as already selected")
        }
    }
}

impl<'a> LowLevelRelayPredicate for RelayExclusion<'a> {
    fn low_level_predicate_permits_relay(&self, relay: &Relay<'_>) -> bool {
        if relay.identities().any(|id| self.exclude_ids.contains(id)) {
            return false;
        }

        if relay.addrs().iter().any(|addr| {
            self.exclude_subnets
                .iter()
                .any(|fam| self.subnet_config.addrs_in_same_subnet(&addr.ip(), fam))
        }) {
            return false;
        }

        if self
            .exclude_relay_families
            .0
            .iter()
            .any(|r| relays_in_same_extended_family(&self.subnet_config, relay, r))
        {
            return false;
        }

        true
    }
}

/// Return true if `r1` and `r2` are in the same "extended" family,
/// considering both explicitly declared families
/// and subnet-based extended families.
fn relays_in_same_extended_family(
    subnet_config: &SubnetConfig,
    r1: &Relay<'_>,
    r2: &Relay<'_>,
) -> bool {
    r1.in_same_family(r2) || subnet_config.any_addrs_in_same_subnet(r1, r2)
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

    use tor_linkspec::RelayId;

    use super::*;
    use crate::testing::{cfg, split_netdir, testnet};

    #[test]
    fn exclude_nothing() {
        let nd = testnet();
        let usage = RelayExclusion::no_relays_excluded();
        assert!(nd
            .relays()
            .all(|r| usage.low_level_predicate_permits_relay(&r)));
    }

    #[test]
    fn exclude_ids() {
        let nd = testnet();
        let id_0 = "$0000000000000000000000000000000000000000".parse().unwrap();
        let id_5 = "ed25519:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
            .parse()
            .unwrap();
        let ids: RelayIdSet = [id_0, id_5].into_iter().collect();
        let (yes, no) = split_netdir(&nd, &RelayExclusion::exclude_identities(ids));

        let p = |r: &Relay<'_>| !(r.has_identity(id_0.as_ref()) || r.has_identity(id_5.as_ref()));
        assert_eq!(yes.len(), 38);
        assert_eq!(no.len(), 2);
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    #[test]
    fn exclude_relays() {
        let nd = testnet();
        let id_0: RelayId = "$0000000000000000000000000000000000000000".parse().unwrap();
        let id_5: RelayId = "ed25519:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
            .parse()
            .unwrap();
        let relay_0 = nd.by_id(&id_0).unwrap();
        let relay_5 = nd.by_id(&id_5).unwrap();

        let (yes, no) = split_netdir(
            &nd,
            &RelayExclusion::exclude_specific_relays(&[relay_0.clone(), relay_5.clone()]),
        );
        let p = |r: &Relay<'_>| !(r.same_relay(&relay_0) || r.same_relay(&relay_5));
        assert_eq!(yes.len(), 38);
        assert_eq!(no.len(), 2);
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    #[test]
    fn exclude_families() {
        let nd = testnet();
        let id_0: RelayId = "$0000000000000000000000000000000000000000".parse().unwrap();
        let id_5: RelayId = "ed25519:BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
            .parse()
            .unwrap();
        let relay_0 = nd.by_id(&id_0).unwrap();
        let relay_5 = nd.by_id(&id_5).unwrap();
        let excluding_relays = vec![relay_0, relay_5];

        // in the test netdir, all (2n, 2n+1) pairs are in a family.
        let id_1 = "$0101010101010101010101010101010101010101".parse().unwrap();
        let id_4 = "$0404040404040404040404040404040404040404".parse().unwrap();
        let expect_excluded_ids: RelayIdSet = [id_0, id_1, id_4, id_5].into_iter().collect();

        // Case one: No subnet-based exclusion.

        let cfg_no_subnet = RelaySelectionConfig {
            long_lived_ports: cfg().long_lived_ports,
            subnet_config: SubnetConfig::new(255, 255),
        };

        let (yes, no) = split_netdir(
            &nd,
            &RelayExclusion::exclude_relays_in_same_family(
                &cfg_no_subnet,
                excluding_relays.clone(),
            ),
        );
        let p = |r: &Relay<'_>| !r.identities().any(|id| expect_excluded_ids.contains(id));
        assert_eq!(yes.len(), 36);
        assert_eq!(no.len(), 4);
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));

        // Case two: default subnet-based exclusion.
        //
        // In the test network, addresses are x.0.0.3 where x is the index of
        // the relay, modulo 5.  Since the default ipv4 subnet family rule looks at /16
        // prefixes, every one of the 40 relays in the testnet will be in a
        // family with 8 other relays.
        let expect_excluded_ids: RelayIdSet = nd
            .relays()
            .filter_map(|r| {
                let rsa = r.rsa_identity().unwrap();
                let b = rsa.as_bytes()[0];
                if [0, 1, 4, 5].contains(&b) || [0, 5].contains(&(b % 5)) {
                    Some(RelayId::from(*rsa))
                } else {
                    None
                }
            })
            .collect();

        let (yes, no) = split_netdir(
            &nd,
            &RelayExclusion::exclude_relays_in_same_family(&cfg(), excluding_relays),
        );
        for r in &no {
            dbg!(r.rsa_identity().unwrap());
        }
        dbg!(&expect_excluded_ids);
        dbg!(expect_excluded_ids.len());
        let p = |r: &Relay<'_>| !r.identities().any(|id| expect_excluded_ids.contains(id));
        assert_eq!(yes.len(), 30);
        assert_eq!(no.len(), 10);
        assert!(yes.iter().all(p));

        assert!(no.iter().all(|r| { !p(r) }));
    }

    #[test]
    fn filter_addresses() {
        let nd = testnet();
        let reachable = vec![
            "1.0.0.0/8:*".parse().unwrap(),
            "2.0.0.0/8:*".parse().unwrap(),
        ];
        let reachable = RelayRestriction::require_address(reachable);

        let (yes, no) = split_netdir(&nd, &reachable);
        assert_eq!(yes.len(), 16);
        assert_eq!(no.len(), 24);

        let expected = ["1.0.0.3".parse().unwrap(), "2.0.0.3".parse().unwrap()];
        let p = |r: &Relay<'_>| expected.contains(&r.addrs()[0].ip());
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    // TODO: Write a geoip test?
}
