//! Logic for selecting relays from a network directory,
//! and reporting the outcome of such a selection.

use crate::{LowLevelRelayPredicate, RelayExclusion, RelayRestriction, RelayUsage};
use tor_basic_utils::iter::FilterCount;
use tor_netdir::{NetDir, Relay, WeightRole};

use std::fmt;

/// Description of the requirements that a relay must implement in order to be selected.
///
/// This object is used to pick a [`Relay`] from a [`NetDir`], or to ensure that a
/// previously selected `Relay` still meets its requirements.
///
/// The requirements on a relay can be _strict_ or _flexible_.
/// If any restriction is flexible, and relay selection fails at first,
/// we _relax_ the `RelaySelector` by removing that restriction,
/// and trying again,
/// before we give up completely.
#[derive(Clone, Debug)]
pub struct RelaySelector<'a> {
    /// A usage that the relay must support.
    ///
    /// Invariant: This is a RelayUsage.
    usage: Restr<'a>,

    /// An excludion that the relay must obey.
    ///
    /// Invariant: This a RelayExclusion.
    exclusion: Restr<'a>,

    /// Other restrictions that a Relay must obey in order to be selected.
    other_restrictions: Vec<Restr<'a>>,
}

/// A single restriction, along with a flag about whether it's strict.
#[derive(Clone, Debug)]
struct Restr<'a> {
    /// The underlying restriction.
    restriction: RelayRestriction<'a>,
    /// Is the restriction strict or flexible?
    strict: bool,
}

impl<'a> Restr<'a> {
    /// Try relaxing this restriction.
    ///
    /// (If this can't be relaxed, just return a copy of it.)
    fn maybe_relax(&self) -> Self {
        if self.strict {
            self.clone()
        } else {
            Self {
                restriction: self.restriction.relax(),
                // The new restriction is always strict, since we don't want to
                // relax it any further.
                strict: true,
            }
        }
    }
}

/// Information about how a given selection was generated.
///
/// Records the specifics of how many relays were excluded by each
/// requirement,
/// whether we had to relax the selector, and so on.
///
/// The caller should typically decide whether an error or warning is necessary,
/// and if so use this to generate a formattable report about what went wrong.
#[derive(Debug, Clone)]
pub struct SelectionInfo<'a> {
    /// Outcome of our first attempt to pick a relay.
    first_try: FilterCounts,

    /// Present if we tried again with a relaxed version of our
    /// flexible members.
    relaxed_try: Option<FilterCounts>,

    /// True if we eventually succeeded in picking a relay.
    succeeded: bool,

    /// The `RelaySelector` that was used.
    ///
    /// Used to produce information about which restriction is which.
    in_selection: &'a RelaySelector<'a>,
}

impl<'a> SelectionInfo<'a> {
    /// Return true if we eventually picked at least one relay.
    ///
    /// (We report success on `pick_n_relays` if we returned a nonzero
    /// number of relays, even if it is smaller than the requested number.)
    pub fn success(&self) -> bool {
        self.succeeded
    }

    /// Return true if picked at least one relay,
    /// but only after relaxing our initial selector.
    pub fn result_is_relaxed_success(&self) -> bool {
        self.relaxed_try.is_some() && self.succeeded
    }
}

impl<'a> fmt::Display for SelectionInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.succeeded, &self.relaxed_try) {
            (true, None) => write!(f, "Success: {}", FcDisp(&self.first_try, self.in_selection))?,
            (false, None) => write!(f, "Failed: {}", FcDisp(&self.first_try, self.in_selection))?,
            (true, Some(retry)) => write!(
                f,
                "Failed at first, then succeeded. At first, {}. After relaxing requirements, {}",
                FcDisp(&self.first_try, self.in_selection),
                FcDisp(retry, self.in_selection)
            )?,
            (false, Some(retry)) => write!(
                f,
                "Failed even after relaxing requirement. At first, {}. After relaxing requirements, {}",
                FcDisp(&self.first_try, self.in_selection),
                FcDisp(retry, self.in_selection)
            )?,
        };
        Ok(())
    }
}

/// A list of [`FilterCount`], associated with a [`RelaySelector`].
#[derive(Debug, Clone)]
struct FilterCounts {
    /// The [`FilterCount`] created by each restriction.
    ///
    /// This `Vec` has the same length as the list of restrictions; its items
    /// refer to them one by one.
    ///
    /// Because restrictions are applied as a set of filters, each successive
    /// count will only include the relays not excluded by the previous filters.
    counts: Vec<FilterCount>,
}

impl FilterCounts {
    /// Create a new empty `FilterCounts`.
    fn new(selector: &RelaySelector) -> Self {
        let counts = vec![FilterCount::default(); selector.n_restrictions()];
        FilterCounts { counts }
    }
}

/// Helper to display filter counts
struct FcDisp<'a>(&'a FilterCounts, &'a RelaySelector<'a>);
impl<'a> fmt::Display for FcDisp<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = &self.0.counts;
        let restrictions = self.1.all_restrictions();
        write!(f, "rejected ")?;
        let mut first = true;
        let mut found_any_rejected = false;
        for (c, r) in counts.iter().zip(restrictions) {
            if let Some(desc) = r.restriction.rejection_description() {
                if first {
                    first = false;
                } else {
                    write!(f, "; ")?;
                }
                write!(f, "{} as {}", c.display_frac_rejected(), desc)?;
                found_any_rejected = true;
            } else {
                debug_assert_eq!(c.n_rejected, 0);
            }
        }
        if !found_any_rejected {
            write!(f, "none")?;
        }
        Ok(())
    }
}

impl<'a> RelaySelector<'a> {
    /// Create a new RelaySelector to pick relays with a given
    /// [`RelayUsage`] and [`RelayExclusion`].
    ///
    /// Both arguments are required, since every caller should consider them explicitly.
    ///
    /// The provided usage and exclusion are strict by default.
    ///
    // TODO: Possibly have this take a struct with named pieces instead, when we
    // get a third thing that we want everybody to think about.
    pub fn new(usage: RelayUsage, exclusion: RelayExclusion<'a>) -> Self {
        Self {
            usage: Restr {
                restriction: RelayRestriction::for_usage(usage),
                strict: true,
            },
            exclusion: Restr {
                restriction: exclusion.into(),
                strict: true,
            },
            other_restrictions: vec![],
        }
    }

    /// Mark the originally provided `RelayUsage` as flexible.
    pub fn mark_usage_flexible(&mut self) {
        self.usage.strict = false;
    }

    /// Mark the originally provided `RelayExclusion` as flexible.
    pub fn mark_exclusion_flexible(&mut self) {
        self.exclusion.strict = false;
    }

    /// Add a new _strict_ [`RelayRestriction`] to this selector.
    pub fn push_restriction(&mut self, restriction: RelayRestriction<'a>) {
        self.push_inner(restriction, true);
    }

    /// Add a new _flexible_ [`RelayRestriction`] to this selector.
    pub fn push_flexible_restriction(&mut self, restriction: RelayRestriction<'a>) {
        self.push_inner(restriction, false);
    }

    /// Helper to implement adding a new restriction.
    fn push_inner(&mut self, restriction: RelayRestriction<'a>, strict: bool) {
        self.other_restrictions.push(Restr {
            restriction,
            strict,
        });
    }

    /// Return the usage for this selector.
    pub fn usage(&self) -> &RelayUsage {
        // See invariants for explanation of why these `expects` are safe.
        self.usage
            .restriction
            .as_usage()
            .expect("Usage not a usage!?")
    }

    /// Return the [`WeightRole`] to use when randomly picking relays according
    /// to this selector.
    fn weight_role(&self) -> WeightRole {
        self.usage().selection_weight_role()
    }

    /// Return true if `relay` is one that this selector would pick.
    pub fn permits_relay(&self, relay: &tor_netdir::Relay<'_>) -> bool {
        self.low_level_predicate_permits_relay(relay)
    }

    /// Return an iterator that yields each restriction from this selector,
    /// including the usage and exclusion.
    fn all_restrictions(&self) -> impl Iterator<Item = &Restr<'a>> {
        use std::iter::once;
        once(&self.usage)
            .chain(once(&self.exclusion))
            .chain(self.other_restrictions.iter())
    }

    /// Return the number of restrictions in this selector,
    /// including the usage and exclusion.
    fn n_restrictions(&self) -> usize {
        self.other_restrictions.len() + 2
    }

    /// Try to pick a random relay from `netdir`,
    /// according to the rules of this selector.
    pub fn select_relay<'s, 'd, R: rand::Rng>(
        &'s self,
        rng: &mut R,
        netdir: &'d NetDir,
    ) -> (Option<Relay<'d>>, SelectionInfo<'s>) {
        with_possible_relaxation(
            self,
            |selector| {
                let role = selector.weight_role();
                let mut fc = FilterCounts::new(selector);
                let relay = netdir.pick_relay(rng, role, |r| selector.relay_usable(r, &mut fc));
                (relay, fc)
            },
            Option::is_some,
        )
    }

    /// Try to pick `n_relays` distinct random relay from `netdir`,
    /// according to the rules of this selector.
    pub fn select_n_relays<'s, 'd, R: rand::Rng>(
        &'s self,
        rng: &mut R,
        n_relays: usize,
        netdir: &'d NetDir,
    ) -> (Vec<Relay<'d>>, SelectionInfo<'s>) {
        with_possible_relaxation(
            self,
            |selector| {
                let role = selector.weight_role();
                let mut fc = FilterCounts::new(selector);
                let relays = netdir
                    .pick_n_relays(rng, n_relays, role, |r| selector.relay_usable(r, &mut fc));
                (relays, fc)
            },
            |relays| !relays.is_empty(),
        )
    }

    /// Check whether a given relay `r` obeys the restrictions of this selector,
    /// updating `fc` according to which restrictions (if any) accepted or
    /// rejected it.
    ///
    /// Requires that `fc` has the same length as self.restrictions.
    ///
    /// This differs from `<Self as RelayPredicate>::permits_relay` in taking
    /// `fc` as an argument.
    fn relay_usable(&self, r: &Relay<'_>, fc: &mut FilterCounts) -> bool {
        debug_assert_eq!(self.n_restrictions(), fc.counts.len());

        self.all_restrictions()
            .zip(fc.counts.iter_mut())
            .all(|(restr, restr_count)| {
                restr_count.count(restr.restriction.low_level_predicate_permits_relay(r))
            })
    }

    /// Return true if this selector has any flexible restrictions.
    fn can_relax(&self) -> bool {
        self.all_restrictions().any(|restr| !restr.strict)
    }

    /// Return a new selector created by relaxing every flexible restriction in
    /// this selector.
    fn relax(&self) -> Self {
        let new_selector = RelaySelector {
            usage: self.usage.maybe_relax(),
            exclusion: self.exclusion.maybe_relax(),
            other_restrictions: self
                .other_restrictions
                .iter()
                .map(Restr::maybe_relax)
                .collect(),
        };
        debug_assert!(!new_selector.can_relax());
        new_selector
    }
}

impl<'a> LowLevelRelayPredicate for RelaySelector<'a> {
    fn low_level_predicate_permits_relay(&self, relay: &tor_netdir::Relay<'_>) -> bool {
        self.all_restrictions()
            .all(|r| r.restriction.low_level_predicate_permits_relay(relay))
    }
}

/// Re-run relay selection, relaxing our selector as necessary.
///
/// This is a helper to implement our relay selection logic.
/// We try to run `select` to find one or more random relays
/// conforming to `selector`.
/// If `ok` says that the result is good (by returning true),
/// we return that result.
/// Otherwise, we try to _relax_ the selector (if possible),
/// and try again.
/// If the selector can't be relaxed any further,
/// we return the original (not-ok) result.
//
// TODO: Later, we might want to relax our restrictions one by one,
// rather than all at once.
fn with_possible_relaxation<'a, SEL, OK, T>(
    selector: &'a RelaySelector,
    mut select: SEL,
    ok: OK,
) -> (T, SelectionInfo<'a>)
where
    SEL: FnMut(&RelaySelector) -> (T, FilterCounts),
    OK: Fn(&T) -> bool,
{
    let (outcome, count_strict) = select(selector);
    let succeeded = ok(&outcome);
    if succeeded || !selector.can_relax() {
        let info = SelectionInfo {
            first_try: count_strict,
            relaxed_try: None,
            succeeded,
            in_selection: selector,
        };
        return (outcome, info);
    }
    let relaxed_selector = selector.relax();
    let (relaxed_outcome, count_relaxed) = select(&relaxed_selector);
    let info = SelectionInfo {
        first_try: count_strict,
        relaxed_try: Some(count_relaxed),
        succeeded: ok(&relaxed_outcome),
        in_selection: selector,
    };
    (relaxed_outcome, info)
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

    use std::collections::HashSet;

    use tor_basic_utils::test_rng::testing_rng;
    use tor_linkspec::{HasRelayIds, RelayId};
    use tor_netdir::{Relay, SubnetConfig};

    use super::*;
    use crate::{
        testing::{cfg, split_netdir, testnet},
        RelaySelectionConfig, TargetPort,
    };

    #[test]
    fn selector_as_predicate() {
        let nd = testnet();
        let id_4 = "$0404040404040404040404040404040404040404".parse().unwrap();
        let usage = RelayUsage::middle_relay(None);
        let exclusion = RelayExclusion::exclude_identities([id_4].into_iter().collect());
        let sel = RelaySelector::new(usage.clone(), exclusion.clone());

        let (yes, no) = split_netdir(&nd, &sel);
        let p = |r: &Relay<'_>| {
            usage.low_level_predicate_permits_relay(r)
                && exclusion.low_level_predicate_permits_relay(r)
        };
        assert!(yes.iter().all(p));
        assert!(no.iter().all(|r| !p(r)));
    }

    #[test]
    fn selector_as_filter() {
        let nd = testnet();
        let id_4 = "$0404040404040404040404040404040404040404".parse().unwrap();
        let usage = RelayUsage::middle_relay(None);
        let exclusion = RelayExclusion::exclude_identities([id_4].into_iter().collect());
        let sel = RelaySelector::new(usage.clone(), exclusion.clone());
        let mut fc = FilterCounts::new(&sel);

        let (yes, _no) = split_netdir(&nd, &sel);
        let filtered: Vec<_> = nd
            .relays()
            .filter(|r| sel.relay_usable(r, &mut fc))
            .collect();
        assert_eq!(yes.len(), filtered.len());

        let k1: HashSet<_> = yes.iter().map(|r| r.rsa_identity().unwrap()).collect();
        let k2: HashSet<_> = filtered.iter().map(|r| r.rsa_identity().unwrap()).collect();
        assert_eq!(k1, k2);

        // 6 relays are rejected for not being suitable as a general-purpose middle relay
        // (no Fast flag or no stable flag)
        assert_eq!(fc.counts[0].n_rejected, 12);
        // 1 additional relay is rejected for having id_4.
        assert_eq!(fc.counts[1].n_rejected, 1);
        // The remainder are accepted.
        assert_eq!(fc.counts[1].n_accepted, yes.len());
    }

    #[test]
    fn selector_pick_random() {
        let nd = testnet();
        let id_4 = "$0404040404040404040404040404040404040404".parse().unwrap();
        let usage = RelayUsage::middle_relay(None);
        let exclusion = RelayExclusion::exclude_identities([id_4].into_iter().collect());
        let sel = RelaySelector::new(usage.clone(), exclusion.clone());

        let (yes, _no) = split_netdir(&nd, &sel);
        let k_yes: HashSet<_> = yes.iter().map(|r| r.rsa_identity().unwrap()).collect();
        let p = |r: Relay<'_>| k_yes.contains(r.rsa_identity().unwrap());

        let mut rng = testing_rng();
        for _ in 0..50 {
            // Select one relay; make sure it is ok.
            let (r_rand, si) = sel.select_relay(&mut rng, &nd);
            assert!(si.success());
            assert!(!si.result_is_relaxed_success());
            assert!(p(r_rand.unwrap()));

            // Select 20 random relays; make sure they are distinct and ok.
            let (rs_rand, si) = sel.select_n_relays(&mut rng, 20, &nd);
            assert_eq!(rs_rand.len(), 20);
            assert!(si.success());
            assert!(!si.result_is_relaxed_success());
            assert!(rs_rand.iter().cloned().all(p));
            let k_got: HashSet<_> = rs_rand.iter().map(|r| r.rsa_identity().unwrap()).collect();
            assert_eq!(k_got.len(), 20);
        }
    }

    #[test]
    fn selector_report() {
        let nd = testnet();
        let id_4 = "$0404040404040404040404040404040404040404".parse().unwrap();
        let usage = RelayUsage::middle_relay(None);
        let exclusion = RelayExclusion::exclude_identities([id_4].into_iter().collect());
        let sel = RelaySelector::new(usage.clone(), exclusion.clone());

        let mut rng = testing_rng();
        let (_, si) = sel.select_relay(&mut rng, &nd);
        assert_eq!(
            si.to_string(),
            "Success: rejected 12/40 as useless for middle relay; 1/28 as already selected"
        );

        // Now try failing.
        // (The test network doesn't have ipv6 support.)
        let unreachable_port = TargetPort::ipv6(80);
        let sel = RelaySelector::new(
            RelayUsage::exit_to_all_ports(&cfg(), vec![unreachable_port]),
            exclusion.clone(),
        );
        let (r_none, si) = sel.select_relay(&mut rng, &nd);
        assert!(r_none.is_none());
        assert_eq!(
            si.to_string(),
            "Failed: rejected 40/40 as not exiting to desired ports; 0/0 as already selected"
        );
    }

    #[test]
    fn relax() {
        let nd = testnet();
        let id_4: RelayId = "$0404040404040404040404040404040404040404".parse().unwrap();
        let r4 = nd.by_id(&id_4).unwrap();
        let usage = RelayUsage::middle_relay(None);
        let very_silly_cfg = RelaySelectionConfig {
            long_lived_ports: cfg().long_lived_ports,
            // This should exclude everyone.
            subnet_config: SubnetConfig::new(1, 1),
        };
        let exclude_relays = vec![r4];
        let exclude_everyone =
            RelayExclusion::exclude_relays_in_same_family(&very_silly_cfg, exclude_relays);

        let mut sel = RelaySelector::new(usage.clone(), exclude_everyone.clone());
        let mut rng = testing_rng();
        let (r_none, _) = sel.select_relay(&mut rng, &nd);
        assert!(r_none.is_none());

        sel.mark_exclusion_flexible();
        let (r_some, si) = sel.select_relay(&mut rng, &nd);
        assert!(r_some.is_some());
        assert_eq!(si.to_string(), "Failed at first, then succeeded. At first, rejected 12/40 as useless for middle relay; \
                                    28/28 as in same family as already selected. \
                                    After relaxing requirements, rejected 12/40 as useless for middle relay; \
                                    0/28 as in same family as already selected");
    }
}
