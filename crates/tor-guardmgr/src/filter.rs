//! Implement GuardFilter and related types.

use tor_linkspec::ChanTarget;
// TODO(nickm): Conceivably, this type should be exposed from a lower-level crate than
// tor-netdoc.
use tor_netdoc::types::policy::AddrPortPattern;

/// An object specifying which relays are eligible to be guards.
///
/// We _always_ restrict the set of possible guards to be the set of
/// relays currently listed in the consensus directory document, and
/// tagged with the `Guard` flag.  But clients may narrow the eligible set
/// even further—for example, to those supporting only a given set of ports,
/// or to those in a given country.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct GuardFilter {
    /// A list of filters to apply to guard or fallback selection.  Each filter
    /// restricts which guards may be used, and possibly how those guards may be
    /// contacted.
    ///
    /// This list of filters has "and" semantics: a relay is permitted by this
    /// filter if ALL patterns in this list permit that first hop.
    filters: Vec<SingleFilter>,
}

/// A single restriction places upon usable guards.
#[derive(Debug, Clone, Eq, PartialEq)]
enum SingleFilter {
    /// A set of allowable addresses that we are willing to try to connect to.
    ///
    /// This list of patterns has "or" semantics: a guard is permitted by this filter
    /// if ANY pattern in this list permits one of the guard's addresses.
    ReachableAddrs(Vec<AddrPortPattern>),
}

impl GuardFilter {
    /// Create a new [`GuardFilter`] that doesn't restrict the set of
    /// permissible guards at all.
    pub fn unfiltered() -> Self {
        GuardFilter::default()
    }

    /// Restrict this filter to only permit connections to an address permitted
    /// by one of the patterns in `addrs`.
    pub fn push_reachable_addresses(&mut self, addrs: impl IntoIterator<Item = AddrPortPattern>) {
        self.filters
            .push(SingleFilter::ReachableAddrs(addrs.into_iter().collect()));
    }

    /// Return true if this filter permits the provided `target`.
    pub(crate) fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        self.filters.iter().all(|filt| filt.permits(target))
    }

    /// Modify `first_hop` so that it contains no elements not permitted by this
    /// filter.
    ///
    /// (For example, if we are restricted only to use certain addresses, then
    /// `permits` will return true for a guard that has multiple addresses even
    /// if _some_ of those addresses are not permitted.  In that scenario, this
    /// method will remove disallowed addresses from `first_hop`.)
    pub(crate) fn modify_hop(
        &self,
        mut first_hop: crate::FirstHop,
    ) -> Result<crate::FirstHop, crate::PickGuardError> {
        for filt in &self.filters {
            first_hop = filt.modify_hop(first_hop)?;
        }
        Ok(first_hop)
    }

    /// Return true if this filter excludes no guards at all.
    pub(crate) fn is_unfiltered(&self) -> bool {
        self.filters.is_empty()
    }

    /// Return a fraction between 0.0 and 1.0 describing what fraction of the
    /// guard bandwidth this filter permits.
    pub(crate) fn frac_bw_permitted(&self, netdir: &tor_netdir::NetDir) -> f64 {
        use tor_netdir::{RelayWeight, WeightRole};
        let mut guard_bw: RelayWeight = 0.into();
        let mut permitted_bw: RelayWeight = 0.into();
        for relay in netdir.relays() {
            if relay.is_suitable_as_guard() {
                let w = netdir.relay_weight(&relay, WeightRole::Guard);
                guard_bw += w;
                if self.permits(&relay) {
                    permitted_bw += w;
                }
            }
        }

        permitted_bw.checked_div(guard_bw).unwrap_or(1.0)
    }
}

impl SingleFilter {
    /// Return true if this filter permits the provided target.
    fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        match self {
            SingleFilter::ReachableAddrs(patterns) => {
                patterns.iter().any(|pat| {
                    match target.chan_method().socket_addrs() {
                        // Check whether _any_ address actually used by this
                        // method is permitted by _any_ pattern.
                        Some(addrs) => addrs.iter().any(|addr| pat.matches_sockaddr(addr)),
                        // This target doesn't use addresses: only hostnames or "None"
                        None => true,
                    }
                })
            }
        }
    }

    /// Modify `first_hop` so that it contains no elements not permitted by this
    /// filter.
    ///
    /// It is an internal error to call this function on a guard not already
    /// passed by `self.permits()`.
    fn modify_hop(
        &self,
        mut first_hop: crate::FirstHop,
    ) -> Result<crate::FirstHop, crate::PickGuardError> {
        match self {
            SingleFilter::ReachableAddrs(patterns) => {
                let r = first_hop
                    .chan_target_mut()
                    .chan_method_mut()
                    .retain_addrs(|addr| patterns.iter().any(|pat| pat.matches_sockaddr(addr)));

                if r.is_err() {
                    // TODO(nickm): The fact that this check needs to be checked
                    // happen indicates a likely problem in our code design.
                    // Right now, we have `modify_hop` and `permits` as separate
                    // methods because our GuardSet logic needs a way to check
                    // whether a guard will be permitted by a filter without
                    // actually altering that guard (since another filter might
                    // be used in the future that would allow the same guard).
                    //
                    // To mitigate the risk of hitting this error, we try to
                    // make sure that modify_hop is always called right after
                    // (or at least soon after) the filter is checked, with the
                    // same filter object.
                    return Err(tor_error::internal!(
                        "Tried to apply an address filter to an unsupported guard"
                    )
                    .into());
                }
            }
        }
        Ok(first_hop)
    }
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
    use super::*;
    use float_eq::assert_float_eq;
    use tor_netdir::testnet;

    #[test]
    fn permissiveness() {
        let nd = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        const TOL: f64 = 0.01;

        let non_filter = GuardFilter::default();
        assert_float_eq!(non_filter.frac_bw_permitted(&nd), 1.0, abs <= TOL);

        let forbid_all = {
            let mut f = GuardFilter::default();
            f.push_reachable_addresses(vec!["*:1".parse().unwrap()]);
            f
        };
        assert_float_eq!(forbid_all.frac_bw_permitted(&nd), 0.0, abs <= TOL);
        let net_1_only = {
            let mut f = GuardFilter::default();
            f.push_reachable_addresses(vec!["1.0.0.0/8:*".parse().unwrap()]);
            f
        };
        assert_float_eq!(net_1_only.frac_bw_permitted(&nd), 54.0 / 330.0, abs <= TOL);
    }
}
