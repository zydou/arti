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
///
/// # Limitations
///
/// Right now, only the `Unrestricted` filter is implemented or available.
/// This enumeration is just a place-holder, however, to make sure we're
/// checking our filter in the right places.
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone)]
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

    /// Return true if this filter excludes no guards at all.
    pub(crate) fn is_unfiltered(&self) -> bool {
        self.filters.is_empty()
    }
}

impl SingleFilter {
    /// Return true if this filter permits the provided target.
    fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        match self {
            SingleFilter::ReachableAddrs(patterns) => patterns
                .iter()
                .any(|pat| target.addrs().iter().any(|addr| pat.matches_sockaddr(addr))),
        }
    }
}
