//! Implement GuardFilter and related types.

use tor_linkspec::ChanTarget;

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
    filters: Vec<SingleFilter>,
}

/// A single restriction places upon usable guards.
#[derive(Debug, Clone)]
enum SingleFilter {
    /// Testing only: checks whether the first byte of the rsa key is 0 modulo 4.
    ///
    /// TODO: remove this once real filters are implemented.
    #[cfg(test)]
    #[allow(dead_code)]
    TestingLimitKeys,
}

impl GuardFilter {
    /// Create a new [`GuardFilter`] that doesn't restrict the set of
    /// permissible guards at all.
    pub fn unfiltered() -> Self {
        GuardFilter::default()
    }

    /// Return true if this filter permits the provided `target`.
    pub(crate) fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        self.filters.iter().all(|filt| filt.permits(target))
    }

    /// Return true if this filter excludes no guards at all.
    pub(crate) fn is_unfiltered(&self) -> bool {
        self.filters.is_empty()
    }

    /// Add a restriction to this filter that keys must have their final two
    /// bits of their first byte are set to 0.
    ///
    /// TODO: this testing-only, and is getting killed off once we have real filter
    #[cfg(test)]
    pub(crate) fn push_key_limit(&mut self) {
        self.filters.push(SingleFilter::TestingLimitKeys);
    }
}

impl SingleFilter {
    /// Return true if this filter permits the provided target.
    fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        // TODO: This is ugly, but the whole function will get rewritten once we
        // have a real filter.
        #[cfg(test)]
        match self {
            SingleFilter::TestingLimitKeys => target.rsa_identity().as_bytes()[0] & 3 == 0,
        }
        #[cfg(not(test))]
        {
            let _ = target;
            true
        }
    }
}
