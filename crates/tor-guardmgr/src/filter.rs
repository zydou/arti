//! Implement GuardFilter and related types.

use educe::Educe;

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
#[derive(Debug, Clone, Educe)]
#[educe(Default)]
#[non_exhaustive]
pub enum GuardFilter {
    /// A filter representing no restrictions on the permissible guards
    /// at all.
    #[educe(Default)]
    Unfiltered,

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
        GuardFilter::Unfiltered
    }

    /// Return true if this filter permits the provided `target`.
    pub(crate) fn permits<C: ChanTarget>(&self, target: &C) -> bool {
        let _ = target; // ignored for now, since only Unfiltered exists.
        match self {
            GuardFilter::Unfiltered => true,
            #[cfg(test)]
            GuardFilter::TestingLimitKeys => target.rsa_identity().as_bytes()[0] & 3 == 0,
        }
    }

    /// Return true if this filter excludes no guards at all.
    pub(crate) fn is_unfiltered(&self) -> bool {
        matches!(self, GuardFilter::Unfiltered)
    }
}
