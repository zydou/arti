//! Consensus method, including checked wrapper type

use super::*;

/// Consensus method that is supported by this crate
///
/// Contains a `ConsensusMethod`, with the additional invariant that it's supported here.
///
/// Taken as an argument by at least all pub entrypoints that might be influenced
/// by the consensus method, so also functions as a proof token that we are running
/// for a supported method.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)] //
#[derive(derive_more::Display, derive_more::Deref, derive_more::Into)]
pub struct SupportedConsensusMethod(ConsensusMethod);

/// Unsupported consensus method error
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, thiserror::Error)]
#[error("unsupported consensus method {requested_method}")]
pub struct UnsupportedConsensusMethod {
    /// the method number
    requested_method: ConsensusMethod,
}

impl TryFrom<ConsensusMethod> for SupportedConsensusMethod {
    type Error = UnsupportedConsensusMethod;
    fn try_from(requested_method: ConsensusMethod) -> Result<Self, Self::Error> {
        if SUPPORTED_METHODS
            .iter()
            .any(|r| r.contains(&requested_method))
        {
            Ok(SupportedConsensusMethod(requested_method))
        } else {
            Err(UnsupportedConsensusMethod { requested_method })
        }
    }
}

impl SupportedConsensusMethod {
    /// Iterate over all supported methods
    pub fn iter_all() -> impl Iterator<Item = SupportedConsensusMethod> {
        SUPPORTED_METHODS
            .iter()
            .flat_map(|r| map_range(r, |b| u32::from(*b)))
            .map(|v: u32| {
                SupportedConsensusMethod::try_from(ConsensusMethod(v))
                    .expect("from our own ranges of supported methods")
            })
    }
}

// Convenience impl so you can write write (eg) method < 110 rather than **method < 110.
impl PartialOrd<u32> for SupportedConsensusMethod {
    fn partial_cmp(&self, other: &u32) -> Option<cmp::Ordering> {
        u32::partial_cmp(&(**self).0, other)
    }
}
impl PartialEq<u32> for SupportedConsensusMethod {
    fn eq(&self, other: &u32) -> bool {
        u32::eq(&(**self).0, other)
    }
}

impl SupportedConsensusMethod {
    /// Most recent method supported here
    #[cfg(test)]
    pub(crate) const MAX: SupportedConsensusMethod =
        SupportedConsensusMethod(*SUPPORTED_METHODS.last().unwrap().end());
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn basic() {
        let v: SupportedConsensusMethod =
            ConsensusMethod(crate::consensus::SUPPORTED_METHODS[0].start().0)
                .try_into()
                .unwrap();

        assert!(v >= 100); // our methods are defined to start at 100
        assert_eq!(v.to_string(), u32::from(v.0).to_string(),);

        let e = SupportedConsensusMethod::try_from(ConsensusMethod(10_000)).unwrap_err();
        let m = e.to_string();
        assert!(m.contains("unsupported consensus method 10000"), "{m:?}");
    }

    #[test]
    fn iter_all() {
        println!("{:?}", SupportedConsensusMethod::iter_all().collect_vec());
    }
}
