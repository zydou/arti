//! Consensus methods

use crate::internal_prelude::*;

mod ip_summary;
mod method;

pub use method::*;

/// Supported consensus methods
///
/// Not guaranteed to be minimal, but guaranteed to be well-formed,
/// sorted and non-overlapping.
///
/// See <https://spec.torproject.org/dir-spec/computing-consensus.html#consensus-method-list>
/// for where these values come from.
///
/// In tor-dirauth, we use literal numeric constants for consensus method values,
/// rather than trying to give each consensus method a named `const`.
pub const SUPPORTED_METHODS: &[RangeInclusive<ConsensusMethod>] = {
    use ConsensusMethod as M;
    &[
        // This list is where the set of supported methods is defined.
        // Only values listed here can be made into a `SupportedConsensusMethod`.
        //
        M(100)..=M(100),
    ]
};

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
    fn supported_well_formed() {
        for r in SUPPORTED_METHODS {
            assert!(r.start() <= r.end());
        }
        for pair in SUPPORTED_METHODS.windows(2) {
            assert!(pair[0].end() < pair[1].start());
        }
    }
}
