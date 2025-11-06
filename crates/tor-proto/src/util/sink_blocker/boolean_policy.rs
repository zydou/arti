//! Implement a sink-blocking policy based on a simple blocked/unblocked status.

use super::Policy;
use tor_error::{Bug, internal};

/// A simple two-state sink-blocking [`Policy`] .
#[derive(Debug, Clone, Copy)]
pub(crate) enum BooleanPolicy {
    /// The sink is blocked.
    Blocked,
    /// The sink is not blocked.
    Unblocked,
}

impl Policy for BooleanPolicy {
    fn is_blocking(&self) -> bool {
        matches!(self, BooleanPolicy::Blocked)
    }

    // Correctness: This method doesn't change `self`.
    // There are no other methods taking `&mut self`.
    // Therefore the invariants of Policy are trivially preserved.
    fn take_one(&mut self) -> Result<(), Bug> {
        match self {
            BooleanPolicy::Blocked => {
                Err(internal!("Tried to take_one on a blocked BooleanPolicy!"))
            }
            BooleanPolicy::Unblocked => Ok(()),
        }
    }
}

impl<S> super::SinkBlocker<S, BooleanPolicy> {
    /// Put this `SinkBlocker` into a blocked state.
    pub(crate) fn set_blocked(&mut self) {
        self.update_policy(BooleanPolicy::Blocked);
    }

    /// Put this `SinkBlocker` into an unblocked state.
    pub(crate) fn set_unblocked(&mut self) {
        // Correctness: Note that this _replaces_ the Policy object,
        // and does not modify an existing Policy object.
        // This is the permitted way to make a SinkBlocker unblocked.
        self.update_policy(BooleanPolicy::Unblocked);
    }
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn boolean_policy() {
        let mut blocked = BooleanPolicy::Blocked;
        assert_eq!(blocked.is_blocking(), true);
        assert!(blocked.take_one().is_err());
        assert_eq!(blocked.is_blocking(), true);

        let mut unblocked = BooleanPolicy::Unblocked;
        assert_eq!(unblocked.is_blocking(), false);
        assert!(unblocked.take_one().is_ok());
        assert_eq!(unblocked.is_blocking(), false);
    }
}
