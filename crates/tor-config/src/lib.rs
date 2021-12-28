//! `tor-config`: Tools for configuration management in Arti
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! It provides low-level types for handling configuration values.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod err;
mod mut_cfg;
mod path;

pub use err::{ConfigBuildError, ReconfigureError};
pub use mut_cfg::MutCfg;
pub use path::CfgPath;

/// Rules for reconfiguring a running Arti instance.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Reconfigure {
    /// Perform no reconfiguration unless we can guarantee that all changes will be successful.
    AllOrNothing,
    /// Try to reconfigure as much as possible; warn on fields that we cannot reconfigure.
    WarnOnFailures,
    /// Don't reconfigure anything: Only check whether we can guarantee that all changes will be successful.
    CheckAllOrNothing,
}

impl Reconfigure {
    /// Called when we see a disallowed attempt to change `field`: either give a ReconfigureError,
    /// or warn and return `Ok(())`, depending on the value of `self`.
    pub fn cannot_change<S: AsRef<str>>(self, field: S) -> Result<(), ReconfigureError> {
        match self {
            Reconfigure::AllOrNothing | Reconfigure::CheckAllOrNothing => {
                Err(ReconfigureError::CannotChange {
                    field: field.as_ref().to_owned(),
                })
            }
            Reconfigure::WarnOnFailures => {
                tracing::warn!("Cannot change {} on a running client.", field.as_ref());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn reconfigure_helpers() {
        let how = Reconfigure::AllOrNothing;
        let err = how.cannot_change("the_laws_of_physics").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cannot change the_laws_of_physics on a running client.".to_owned()
        );

        let how = Reconfigure::WarnOnFailures;
        let ok = how.cannot_change("stuff");
        assert!(ok.is_ok());
        assert!(logs_contain("Cannot change stuff on a running client."));
    }
}
