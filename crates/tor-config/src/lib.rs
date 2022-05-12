//! `tor-config`: Tools for configuration management in Arti
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! It provides low-level types for handling configuration values.
//!
//! # ⚠ Stability Warning ⚠
//!
//! The design of this crate, and of the configuration system for
//! Arti, is likely to change significantly before the release of Arti
//! 1.0.0.  For more information see ticket [#285].
//!
//! [#285]: https://gitlab.torproject.org/tpo/core/arti/-/issues/285

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
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

pub mod cmdline;
mod err;
pub mod list_builder;
mod mut_cfg;
mod path;

pub use cmdline::CmdLine;
pub use educe;
pub use err::{ConfigBuildError, ReconfigureError};
pub use mut_cfg::MutCfg;
pub use paste::paste;
pub use path::{CfgPath, CfgPathError};
pub use serde;

pub use tor_basic_utils::macro_first_nonempty;

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

/// Defines `Default` for a struct with a `Builder`.  Use this, not `derive`.
///
/// Use this.  Do not `#[derive(Builder, Default)]`.  That latter approach would produce
/// wrong answers if builder attributes are used to specify non-`Default` default values.
///
/// `$Config`'s builder must have default values for all the fields,
/// or this macro-generated self-test will fail.
/// This should be OK for all elements of our configuration.
#[macro_export]
macro_rules! impl_default_via_builder { {
    $Config:ty
} => {
    $crate::paste!{
        impl Default for $Config {
            fn default() -> Self {
                // unwrap is good because the test case above checks that it works!
                [< $Config Builder >]::default().build().unwrap()
            }
        }

        #[test]
        fn [< test_impl_Default_for_ $Config >] () { let _ = $Config::default(); }
    }
} }

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
