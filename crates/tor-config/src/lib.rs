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
pub mod sources;

pub use cmdline::CmdLine;
pub use config as config_crate;
pub use educe;
pub use err::{ConfigBuildError, ReconfigureError};
pub use mut_cfg::MutCfg;
pub use paste::paste;
pub use path::{CfgPath, CfgPathError};
pub use serde;
pub use sources::ConfigurationSources;

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

/// Defines standard impls for a struct with a `Builder`, incl `Default`
///
/// **Use this.**  Do not `#[derive(Builder, Default)]`.  That latter approach would produce
/// wrong answers if builder attributes are used to specify non-`Default` default values.
///
/// # Input syntax
///
/// ```
/// use derive_builder::Builder;
/// use serde::{Deserialize, Serialize};
/// use tor_config::impl_standard_builder;
/// use tor_config::ConfigBuildError;
///
/// #[derive(Debug, Builder, Clone, Eq, PartialEq)]
/// #[builder(derive(Serialize, Deserialize, Debug))]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// struct SomeConfigStruct { }
/// impl_standard_builder! { SomeConfigStruct }
///
/// #[derive(Debug, Builder, Clone, Eq, PartialEq)]
/// struct UnusualStruct { }
/// impl_standard_builder! { UnusualStruct: !Deserialize }
/// ```
///
/// # Requirements
///
/// `$Config`'s builder must have default values for all the fields,
/// or this macro-generated self-test will fail.
/// This should be OK for all principal elements of our configuration.
///
/// `$ConfigBuilder` must have an appropriate `Deserialize` impl.
///
/// # Options
///
///  * `!Deserialize` suppresses the test case involving `Builder: Deserialize`.
///    This should not be done for structs which are part of Arti's configuration,
///    but can be appropriate for other types that use [`derive_builder`].
///
/// # Generates
///
///  * `impl Default for $Config`
///  * a self-test that the `Default` impl actually works
///  * a test that the `Builder` can be deserialized from an empty [`config::Config`],
///    and then built, and that the result is the same as the ordinary default.
//
// The implementation munches fake "trait bounds" (`: !Deserialie + !Wombat ...`) off the RHS.
// We're going to add at least one more option.
#[macro_export]
macro_rules! impl_standard_builder {
    // Convert the input into the "being processed format":
    {
        $Config:ty $(: $($options:tt)* )?
    } => { $crate::impl_standard_builder!{
        // ^Being processed format:
        @ ( try_deserialize            ) $Config    :                 $( $( $options    )* )?
        //  ~~~~~~~~~~~~~~~              ^^^^^^^    ^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        // present iff not !Deserialize  type      always present    options yet to be parsed
    } };
    // If !Deserialize is the next option, implement it by making $try_deserialize absent
    {
        @ ( $($try_deserialize:ident)? ) $Config:ty : $(+)? !Deserialize $( $options:tt )*
    } => {  $crate::impl_standard_builder!{
        @ (                            ) $Config    :                    $( $options    )*
    } };
    // Having parsed all options, produce output:
    {
        @ ( $($try_deserialize:ident)? ) $Config:ty : $(+)?
    } => { $crate::paste!{
        impl $Config {
            /// Returns a fresh, default, builder
            pub fn builder() -> [< $Config Builder >] {
                Default::default()
            }
        }

        impl Default for $Config {
            fn default() -> Self {
                // unwrap is good because one of the test cases above checks that it works!
                [< $Config Builder >]::default().build().unwrap()
            }
        }

        #[test]
        fn [< test_impl_Default_for_ $Config >] () {
            #[allow(unused_variables)]
            let def = $Config::default();

            $( // expands iff there was $try_deserialize, which is always try_deserialize
                let empty_config = $crate::config_crate::Config::builder().build().unwrap();
                let builder: [< $Config Builder >] = empty_config.$try_deserialize().unwrap();
                let from_empty = builder.build().unwrap();
                assert_eq!(def, from_empty);
            )*
        }
    } };
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
