//! `tor-config`: Tools for configuration management in Arti
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! It provides types for handling configuration values,
//! and general machinery for configuration management.
//!
//! # Configuration in Arti
//!
//! The configuration for the `arti` command line program,
//! and other programs which embed Arti reusing the configuration machinery,
//! works as follows:
//!
//!  1. We use [`tor_config::ConfigurationSources`](ConfigurationSources)
//!     to enumerate the various places
//!     where configuration information needs to come from,
//!     and configure how they are to be read.
//!     `arti` uses [`ConfigurationSources::from_cmdline`].
//!
//!  2. [`ConfigurationSources::load`] actually *reads* all of these sources,
//!     parses them (eg, as TOML files),
//!     and returns a [`config::Config`].
//!     This is a tree-structured dynamically typed data structure,
//!     mirroring the input configuration structure, largely unvalidated,
//!     and containing everything in the input config sources.
//!
//!  3. We call one of the [`tor_config::resolve`](resolve) family.
//!     This maps the input configuration data to concrete `ConfigBuilder `s
//!     for the configuration consumers within the program.
//!     (For `arti`, that's `TorClientConfigBuilder` and `ArtiBuilder`).
//!     This mapping is done using the `Deserialize` implementations on the `Builder`s.
//!     `resolve` then calls the `build()` method on each of these parts of the configuration
//!     which applies defaults and validates the resulting configuation.
//!
//!     It is important to call `resolve` *once* for *all* the configuration consumers,
//!     so that it sees a unified view of which config settings in the input
//!     were unrecognized, and therefore may need to be reported to the user.
//!     See the example in the [`load`] module documentation.
//!
//!  4. The resulting configuration objects (eg, `TorClientConfig`, `ArtiConfig`)
//!     are provided to the code that must use them (eg, to make a `TorClient`).
//!
//! See the
//! [`tor_config::load` module-level documentation](load).
//! for an example.
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
pub mod load;
mod mut_cfg;
mod path;
pub mod sources;

pub use cmdline::CmdLine;
pub use config as config_crate;
pub use educe;
pub use err::{ConfigBuildError, ReconfigureError};
pub use load::{resolve, resolve_ignore_unrecognized, resolve_return_unrecognized};
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
/// impl_standard_builder! { UnusualStruct: !Deserialize + !Builder }
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
///  * `!Builder` suppresses the impl of the [`tor_config::load::Builder`](load::Builder) trait
///    This will be necessary if the error from the builder is not [`ConfigBuildError`].
///
/// # Generates
///
///  * `impl Default for $Config`
///  * `impl Builder for $ConfigBuilder`
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
        @ ( Builder                    )
          ( try_deserialize            ) $Config    :                 $( $( $options    )* )?
        //  ~~~~~~~~~~~~~~~              ^^^^^^^    ^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        // present iff not !Builder
        // present iff not !Deserialize  type      always present    options yet to be parsed
    } };
    // If !Deserialize is the next option, implement it by making $try_deserialize absent
    {
        @ ( $($Builder        :ident)? )
          ( $($try_deserialize:ident)? ) $Config:ty : $(+)? !Deserialize $( $options:tt )*
    } => {  $crate::impl_standard_builder!{
        @ ( $($Builder              )? )
          (                            ) $Config    :                    $( $options    )*
    } };
    // If !Builder is the next option, implement it by making $Builder absent
    {
        @ ( $($Builder        :ident)? )
          ( $($try_deserialize:ident)? ) $Config:ty : $(+)? !Builder     $( $options:tt )*
    } => {  $crate::impl_standard_builder!{
        @ (                            )
          ( $($try_deserialize      )? ) $Config    :                    $( $options    )*
    } };
    // Having parsed all options, produce output:
    {
        @ ( $($Builder        :ident)? )
          ( $($try_deserialize:ident)? ) $Config:ty : $(+)?
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

        $( // expands iff there was $Builder, which is always Builder
            impl $crate::load::$Builder for [< $Config Builder >] {
                type Built = $Config;
                fn build(&self) -> Result<$Config, $crate::ConfigBuildError> {
                    [< $Config Builder >]::build(self)
                }
            }
        )?

        #[test]
        #[allow(non_snake_case)]
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
