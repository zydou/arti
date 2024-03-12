#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
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
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod config;
mod restriction;
mod selector;
mod target_port;
mod usage;

pub use config::RelaySelectionConfig;
pub use restriction::{RelayExclusion, RelayRestriction};
pub use selector::{RelaySelector, SelectionInfo};
pub use target_port::TargetPort;
pub use usage::RelayUsage;

/// A property that can be provided by relays.
///
/// The predicates that implement this trait are typically lower level ones that
/// represent only some of the properties that need to be checked before a relay
/// can be used.  Code should generally use RelaySelector instead.
pub trait LowLevelRelayPredicate {
    /// Return true if `relay` provides this predicate.
    fn low_level_predicate_permits_relay(&self, relay: &tor_netdir::Relay<'_>) -> bool;
}

/// Helper module for our tests.
#[cfg(test)]
pub(crate) mod testing {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use crate::{LowLevelRelayPredicate, RelaySelectionConfig};
    use once_cell::sync::Lazy;
    use std::collections::HashSet;
    use tor_netdir::{NetDir, Relay, SubnetConfig};
    use tor_netdoc::doc::netstatus::RelayFlags;

    /// Use a predicate to divide a NetDir into the relays that do and do not
    /// conform (respectively).
    ///
    /// # Panics
    ///
    /// Panics if either the "yes" list or the "no" list is empty, to ensure
    /// that all of our tests are really testing something.
    pub(crate) fn split_netdir<'a, P: LowLevelRelayPredicate>(
        netdir: &'a NetDir,
        pred: &P,
    ) -> (Vec<Relay<'a>>, Vec<Relay<'a>>) {
        let (yes, no): (Vec<_>, Vec<_>) = netdir
            .relays()
            .partition(|r| pred.low_level_predicate_permits_relay(r));
        assert!(!yes.is_empty());
        assert!(!no.is_empty());
        (yes, no)
    }

    /// Return a basic configuration.
    pub(crate) fn cfg() -> RelaySelectionConfig<'static> {
        static STABLE_PORTS: Lazy<HashSet<u16>> = Lazy::new(|| [22].into_iter().collect());
        RelaySelectionConfig {
            long_lived_ports: &STABLE_PORTS,
            subnet_config: SubnetConfig::default(),
        }
    }

    // Construct a test network to exercise the various cases in this crate.
    pub(crate) fn testnet() -> NetDir {
        tor_netdir::testnet::construct_custom_netdir(|idx, node| {
            if idx % 7 == 0 {
                node.rs.clear_flags(RelayFlags::FAST);
            }
            if idx % 5 == 0 {
                node.rs.clear_flags(RelayFlags::STABLE);
            };
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap()
    }
}
