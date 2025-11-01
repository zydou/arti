#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

mod address;
mod builder;
mod client;
mod protostatus;
mod release_date;
#[cfg(feature = "rpc")]
pub mod rpc;
mod util;

pub mod config;
pub mod status;

pub use address::{DangerouslyIntoTorAddr, IntoTorAddr, TorAddr, TorAddrError};
pub use builder::{MAX_LOCAL_RESOURCE_TIMEOUT, TorClientBuilder};
pub use client::{BootstrapBehavior, DormantMode, InertTorClient, StreamPrefs, TorClient};
pub use config::TorClientConfig;

pub use tor_circmgr::IsolationToken;
pub use tor_circmgr::isolation;
pub use tor_error::{ErrorKind, HasKind};
pub use tor_proto::client::stream::{DataReader, DataStream, DataWriter};

mod err;
pub use err::{Error, ErrorHint, HintableError};

#[cfg(feature = "error_detail")]
pub use err::ErrorDetail;

/// Alias for the [`Result`] type corresponding to the high-level [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "experimental-api")]
pub use builder::DirProviderBuilder;

#[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
pub use {
    tor_hscrypto::pk::{HsClientDescEncKey, HsId},
    tor_keymgr::KeystoreSelector,
};

#[cfg(feature = "geoip")]
pub use tor_geoip::CountryCode;

/// Return a list of the protocols [supported](tor_protover::doc_supported) by this crate.
///
/// (This is a crate-private method so as not to expose tor_protover in our public API.)
///
/// *WARNING*: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
/// SEE [`tor_protover::doc_changing`]
pub(crate) fn supported_protocols() -> tor_protover::Protocols {
    let protocols = tor_proto::supported_client_protocols()
        .union(&tor_netdoc::supported_protocols())
        .union(&tor_dirmgr::supported_client_protocols());

    // TODO: the behavior for here seems most questionable!
    // We will warn if any hs protocol happens to be recommended and we do not support onion
    // services.
    // We will also fail to warn if any hs protocol is required, and we support it only as a client
    // or only as a service.
    // We ought to determine the right behavior here.
    // See torspec#319 at https://gitlab.torproject.org/tpo/core/torspec/-/issues/319.
    #[cfg(feature = "onion-service-service")]
    let protocols = protocols.union(&tor_hsservice::supported_hsservice_protocols());
    #[cfg(feature = "onion-service-client")]
    let protocols = protocols.union(&tor_hsclient::supported_hsclient_protocols());

    let hs_protocols = {
        // As a temporary workaround (again see torspec#319) we are unconditionally adding the
        // conditionally supported HSService protocols.
        use tor_protover::named::*;
        [
            //
            HSINTRO_V3,
            HSINTRO_RATELIM,
            HSREND_V3,
            HSDIR_V3,
        ]
        .into_iter()
        .collect()
    };

    protocols.union(&hs_protocols)
}

/// Return the approximate release date of this version of arti client.
///
/// See[`release_date::ARTI_CLIENT_RELEASE_DATE`] for rationale.
pub(crate) fn software_release_date() -> std::time::SystemTime {
    use time::OffsetDateTime;

    let format = time::macros::format_description!("[year]-[month]-[day]");
    let date = time::Date::parse(release_date::ARTI_CLIENT_RELEASE_DATE, &format)
        .expect("Invalid hard-coded release date!?");
    OffsetDateTime::new_utc(date, time::Time::MIDNIGHT).into()
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

    use cfg_if::cfg_if;

    use super::*;

    #[test]
    fn protocols_enforced() {
        let pr = supported_protocols();

        for recommendation in [
            // Required in consensus as of 2024-04-02
            "Cons=2 Desc=2 Link=4 Microdesc=2 Relay=2",
            // Recommended in consensus as of 2024-04-02
            "Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2",
            // Required by c-tor main-branch authorities as of 2024-04-02
            "Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2",
            // // Recommended by c-tor main-branch authorities as of 2024-04-02
            // TODO: (Cannot deploy yet, see below.)
            // "Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4",
        ] {
            let rec: tor_protover::Protocols = recommendation.parse().unwrap();

            let unsupported = rec.difference(&pr);

            assert!(unsupported.is_empty(), "{} not supported", unsupported);
        }

        // TODO: Revise this once congestion control is fully implemented and always-on.
        {
            // Recommended by c-tor main-branch authorities as of 2024-04-02
            let rec: tor_protover::Protocols =
                "Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 \
                 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4"
                    .parse()
                    .unwrap();

            // Although this is recommended, it isn't always-on in Arti yet yet.
            cfg_if! {
                if #[cfg(feature="flowctl-cc")] {
                     let permitted_missing: tor_protover::Protocols =
                        [].into_iter().collect();
                } else {
                    let permitted_missing: tor_protover::Protocols =
                        [tor_protover::named::FLOWCTRL_CC].into_iter().collect();
                }
            }
            let unsupported = rec.difference(&pr);
            assert!(unsupported.difference(&permitted_missing).is_empty());
        }
    }

    #[test]
    fn release_date_format() {
        // Make sure we can parse the release date.
        let _d: std::time::SystemTime = software_release_date();
    }
}
