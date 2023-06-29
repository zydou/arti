#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod err;
mod key_specifier;

#[cfg(feature = "keymgr")]
mod key_type;
#[cfg(feature = "keymgr")]
mod keystore;
#[cfg(feature = "keymgr")]
mod mgr;

#[cfg(not(feature = "keymgr"))]
mod dummy;

pub use err::{Error, KeystoreError};
pub use key_specifier::{ArtiPath, ArtiPathComponent, CTorPath, KeySpecifier};

#[cfg(feature = "keymgr")]
#[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
pub use {
    key_type::KeyType,
    keystore::arti::ArtiNativeKeystore,
    keystore::{EncodableKey, ErasedKey, Keystore, ToEncodableKey},
    mgr::KeyMgr,
};

#[cfg(not(feature = "keymgr"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "keymgr"))))]
pub use dummy::*;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;
