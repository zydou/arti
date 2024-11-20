#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
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
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO: write more comprehensive documentation when the API is a bit more
// stable

mod arti_path;
pub mod config;
mod err;
mod key_specifier;
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

#[cfg(feature = "keymgr")]
mod keystore;
#[cfg(feature = "keymgr")]
mod mgr;

#[cfg(not(feature = "keymgr"))]
mod dummy;

pub use arti_path::{ArtiPath, DENOTATOR_SEP};
pub use err::{
    ArtiPathSyntaxError, Error, KeystoreCorruptionError, KeystoreError, UnknownKeyTypeError,
};
pub use key_specifier::{
    ArtiPathRange, ArtiPathUnavailableError, CTorPath, CTorServicePath,
    InvalidKeyPathComponentValue, KeyCertificateSpecifier, KeyPath, KeyPathError, KeyPathInfo,
    KeyPathInfoBuilder, KeyPathInfoExtractor, KeyPathPattern, KeySpecifier, KeySpecifierComponent,
    KeySpecifierComponentViaDisplayFromStr, KeySpecifierPattern,
};

#[cfg(feature = "keymgr")]
#[cfg_attr(docsrs, doc(cfg(feature = "keymgr")))]
pub use {
    keystore::arti::ArtiNativeKeystore,
    keystore::Keystore,
    mgr::{KeyMgr, KeyMgrBuilder, KeyMgrBuilderError, KeystoreEntry},
    ssh_key,
};

#[cfg(all(feature = "keymgr", feature = "ephemeral-keystore"))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "keymgr", feature = "ephemeral-keystore")))
)]
pub use keystore::ephemeral::ArtiEphemeralKeystore;

#[cfg(all(feature = "keymgr", feature = "ctor-keystore"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "keymgr", feature = "ctor-keystore"))))]
pub use keystore::ctor::{CTorClientKeystore, CTorServiceKeystore};

#[doc(hidden)]
pub use key_specifier::derive as key_specifier_derive;

pub use tor_key_forge::{
    EncodableKey, ErasedKey, KeyType, Keygen, KeygenRng, SshKeyAlgorithm, SshKeyData,
    ToEncodableKey,
};

derive_deftly::template_export_semver_check! { "0.12.1" }

#[cfg(not(feature = "keymgr"))]
#[cfg_attr(docsrs, doc(cfg(not(feature = "keymgr"))))]
pub use dummy::*;

/// A boxed [`Keystore`].
pub(crate) type BoxedKeystore = Box<dyn Keystore>;

#[doc(hidden)]
pub use {derive_deftly, inventory};

use derive_more::{AsRef, Display, From};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An identifier for a particular [`Keystore`] instance.
//
// TODO (#1193): restrict the charset of this ID
#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Display, AsRef,
)]
#[serde(transparent)]
#[non_exhaustive]
pub struct KeystoreId(String);

impl FromStr for KeystoreId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(s.into()))
    }
}

/// Specifies which keystores a [`KeyMgr`] operation should apply to.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash, From)]
#[non_exhaustive]
pub enum KeystoreSelector<'a> {
    /// Try to use the keystore with the specified ID.
    Id(&'a KeystoreId),
    /// Use the primary key store.
    #[default]
    Primary,
}
