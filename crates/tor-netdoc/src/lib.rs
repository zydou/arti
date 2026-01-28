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
#![deny(clippy::unused_async)]
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(not(all(feature = "full", feature = "experimental")), allow(unused))]

#[macro_use]
mod derive_common;
#[cfg(feature = "parse2")]
#[macro_use]
pub mod parse2;
#[cfg(feature = "encode")]
#[macro_use]
pub mod encode;
#[macro_use]
pub(crate) mod parse;
pub mod doc;
mod err;
pub mod types;
mod util;

#[cfg(all(test, feature = "parse2", feature = "encode"))]
mod test2;

#[doc(hidden)]
pub use derive_deftly;

// Use `#[doc(hidden)]` rather than pub(crate), because otherwise the doctest
// doesn't work.
#[doc(hidden)]
pub use util::batching_split_before;

pub use err::{BuildError, Error, NetdocErrorKind, Pos};

#[cfg(feature = "encode")]
#[cfg_attr(docsrs, doc(cfg(feature = "encode")))]
pub use encode::NetdocBuilder;

/// Alias for the Result type returned by most objects in this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Alias for the Result type returned by document-builder functions in this
/// module.
pub type BuildResult<T> = std::result::Result<T, BuildError>;

/// Keywords that can be encoded (written) into a (being-built) network document
pub trait KeywordEncodable {
    /// Encoding of the keyword.
    ///
    /// Used for error reporting, and also by `NetdocEncoder::item`.
    fn to_str(self) -> &'static str;
}

impl KeywordEncodable for &'static str {
    fn to_str(self) -> &'static str {
        self
    }
}

/// Indicates whether we should parse an annotated list of objects or a
/// non-annotated list.
#[derive(PartialEq, Debug, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum AllowAnnotations {
    /// Parsing a document where items might be annotated.
    ///
    /// Annotations are a list of zero or more items with keywords
    /// beginning with @ that precede the items that are actually part
    /// of the document.
    AnnotationsAllowed,
    /// Parsing a document where annotations are not allowed.
    AnnotationsNotAllowed,
}

/// A "normally formatted" argument to a netdoc item
///
/// A type that is represented as a single argument
/// whose representation is as for the type's `FromStr` and `Display`.
///
/// Implementing this trait enables a blanket impl of `parse2::ItemArgumentParseable`
/// and `build::ItemArgument`.
pub trait NormalItemArgument: std::str::FromStr + std::fmt::Display {}
// TODO: should we implement ItemArgument for, say, tor_llcrypto::pk::rsa::RsaIdentity ?
// It's not clear whether it's always formatted the same way in all parts of the spec.
// The Display impl of RsaIdentity adds a `$` which is not supposed to be present
// in (for example) an authority certificate (authcert)'s "fingerprint" line.

impl NormalItemArgument for usize {}
impl NormalItemArgument for u8 {}
impl NormalItemArgument for u16 {}
impl NormalItemArgument for u32 {}
impl NormalItemArgument for u64 {}
impl NormalItemArgument for u128 {}

impl NormalItemArgument for isize {}
impl NormalItemArgument for i8 {}
impl NormalItemArgument for i16 {}
impl NormalItemArgument for i32 {}
impl NormalItemArgument for i64 {}
impl NormalItemArgument for i128 {}

impl NormalItemArgument for String {}

/// Return a list of the protocols [supported](tor_protover::doc_supported)
/// by this crate.
pub fn supported_protocols() -> tor_protover::Protocols {
    use tor_protover::named::*;
    // WARNING: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
    // SEE [`tor_protover::doc_changing`]
    [
        DESC_CROSSSIGN,
        DESC_NO_TAP,
        DESC_FAMILY_IDS,
        MICRODESC_ED25519_KEY,
        MICRODESC_NO_TAP,
        CONS_ED25519_MDS,
    ]
    .into_iter()
    .collect()
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
    fn protocols() {
        let pr = supported_protocols();
        let expected = "Cons=2 Desc=2-4 Microdesc=2-3".parse().unwrap();
        assert_eq!(pr, expected);
    }
}
