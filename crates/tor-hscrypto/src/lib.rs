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
#![allow(dead_code, unused_variables)]

mod macros;
pub mod ops;
pub mod pk;
pub mod time;

use macros::define_bytes;

define_bytes! {
/// A value to identify an onion service during a given period. (`N_hs_subcred`)
///
/// This is computed from the onion service's public ID and the blinded ID for
/// the current time period.
///
/// Given this piece of information, the original public ID and blinded ID cannot
/// be re-derived.
#[derive(Copy, Clone, Debug)]
pub struct Subcredential([u8; 32]);
}

/// Counts which revision of an onion service descriptor is which, within a
/// given time period.
///
/// There can be gaps in this numbering. A descriptor with a higher-valued
/// revision counter supersedes one with a lower revision counter.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct RevisionCounter(u64);

define_bytes! {
/// An opaque value `RENDEZVOUS_COOKIE` used at a rendezvous point to match clients and services.
///
/// See rend-spec-v3 s4.1.
///
/// The client includes this value to the rendezvous point in its
/// `ESTABLISH_RENDEZVOUS` message; the service later provides the same value in its
/// `RENDEZVOUS1` message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RendCookie([u8; 20]);
}
