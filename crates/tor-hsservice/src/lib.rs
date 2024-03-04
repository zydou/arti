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

use std::fmt::{self, Display};
use std::str::FromStr;

use derive_adhoc::Adhoc;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use thiserror::Error;

use tor_basic_utils::impl_debug_hex;
use tor_keymgr::KeySpecifierComponentViaDisplayFromStr;

#[macro_use] // SerdeStringOrTransparent
mod time_store;

mod anon_level;
pub mod config;
mod err;
mod helpers;
mod ipt_establish;
mod ipt_lid;
mod ipt_mgr;
mod ipt_set;
mod keys;
mod netdir;
mod nickname;
mod publish;
mod rend_handshake;
mod replay;
mod req;
pub mod status;
mod svc;
mod timeout_track;

// rustdoc doctests can't use crate-public APIs, so are broken if provided for private items.
// So we export the whole module again under this name.
// Supports the Example in timeout_track.rs's module-level docs.
//
// Any out-of-crate user needs to write this ludicrous name in their code,
// so we don't need to put any warnings in the docs for the individual items.)
//
// (`#[doc(hidden)] pub mod timeout_track;` would work for the test but it would
// completely suppress the actual documentation, which is not what we want.)
#[doc(hidden)]
pub mod timeout_track_for_doctests_unstable_no_semver_guarantees {
    pub use crate::timeout_track::*;
}
#[doc(hidden)]
pub mod time_store_for_doctests_unstable_no_semver_guarantees {
    pub use crate::time_store::*;
}

pub use anon_level::Anonymity;
pub use config::OnionServiceConfig;
pub use err::{ClientError, EstablishSessionError, FatalError, IntroRequestError, StartupError};
pub use ipt_mgr::IptError;
pub use keys::{
    BlindIdKeypairSpecifier, BlindIdPublicKeySpecifier, DescSigningKeypairSpecifier,
    HsIdKeypairSpecifier, HsIdPublicKeySpecifier,
};
pub use nickname::{HsNickname, InvalidNickname};
pub use req::{RendRequest, StreamRequest};
pub use crate::netdir::NetdirProviderShutdown;
pub use publish::UploadError as DescUploadError;
pub use svc::{OnionService, RunningOnionService};

use err::IptStoreError;
use ipt_lid::{InvalidIptLocalId, IptLocalId};

pub use helpers::handle_rend_requests;
