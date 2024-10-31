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
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod connpt;

pub use connpt::{ParsedConnectPoint, ResolveError, ResolvedConnectPoint};

/// An action that an RPC client should take when a connect point fails.
///
/// (This terminology is taken from the spec.)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)]
pub enum ClientErrorAction {
    /// The client must stop, and must not make any more connect attempts.
    Abort,
    /// The connect point has failed; the client can continue to the next connect point.
    Decline,
}
/// An error that has a [`ClientErrorAction`].
pub trait HasClientErrorAction {
    /// Return the action that an RPC client should take based on this error.
    fn client_action(&self) -> ClientErrorAction;
}
impl HasClientErrorAction for tor_config_path::CfgPathError {
    fn client_action(&self) -> ClientErrorAction {
        // TODO RPC: Confirm that every variant of this means a configuration error
        // or an ill-formed TOML file.
        ClientErrorAction::Abort
    }
}
impl HasClientErrorAction for tor_config_path::addr::CfgAddrError {
    fn client_action(&self) -> ClientErrorAction {
        use tor_config_path::addr::CfgAddrError as CAE;
        use ClientErrorAction as A;
        match self {
            CAE::NoUnixAddressSupport(_) => A::Decline,
            CAE::Path(cfg_path_error) => cfg_path_error.client_action(),
            CAE::ConstructUnixAddress(_) => A::Abort,
            // No variants are currently captured in this pattern, but they _could_ be in the future.
            _ => A::Abort,
        }
    }
}
/// Return the ClientErrorAction for an IO error encountered
/// while accessing the filesystem.
///
/// Note that this is not an implementation of `HasClientErrorAction`:
/// We want to decline on a different set of errors for network operation.
fn fs_error_action(err: &std::io::Error) -> ClientErrorAction {
    use std::io::ErrorKind as EK;
    use ClientErrorAction as A;
    match err.kind() {
        EK::NotFound => A::Decline,
        EK::PermissionDenied => A::Decline,
        _ => A::Abort,
    }
}
