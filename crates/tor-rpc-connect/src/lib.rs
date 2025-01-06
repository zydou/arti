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

pub mod auth;
#[cfg(feature = "rpc-client")]
pub mod client;
mod connpt;
pub mod load;
#[cfg(feature = "rpc-server")]
pub mod server;
#[cfg(test)]
mod testing;

use std::{io, sync::Arc};

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
/// Return the ClientErrorAction for an IO error encountered
/// while opening a socket.
///
/// Note that this is not an implementation of `HasClientErrorAction`:
/// We want to decline on a different set of errors for fs operation.
fn net_error_action(err: &std::io::Error) -> ClientErrorAction {
    use std::io::ErrorKind as EK;
    use ClientErrorAction as A;
    match err.kind() {
        EK::ConnectionRefused => A::Decline,
        EK::ConnectionReset => A::Decline,
        // TODO RPC: Are there other "decline" error types here?
        //
        // TODO Rust 1.83; revisit once some of `io_error_more` is stabilized.
        // see https://github.com/rust-lang/rust/pull/128316
        _ => A::Abort,
    }
}
impl HasClientErrorAction for fs_mistrust::Error {
    fn client_action(&self) -> ClientErrorAction {
        use fs_mistrust::Error as E;
        use ClientErrorAction as A;
        match self {
            E::Multiple(errs) => {
                if errs.iter().any(|e| e.client_action() == A::Abort) {
                    A::Abort
                } else {
                    A::Decline
                }
            }
            E::Io { err, .. } => fs_error_action(err),
            E::CouldNotInspect(_, err) => fs_error_action(err),

            E::NotFound(_) => A::Decline,
            E::BadPermission(_, _, _) | E::BadOwner(_, _) => A::Decline,
            E::StepsExceeded | E::CurrentDirectory(_) => A::Abort,

            // TODO RPC: Not sure about this one.
            E::BadType(_) => A::Abort,

            // These should be impossible for clients given how we use fs_mistrust in this crate.
            E::CreatingDir(_)
            | E::Content(_)
            | E::NoSuchGroup(_)
            | E::NoSuchUser(_)
            | E::MissingField(_)
            | E::InvalidSubdirectory => A::Abort,
            E::PasswdGroupIoError(_) => A::Abort,
            _ => A::Abort,
        }
    }
}

/// A failure to connect or bind to a [`ResolvedConnectPoint`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// We encountered an IO error while actually opening our socket.
    #[error("IO error while connecting")]
    Io(#[source] Arc<io::Error>),
    /// The connect point told us to abort explicitly.
    #[error("Encountered an explicit \"abort\"")]
    ExplicitAbort,
    /// We couldn't load the cookie file for cookie authentication.
    #[error("Unable to load cookie file")]
    LoadCookie(#[from] auth::CookieAccessError),
    /// We were told to connect to a socket type that we don't support.
    #[error("Unsupported socket type")]
    UnsupportedSocketType,
    /// We were told to connect using an auth type that we don't support.
    #[error("Unsupported authentication type")]
    UnsupportedAuthType,
    /// We were told to use a Unix address for which we could not extract a parent directory.
    #[error("Invalid unix address")]
    InvalidUnixAddress,
    /// Unable to access the location of a Unix address.
    #[error("Unix address access")]
    UnixAddressAccess(#[from] fs_mistrust::Error),
    /// Another process was holding a lock for this connect point,
    /// so we couldn't bind to it.
    #[error("Could not acquire lock: Another process is listening on this connect point")]
    AlreadyLocked,
}

impl From<io::Error> for ConnectError {
    fn from(err: io::Error) -> Self {
        ConnectError::Io(Arc::new(err))
    }
}
impl crate::HasClientErrorAction for ConnectError {
    fn client_action(&self) -> crate::ClientErrorAction {
        use crate::ClientErrorAction as A;
        use ConnectError as E;
        match self {
            E::Io(err) => crate::net_error_action(err),
            E::ExplicitAbort => A::Abort,
            E::LoadCookie(err) => err.client_action(),
            E::UnsupportedSocketType => A::Decline,
            E::UnsupportedAuthType => A::Decline,
            E::InvalidUnixAddress => A::Decline,
            E::UnixAddressAccess(err) => err.client_action(),
            E::AlreadyLocked => A::Abort, // (This one can't actually occur for clients.)
        }
    }
}
#[cfg(any(feature = "rpc-client", feature = "rpc-server"))]
/// Given a `general::SocketAddr`, try to return the path of its parent directory (if any).
fn socket_parent_path(addr: &tor_general_addr::general::SocketAddr) -> Option<&std::path::Path> {
    addr.as_pathname().and_then(|p| p.parent())
}

/// Default connect point for a user-owned Arti instance.
pub const USER_DEFAULT_CONNECT_POINT: &str = {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
r#"
[connect]
socket = "unix:${ARTI_LOCAL_DATA}/rpc/arti_rpc_socket"
auth = "none"
"#
        } else {
        // TODO RPC: Does this make sense as a windows default?  If so document it.
r#"
[connect]
socket = "inet:127.0.0.1:9180"
auth = { cookie = { path = "${ARTI_LOCAL_DATA}/rpc/arti_rpc_cookie" } }
"#
        }
    }
};

/// Default connect point for a system-wide Arti instance.
///
/// This is `None` if, on this platform, there is no such default connect point.
pub const SYSTEM_DEFAULT_CONNECT_POINT: Option<&str> = {
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            Some(
r#"
[connect]
socket = "unix:/var/run/arti-rpc/arti_rpc_socket"
auth = "none"
"#
            )
        } else {
            None
        }
    }
};

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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn parse_defaults() {
        let _parsed: ParsedConnectPoint = USER_DEFAULT_CONNECT_POINT.parse().unwrap();
        if let Some(s) = SYSTEM_DEFAULT_CONNECT_POINT {
            let _parsed: ParsedConnectPoint = s.parse().unwrap();
        }
    }
}
