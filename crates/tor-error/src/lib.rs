//! `tor-error` -- Support for error handling in Tor and Ari
//!
//! Primarily, this crate provides the [`ErrorKind`] enum,
//! and associated [`HasKind`] trait.
//!
//! There is also some other miscellany, supporting error handling in
//! crates higher up the dependency stack.

#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
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

use derive_more::Display;

mod internal;
pub use internal::*;

mod truncated;
pub use truncated::*;

/// Classification of an error arising from Arti's Tor operations
///
/// This `ErrorKind` should suffice for programmatic handling by most applications embedding Arti:
/// get the kind via [`HasKind::kind`] and compare it to the expected value(s) with equality
/// or by matching.
///
/// When forwarding or reporting errors, use the whole error (e.g., `TorError`), not just the kind:
/// the error itself will contain more detail and context which is useful to humans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Error connecting to the Tor network
    ///
    /// Perhaps the local network is not working, or perhaps the chosen relay is not working
    /// properly.  Not used for errors that occur within the Tor network, or accessing the public
    /// internet on the far side of Tor.
    #[display(fmt = "error connecting to Tor")]
    TorConnectionFailed,

    /// An attempt was made to use a Tor client for something without bootstrapping it first.
    #[display(fmt = "attempted to use unbootstrapped client")]
    BootstrapRequired,

    /// IO error accessing local persistent state
    ///
    /// Eg, disk full or permissions problem.
    /// Usually the source will be [`std::io::Error`].
    #[display(fmt = "could not read/write persistent state")]
    PersistentStateAccessFailed,

    /// Tor client's persistent state has been corrupted
    ///
    /// This could be because of a bug in the Tor code, or because something else has been messing
    /// with the data.
    ///
    /// This might also occur if the Tor code was upgraded and the new Tor is not compatible.
    #[display(fmt = "corrupted data in persistent state")]
    PersistentStateCorrupted,

    /// Tried to write to read-only persistent state.
    ///
    /// Usually, errors of this kind should be handled before the user sees
    /// them: the state manager's locking code is supposed to prevent
    /// higher level crates from accidentally trying to do this.  This
    /// error kind can indicate a bug.
    #[display(fmt = "could not write to read-only persistent state")]
    PersistentStateReadOnly,

    /// Tor client's Rust async reactor is shutting down.
    ///
    /// This likely indicates that the reactor has encountered a fatal error, or
    /// has been told to do a clean shutdown, and it isn't possible to spawn new
    /// tasks.
    #[display(fmt = "shutting down")]
    ReactorShuttingDown,

    /// Tor client's Rust async reactor could not spawn a task for unexplained
    /// reasons
    ///
    /// This is probably a bug or configuration problem in the async reactor
    /// implementation, or in arti's use of it.
    #[display(fmt = "unexplained rust async task spawn failure")]
    UnexplainedTaskSpawnFailure,

    /// An operation failed because we waited too long for an exit to do
    /// something.
    ///
    /// This error can happen if the host you're trying to connect to isn't
    /// responding to traffic. It can also happen if an exit is overloaded, and
    /// unable to answer your replies in a timely manner.
    ///
    /// In either case, trying later, or on a different circuit, might help.  
    #[display(fmt = "operation timed out at exit")]
    ExitTimeout,

    /// One or more configuration values were invalid or incompatible.
    ///
    /// This kind of error can happen if the user provides an invalid or badly
    /// formatted configuration file, if some of the options in that file are
    /// out of their ranges or unparsable, or if the options are not all
    /// compatible with one another. It can also happen if configuration options
    /// provided via APIs are out of range.
    ///
    /// If this occurs because of user configuration, it's probably best to tell
    /// the user about the error. If it occurs because of API usage, it's
    /// probably best to fix the code that causes the error.
    #[display(fmt = "invalid configuration")]
    InvalidConfig,

    /// Tried to change the configuration of a running Arti service in a way
    /// that isn't supported.
    ///
    /// This kind of error can happen when you call a `reconfigure()` method on
    /// a service (or part of a service) and the new configuration is not
    /// compatible with the previous configuration.
    #[display(fmt = "invalid configuration transition")]
    InvalidConfigTransition,

    /// Tried to look up a directory depending on the user's home directory, but
    /// the user's home directory isn't set or can't be found.
    ///
    /// This kind of error can also occur if we're running in an environment
    /// where users don't have home directories.
    ///
    /// To resolve this kind of error, either move to an OS with home
    /// directories, or make sure that all paths in the configuration are set
    /// explicitly, and do not depend on any path variables.
    #[display(fmt = "could not find a home directory")]
    NoHomeDirectory,

    /// A requested operation was not implemented by Arti.
    ///
    /// This kind of error can happen when calling an API that isn't available
    /// at runtime, or when requesting a piece of protocol functionality that is
    /// not implemented.
    ///
    /// If it happens as a result of a user activity, it's fine to ignore, log,
    /// or report the error. If it happens as a result of direct API usage, it
    /// may indicate that you're using something that isn't implemented yet, or
    /// hasn't been turned on for your build environment.
    #[display(fmt = "operation not supported")]
    NoSupport,

    /// Someone or something violated a network protocol.
    ///
    /// This kind of error can happen when a remote Tor instance behaves in a
    /// way we don't expect, or when a local program accessing us over some
    /// other protocol violates the protocol's requirements.
    ///
    /// It usually indicates a programming error: either in their implementation
    /// of the protocol, or in ours.  It can also indicate an attempted attack,
    /// though that can be hard to diagnose.
    #[display(fmt = "network protocol violation")]
    ProtocolViolation,

    /// Called a function with an invalid argument.
    ///
    /// This kind of error is usually a programming mistake on the caller's part.
    #[display(fmt = "invalid argument")]
    BadArgument,

    /// Internal error (bug) in Arti.
    ///
    /// A supposedly impossible problem has arisen.  This indicates a bug in
    /// Arti; if the Arti version is relatively recent, please report the bug on
    /// our [bug tracker](https://gitlab.torproject.org/tpo/core/arti/-/issues).
    #[display(fmt = "internal error (bug)")]
    Internal,

    /// TODO - error still needs to be categorized in tor/arti code
    ///
    /// This variant is going to be ABOLISHED!  If you see it in your code,
    /// then you are using a version of Arti from before we managed to
    /// remove every error.
    #[display(fmt = "uncategorized error (TODO)")]
    TODO,
}

/// Errors that can be categorized as belonging to an [`ErrorKind`]
///
/// The most important implementation of this trait is
/// `arti_client::TorError`; however, other internal errors throughout Arti
/// also implement it.
pub trait HasKind {
    /// Return the kind of this error.
    fn kind(&self) -> ErrorKind;
}

impl HasKind for futures::task::SpawnError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        if self.is_shutdown() {
            EK::ReactorShuttingDown
        } else {
            EK::UnexplainedTaskSpawnFailure
        }
    }
}
