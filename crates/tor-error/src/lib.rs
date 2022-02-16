//! `tor-error` -- Support for error handling in Tor and Ari
//!
//! Primarily, this crate provides the [`ErrorKind`] enum,
//! and associated [`HasKind`] trait.
//!
//! There is also some other miscellany, supporting error handling in
//! crates higher up the dependency stack.

#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
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
    ///
    /// The only available remedy is to tear down the service and make a fresh
    /// one (for example, by making a new `TorClient`).
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
    /// This kind of error can happen when requesting a piece of protocol
    /// functionality that has not (yet) been implemented in the Arti project.
    ///
    /// If it happens as a result of a user activity, it's fine to ignore, log,
    /// or report the error. If it happens as a result of direct API usage, it
    /// may indicate that you're using something that isn't implemented yet.
    ///
    /// This kind can relate both to operations which we plan to implement, and
    /// to operations which we do not.  It does not relate to faciities which
    /// are disabled (e.g. at build time) or harmful.
    ///
    /// It can refer to facilities which were once implemented in Tor or Arti
    /// but for which support has been removed.
    #[display(fmt = "operation not implemented")]
    NotImplemented,

    /// A feature was requested which has been disabled in this build of Arti.
    ///!
    /// This kind of error happens when the running Arti was built wityout the
    /// appropriate feature (usually, cargo feature) enabled.
    ///!
    /// This might indicate that the overall running system has been
    /// mis-configured at build-time.  Alternatively, it can occur if the
    /// running system is deliberately stripped down, in which case it might be
    /// reasonable to simply report this error to a user.
    #[display(fmt = "operation not supported because Arti feature disabled")]
    FeatureDisabled,

    /// Someone or something local violated a network protocol.
    ///
    /// This kind of error can happen when a local program accessing us over some
    /// other protocol violates the protocol's requirements.
    ///
    /// This usually indicates a programming error: either in that program's
    /// implementation of the protocol, or in ours.  In any case, the problem
    /// is with software on the local system (or otherwise sharing a Tor client).
    ///
    /// It might also occur if the local system has an incompatible combination of
    ///
    #[display(fmt = "local protocol violation (local bug or incompatibility)")]
    LocalProtocolViolation,

    /// Someone or something on the Tor network violated the Tor protocols.
    ///
    /// This kind of error can happen when a remote Tor instance behaves in a
    /// way we don't expect.
    ///
    /// It usually indicates a programming error: either in their implementation
    /// of the protocol, or in ours.  It can also indicate an attempted attack,
    /// though that can be hard to diagnose.
    #[display(fmt = "Tor network protocol violation (bug, incompatibility, or attack)")]
    TorProtocolViolation,

    /// Something went wrong with a network connection or the local network.
    ///
    /// This kind of error is usually safe to retry, and shouldn't typically be
    /// seen.  By the time it reaches the caller, more specific error type
    /// should typically be available.
    #[display(fmt = "problem with network or connection")]
    Network,

    /// A remote host had an identity other than the one we expected.
    ///
    /// This could indicate a MITM attack, but more likely indicates that the
    /// relay has changed its identity but the new identity hasn't propagated
    /// through the directory system yet.
    #[display(fmt = "identity mismatch")]
    RemoteIdMismatch,

    /// An attempt to do something remotely through the Tor network failed
    /// because the circuit it was using shut down before the operation could
    /// finish.
    #[display(fmt = "circuit collapsed")]
    CircuitCollapse,

    /// An operation finished because a remote stream was closed successfully.
    ///
    /// This can indicate that the target server closed the TCP connection,
    /// or that the exit told us that it closed the TCP connection.
    /// Callers should generally treat this like a closed TCP connection.
    #[display(fmt = "remote stream closed")]
    RemoteStreamClosed,

    /// An operation finished because a remote stream was closed unsuccessfully,
    ///
    /// This indicates that the exit reported some error message for the stream.
    #[display(fmt = "remote stream error")]
    RemoteStreamError,

    /// An operation finished because a remote name lookup was unsuccessful.
    ///
    /// Trying at another exit might succeed, or the address might be
    /// unresolvable.
    #[display(fmt = "remote name-lookup failure")]
    RemoteNameError,

    /// An operation won't work because it's trying to use an object that's
    /// already in a shutting-down state.
    #[display(fmt = "target object already closed")]
    AlreadyClosed,

    /// Bug, for example calling a function with an invalid argument.
    ///
    /// This kind of error is usually a programming mistake on the caller's part.
    /// This is usually a bug in code calling Arti, but it might be a bug in Arti itself.
    //
    // Usually, use `bad_api_usage!` and `into_bad_api_usage!` and thereby `InternalError`,
    // rather than inventing a new type with this kind.
    //
    // Errors with this kind should generally include a stack trace.  They are
    // very like InternalError, in that they represent a bug in the program.
    // The difference is that an InternalError, with kind `Internal`, represents
    // a bug in arti, whereas errors with kind BadArgument represent bugs which
    // could be (often, are likely to be) outside arti.
    #[display(fmt = "bad API usage (bug)")]
    BadApiUsage,

    /// An operation failed because a local namespace is too full to grow.
    ///
    /// This error can occur if you try to put too many steams onto a single
    /// circuit, or too many circuits onto a single channel.  Both are very
    /// unlikely in practice.
    ///
    /// If you see this kind of error when opening a stream, try opening the
    /// stream on a different circuit.  If you see this kind of error when
    /// opening a circuit, then there is probably a bug in your program.
    #[display(fmt = "namespace full")]
    NamespaceFull,

    /// An operation failed because a remote party on the Tor expected us to
    /// have a resource or identity that we do not.
    ///
    /// Clients should never encounter this kind of error.
    #[display(fmt = "requested resource is not available")]
    RequestedResourceAbsent,

    /// We asked a remote host to do something, and it declined.
    ///
    /// Either it gave an error message indicating that it refused to perform
    /// the request, or the protocol gives it no room to explain what happened.
    #[display(fmt = "remote host refused our request")]
    RemoteRefused,

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
