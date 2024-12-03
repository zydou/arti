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

use derive_more::Display;

mod internal;
pub use internal::*;

mod report;
pub use report::*;

mod retriable;
pub use retriable::*;

mod misc;
pub use misc::*;

#[cfg(feature = "tracing")]
pub mod tracing;

/// Classification of an error arising from Arti's Tor operations
///
/// This `ErrorKind` should suffice for programmatic handling by most applications embedding Arti:
/// get the kind via [`HasKind::kind`] and compare it to the expected value(s) with equality
/// or by matching.
///
/// When forwarding or reporting errors, use the whole error (e.g., `TorError`), not just the kind:
/// the error itself will contain more detail and context which is useful to humans.
//
// Splitting vs lumping guidelines:
//
// # Split on the place which caused the error
//
// Every ErrorKind should generally have an associated "location" in
// which it occurred.  If a problem can happen in two different
// "locations", it should have two different ErrorKinds.  (This goal
// may be frustrated sometimes by difficulty in determining where exactly
// a given error occurred.)
//
// The location of an ErrorKind should always be clear from its name.  If is not
// clear, add a location-related word to the name of the ErrorKind.
//
// For the purposes of this discussion, the following locations exist:
//   - Process:  Our code, or the application code using it.  These errors don't
//     usually need a special prefix.
//   - Host: A problem with our local computing  environment.  These errors
//     usually reflect trying to run under impossible circumstances (no file
//     system, no permissions, etc).
//   - Local: Another process on the same machine, or on the network between us
//     and the Tor network.  Errors in this location often indicate an outage,
//     misconfiguration, or a censorship event.
//   - Tor: Anywhere within the Tor network, or connections between Tor relays.
//     The words "Exit" and "Relay" also indicate this location.
//   - Remote: Anywhere _beyond_ the Tor exit. Can be a problem in the Tor
//     exit's connection to the real internet,  or with the remote host that the
//     exit is talking to.  (This kind of error can also indicate that the exit
//     is lying.)
//
// ## Lump any locations more fine-grained than that.
//
// We do not split locations more finely unless there's a good reason to do so.
// For example, we don't typically split errors within the "Tor" location based
// on whether they happened at a guard, a directory, or an exit.  (Errors with
// "Exit" or "Guard" in their names are okay, so long as that kind of error can
// _only_ occur at an Exit or Guard.)
//
// # Split based on reasonable response and semantics
//
// We also should split ErrorKinds based on what it's reasonable for the
// receiver to do with them.  Users may find more applications for our errors
// than we do, so we shouldn't assume that we can predict every reasonable use
// in advance.
//
// ErrorKinds should be more specific than just the locations in which they
// happen: for example, there shouldn't be a `TorNetworkError` or
// a `RemoteFailure`.
//
// # Avoid exposing implementation details
//
// ErrorKinds should not relate to particular code paths in the Arti codebase.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Error connecting to the Tor network
    ///
    /// Perhaps the local network is not working,
    /// or perhaps the chosen relay or bridge is not working properly.
    /// Not used for errors that occur within the Tor network, or accessing the public
    /// internet on the far side of Tor.
    #[display("error connecting to Tor")]
    TorAccessFailed,

    /// An attempt was made to use a Tor client for something without bootstrapping it first.
    #[display("attempted to use unbootstrapped client")]
    BootstrapRequired,

    /// Our network directory has expired before we were able to replace it.
    ///
    /// This kind of error can indicate one of several possible problems:
    /// * It can occur if the client used to be on the network, but has been
    ///   unable to make directory connections for a while.
    /// * It can occur if the client has been suspended or sleeping for a long
    ///   time, and has suddenly woken up without having a chance to replace its
    ///   network directory.
    /// * It can happen if the client has a sudden clock jump.
    ///
    /// Often, retrying after a minute or so will resolve this issue.
    ///
    // TODO this is pretty shonky.  "try again after a minute or so", seriously?
    //
    /// Future versions of Arti may resolve this situation automatically without caller
    /// intervention, possibly depending on preferences and API usage, in which case this kind of
    /// error will never occur.
    //
    // TODO: We should distinguish among the actual issues here, and report a
    // real bootstrapping problem when it exists.
    #[display("network directory is expired.")]
    DirectoryExpired,

    /// IO error accessing local persistent state
    ///
    /// For example, the disk might be full, or there may be a permissions problem.
    /// Usually the source will be [`std::io::Error`].
    ///
    /// Note that this kind of error only applies to problems in your `state_dir`:
    /// problems with your cache are another kind.
    #[display("could not read/write persistent state")]
    PersistentStateAccessFailed,

    /// We could not start up because a local resource is already being used by someone else
    ///
    /// Local resources include things like listening ports and state lockfiles.
    /// (We don't use this error for "out of disk space" and the like.)
    ///
    /// This can occur when another process
    /// (or another caller of Arti APIs)
    /// is already running a facility that overlaps with the one being requested.
    ///
    /// For example,
    /// running multiple processes each containing instances of the same hidden service,
    /// using the same state directories etc., is not supported.
    ///
    /// Another example:
    /// if Arti is configured to listen on a particular port,
    /// but another process on the system is already listening there,
    /// the resulting error has kind `LocalResourceAlreadyInUse`.
    // Actually, we only currently listen on ports in `arti` so we don't return
    // any Rust errors for this situation at all, at the time of writing.
    #[display("local resource (port, lockfile, etc.) already in use")]
    LocalResourceAlreadyInUse,

    /// We encountered a problem with filesystem permissions.
    ///
    /// This is likeliest to be caused by permissions on a file or directory
    /// being too permissive; the next likeliest cause is that we were unable to
    /// check the permissions on the file or directory, or on one of its
    /// ancestors.
    #[display("problem with filesystem permissions")]
    FsPermissions,

    /// Tor client's persistent state has been corrupted
    ///
    /// This could be because of a bug in the Tor code, or because something
    /// else has been messing with the data.
    ///
    /// This might also occur if the Tor code was upgraded and the new Tor is
    /// not compatible.
    ///
    /// Note that this kind of error only applies to problems in your
    /// `state_dir`: problems with your cache are another kind.
    #[display("corrupted data in persistent state")]
    PersistentStateCorrupted,

    /// Tor client's cache has been corrupted.
    ///
    /// This could be because of a bug in the Tor code, or because something else has been messing
    /// with the data.
    ///
    /// This might also occur if the Tor code was upgraded and the new Tor is not compatible.
    ///
    /// Note that this kind of error only applies to problems in your `cache_dir`:
    /// problems with your persistent state are another kind.
    #[display("corrupted data in cache")]
    CacheCorrupted,

    /// We had a problem reading or writing to our data cache.
    ///
    /// This may be a disk error, a file permission error, or similar.
    ///
    /// Note that this kind of error only applies to problems in your `cache_dir`:
    /// problems with your persistent state are another kind.
    #[display("cache access problem")]
    CacheAccessFailed,

    /// The keystore has been corrupted
    ///
    /// This could be because of a bug in the Tor code, or because something else has been messing
    /// with the data.
    ///
    /// Note that this kind of error only applies to problems in your `keystore_dir`:
    /// problems with your cache or persistent state are another kind.
    #[display("corrupted data in keystore")]
    KeystoreCorrupted,

    /// IO error accessing keystore
    ///
    /// For example, the disk might be full, or there may be a permissions problem.
    /// The source is typically an [`std::io::Error`].
    ///
    /// Note that this kind of error only applies to problems in your `keystore_dir`:
    /// problems with your cache or persistent state are another kind.
    #[display("could not access keystore")]
    KeystoreAccessFailed,

    /// Tor client's Rust async reactor is shutting down.
    ///
    /// This likely indicates that the reactor has encountered a fatal error, or
    /// has been told to do a clean shutdown, and it isn't possible to spawn new
    /// tasks.
    #[display("reactor is shutting down")]
    ReactorShuttingDown,

    /// Tor client is shutting down.
    ///
    /// This likely indicates that the last handle to the `TorClient` has been
    /// dropped, and is preventing other operations from completing.
    #[display("Tor client is shutting down.")]
    ArtiShuttingDown,

    /// An operation failed because we waited too long for an exit to do
    /// something.
    ///
    /// This error can happen if the host you're trying to connect to isn't
    /// responding to traffic.
    /// It can also happen if an exit, or hidden service, is overloaded, and
    /// unable to answer your replies in a timely manner.
    ///
    /// And it might simply mean that the Tor network itself
    /// (including possibly relays, or hidden service introduction or rendezvous points)
    /// is not working properly
    ///
    /// In either case, trying later, or on a different circuit, might help.
    //
    // TODO: Say that this is distinct from the case where the exit _tells you_
    // that there is a timeout.
    #[display("operation timed out at exit")]
    RemoteNetworkTimeout,

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
    #[display("invalid configuration")]
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
    #[display("invalid configuration transition")]
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
    #[display("could not find a home directory")]
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
    /// to operations which we do not.  It does not relate to facilities which
    /// are disabled (e.g. at build time) or harmful.
    ///
    /// It can refer to facilities which were once implemented in Tor or Arti
    /// but for which support has been removed.
    #[display("operation not implemented")]
    NotImplemented,

    /// A feature was requested which has been disabled in this build of Arti.
    ///
    /// This kind of error happens when the running Arti was built without the
    /// appropriate feature (usually, cargo feature) enabled.
    ///
    /// This might indicate that the overall running system has been
    /// mis-configured at build-time.  Alternatively, it can occur if the
    /// running system is deliberately stripped down, in which case it might be
    /// reasonable to simply report this error to a user.
    #[display("operation not supported because Arti feature disabled")]
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
    /// It might also occur if the local system has an incompatible combination
    /// of tools that we can't talk with.
    ///
    /// This error kind does *not* include situations that are better explained
    /// by a local program simply crashing or terminating unexpectedly.
    #[display("local protocol violation (local bug or incompatibility)")]
    LocalProtocolViolation,

    /// Someone or something on the Tor network violated the Tor protocols.
    ///
    /// This kind of error can happen when a remote Tor instance behaves in a
    /// way we don't expect.
    ///
    /// It usually indicates a programming error: either in their implementation
    /// of the protocol, or in ours.  It can also indicate an attempted attack,
    /// though that can be hard to diagnose.
    #[display("Tor network protocol violation (bug, incompatibility, or attack)")]
    TorProtocolViolation,

    /// Something went wrong with a network connection or the local network.
    ///
    /// This kind of error is usually safe to retry, and shouldn't typically be
    /// seen.  By the time it reaches the caller, a more specific error type
    /// should typically be available.
    #[display("problem with network or connection")]
    LocalNetworkError,

    /// More of a local resource was needed, than is available (or than we are allowed)
    ///
    /// For example, we tried to use more memory than permitted by our memory quota.
    #[display("local resource exhausted")]
    LocalResourceExhausted,

    /// A problem occurred when launching or communicating with an external
    /// process running on this computer.
    #[display("an externally launched plug-in tool failed")]
    ExternalToolFailed,

    /// A relay had an identity other than the one we expected.
    ///
    /// This could indicate a MITM attack, but more likely indicates that the
    /// relay has changed its identity but the new identity hasn't propagated
    /// through the directory system yet.
    #[display("identity mismatch")]
    RelayIdMismatch,

    /// An attempt to do something remotely through the Tor network failed
    /// because the circuit it was using shut down before the operation could
    /// finish.
    #[display("circuit collapsed")]
    CircuitCollapse,

    /// An operation timed out on the tor network.
    ///
    /// This may indicate a network problem, either with the local network
    /// environment's ability to contact the Tor network, or with the Tor
    /// network itself.
    #[display("tor operation timed out")]
    TorNetworkTimeout,

    /// We tried but failed to download a piece of directory information.
    ///
    /// This is a lower-level kind of error; in general it should be retried
    /// before the user can see it.   In the future it is likely to be split
    /// into several other kinds.
    // TODO ^
    #[display("directory fetch attempt failed")]
    TorDirectoryError,

    /// An operation finished because a remote stream was closed successfully.
    ///
    /// This can indicate that the target server closed the TCP connection,
    /// or that the exit told us that it closed the TCP connection.
    /// Callers should generally treat this like a closed TCP connection.
    #[display("remote stream closed")]
    RemoteStreamClosed,

    /// An operation finished because the remote stream was closed abruptly.
    ///
    /// This kind of error is analogous to an ECONNRESET error; it indicates
    /// that the exit reported that the stream was terminated without a clean
    /// TCP shutdown.
    ///
    /// For most purposes, it's fine to treat this kind of error the same as
    /// regular unexpected close.
    #[display("remote stream reset")]
    RemoteStreamReset,

    /// An operation finished because a remote stream was closed unsuccessfully.
    ///
    /// This indicates that the exit reported some error message for the stream.
    ///
    /// We only provide this error kind when no more specific kind is available.
    #[display("remote stream error")]
    RemoteStreamError,

    /// A stream failed, and the exit reports that the remote host refused
    /// the connection.
    ///
    /// This is analogous to an ECONNREFUSED error.
    #[display("remote host refused connection")]
    RemoteConnectionRefused,

    /// A stream was rejected by the exit relay because of that relay's exit
    /// policy.
    ///
    /// (In Tor, exits have a set of policies declaring which addresses and
    /// ports they're willing to connect to.  Clients download only _summaries_
    /// of these policies, so it's possible to be surprised by an exit's refusal
    /// to connect somewhere.)
    #[display("rejected by exit policy")]
    ExitPolicyRejected,

    /// An operation failed, and the exit reported that it waited too long for
    /// the operation to finish.
    ///
    /// This kind of error is distinct from `RemoteNetworkTimeout`, which means
    /// that _our own_ timeout threshold was violated.
    #[display("timeout at exit relay")]
    ExitTimeout,

    /// An operation failed, and the exit reported a network failure of some
    /// kind.
    ///
    /// This kind of error can occur for a number of reasons.  If it happens
    /// when trying to open a stream, it usually indicates a problem connecting,
    /// such as an ENOROUTE error.
    #[display("network failure at exit")]
    RemoteNetworkFailed,

    /// An operation finished because an exit failed to look up a hostname.
    ///
    /// Unfortunately, the Tor protocol does not distinguish failure of DNS
    /// services ("we couldn't find out if this host exists and what its name is")
    /// from confirmed denials ("this is not a hostname").  So this kind
    /// conflates both those sorts of error.
    ///
    /// Trying at another exit might succeed, or the address might truly be
    /// unresolvable.
    #[display("remote hostname not found")]
    RemoteHostNotFound,

    /// The target hidden service (`.onion` service) was not found in the directory
    ///
    /// We successfully connected to at least one directory server,
    /// but it didn't have a record of the hidden service.
    ///
    /// This probably means that the hidden service is not running, or does not exist.
    /// (It might mean that the directory servers are faulty,
    /// and that the hidden service was unable to publish its descriptor.)
    #[display("Onion Service not found")]
    OnionServiceNotFound,

    /// The target hidden service (`.onion` service) seems to be down
    ///
    /// We successfully obtained a hidden service descriptor for the service,
    /// so we know it is supposed to exist,
    /// but we weren't able to communicate with it via any of its
    /// introduction points.
    ///
    /// This probably means that the hidden service is not running.
    /// (It might mean that the introduction point relays are faulty.)
    #[display("Onion Service not running")]
    OnionServiceNotRunning,

    /// Protocol trouble involving the target hidden service (`.onion` service)
    ///
    /// Something unexpected happened when trying to connect to the selected hidden service.
    /// It seems to have been due to the hidden service violating the Tor protocols somehow.
    #[display("Onion Service protocol failed (apparently due to service behaviour)")]
    OnionServiceProtocolViolation,

    /// The target hidden service (`.onion` service) is running but we couldn't connect to it,
    /// and we aren't sure whose fault that is
    ///
    /// This might be due to malfunction on the part of the service,
    /// or a relay being used as an introduction point or relay,
    /// or failure of the underlying Tor network.
    #[display("Onion Service not reachable (due to service, or Tor network, behaviour)")]
    OnionServiceConnectionFailed,

    /// We tried to connect to an onion service without authentication,
    /// but it apparently requires authentication.
    #[display("Onion service required authentication, but none was provided.")]
    OnionServiceMissingClientAuth,

    /// We tried to connect to an onion service that requires authentication, and
    /// ours is wrong.
    ///
    /// This likely means that we need to use a different key for talking to
    /// this onion service, or that it has revoked our permissions to reach it.
    #[display("Onion service required authentication, but provided authentication was incorrect.")]
    OnionServiceWrongClientAuth,

    /// We tried to parse a `.onion` address, and found that it was not valid.
    ///
    /// This likely means that it was corrupted somewhere along its way from its
    /// origin to our API surface.  It may be the wrong length, have invalid
    /// characters, have an invalid version number, or have an invalid checksum.
    #[display(".onion address was invalid.")]
    OnionServiceAddressInvalid,

    /// An resolve operation finished with an error.
    ///
    /// Contrary to [`RemoteHostNotFound`](ErrorKind::RemoteHostNotFound),
    /// this can't mean "this is not a hostname".
    /// This error should be retried.
    #[display("remote hostname lookup failure")]
    RemoteHostResolutionFailed,

    /// Trouble involving a protocol we're using with a peer on the far side of the Tor network
    ///
    /// We were using a higher-layer protocol over a Tor connection,
    /// and something went wrong.
    /// This might be an error reported by the remote host within that higher protocol,
    /// or a problem detected locally but relating to that higher protocol.
    ///
    /// The nature of the problem can vary:
    /// examples could include:
    /// failure to agree suitable parameters (incompatibility);
    /// authentication problems (eg, TLS certificate trouble);
    /// protocol violation by the peer;
    /// peer refusing to provide service;
    /// etc.
    #[display("remote protocol violation")]
    RemoteProtocolViolation,

    /// An operation failed, and the relay in question reported that it's too
    /// busy to answer our request.
    #[display("relay too busy")]
    RelayTooBusy,

    /// We were asked to make an anonymous connection to a malformed address.
    ///
    /// This is probably because of a bad input from a user.
    #[display("target address was invalid")]
    InvalidStreamTarget,

    /// We were asked to make an anonymous connection to a _locally_ disabled
    /// address.
    ///
    /// For example, this kind of error can happen when try to connect to (e.g.)
    /// `127.0.0.1` using a client that isn't configured with allow_local_addrs.
    ///
    /// Usually this means that you intended to reject the request as
    /// nonsensical; but if you didn't, it probably means you should change your
    /// configuration to allow what you want.
    #[display("target address disabled locally")]
    ForbiddenStreamTarget,

    /// An operation failed in a transient way.
    ///
    /// This kind of error indicates that some kind of operation failed in a way
    /// where retrying it again could likely have made it work.
    ///
    /// You should not generally see this kind of error returned directly to you
    /// for high-level functions.  It should only be returned from lower-level
    /// crates that do not automatically retry these failures.
    // Errors with this kind should generally not return a `HasRetryTime::retry_time()` of `Never`.
    #[display("un-retried transient failure")]
    TransientFailure,

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
    #[display("bad API usage (bug)")]
    BadApiUsage,

    /// We asked a relay to create or extend a circuit, and it declined.
    ///
    /// Either it gave an error message indicating that it refused to perform
    /// the request, or the protocol gives it no room to explain what happened.
    ///
    /// This error is returned by higher-level functions only if it is the most informative
    /// error after appropriate retries etc.
    #[display("remote host refused our request")]
    CircuitRefused,

    /// We were unable to construct a path through the Tor network.
    ///
    /// Usually this indicates that there are too many user-supplied
    /// restrictions for us to comply with.
    ///
    /// On test networks, it likely indicates that there aren't enough relays,
    /// or that there aren't enough relays in distinct families.
    //
    // TODO: in the future, errors of this type should distinguish between
    // cases where this happens because of a user restriction and cases where it
    // happens because of a severely broken directory.
    //
    // The latter should be classified as TorDirectoryBroken.
    #[display("could not construct a path")]
    NoPath,

    /// We were unable to find an exit relay with a certain set of desired
    /// properties.
    ///
    /// Usually this indicates that there were too many user-supplied
    /// restrictions on the exit for us to comply with, or that there was no
    /// exit on the network supporting all of the ports that the user asked for.
    //
    // TODO: same as for NoPath.
    #[display("no exit available for path")]
    NoExit,

    /// The Tor consensus directory is broken or unsuitable
    ///
    /// This could occur when running very old software
    /// against the current Tor network,
    /// so that the newer network is incompatible.
    ///
    /// It might also mean a catastrophic failure of the Tor network,
    /// or that a deficient test network is in use.
    ///
    /// Currently some instances of this kind of problem
    /// are reported as `NoPath` or `NoExit`.
    #[display("Tor network consensus directory is not usable")]
    TorDirectoryUnusable,

    /// An operation failed because of _possible_ clock skew.
    ///
    /// The broken clock may be ours, or it may belong to another party on the
    /// network. It's also possible that somebody else is lying about the time,
    /// caching documents for far too long, or something like that.
    #[display("possible clock skew detected")]
    ClockSkew,

    /// Internal error (bug) in Arti.
    ///
    /// A supposedly impossible problem has arisen.  This indicates a bug in
    /// Arti; if the Arti version is relatively recent, please report the bug on
    /// our [bug tracker](https://gitlab.torproject.org/tpo/core/arti/-/issues).
    #[display("internal error (bug)")]
    Internal,

    /// Unclassified error
    ///
    /// Some other error occurred, which does not fit into any of the other kinds.
    ///
    /// This kind is provided for use by external code
    /// hooking into or replacing parts of Arti.
    /// It is never returned by the code in Arti (`arti-*` and `tor-*` crates).
    #[display("unclassified error")]
    Other,
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

#[cfg(feature = "futures")]
impl HasKind for futures::task::SpawnError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        if self.is_shutdown() {
            EK::ReactorShuttingDown
        } else {
            EK::Internal
        }
    }
}

impl HasKind for void::Void {
    fn kind(&self) -> ErrorKind {
        void::unreachable(*self)
    }
}

impl HasKind for std::convert::Infallible {
    fn kind(&self) -> ErrorKind {
        unreachable!()
    }
}

/// Sealed
mod sealed {
    /// Sealed
    pub trait Sealed {}
}
