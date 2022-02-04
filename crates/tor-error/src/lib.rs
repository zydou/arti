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

    /// Tor client's Rust async reactor is shutting down
    #[display(fmt = "shutting down")]
    ReactorShuttingDown,

    /// Tor client's Rust async reactor could not spawn a task for unexplained reasons
    #[display(fmt = "unexplained rust async task spawn failure")]
    UnexplainedTaskSpawnFailure,

    /// Internal error (bug)
    ///
    /// A supposedly impossible problem has arisen.  This indicates a bug in Arti.
    #[display(fmt = "internal error (bug)")]
    Internal,

    /// TODO - error still needs to be categorised in tor/arti code
    ///
    /// This variant is going to be ABOLISHED!
    #[display(fmt = "uncategorized error (TODO)")]
    TODO,
}

/// Errors that can be categorised as belonging to one `tor_error::ErrorKind`
pub trait HasKind {
    /// The kind
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
