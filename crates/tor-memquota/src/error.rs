//! Errors arising from memory tracking

use crate::internal_prelude::*;

/// An error occurring when tracking memory usage
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum Error {
    /// The memory quota tracker has been torn down
    #[error("attempted to use shut down memory tracker")]
    TrackerShutdown,

    /// The Account has been torn down
    ///
    /// This can happen if the account or participant has Collapsed due to reclamation
    #[error("memquota - attempted to use closed memory tracking account")]
    AccountClosed,

    /// The Participant has been torn down
    ///
    /// This can happen if the account or participant has Collapsed due to reclamation
    #[error("memquota - attempt to allocate by torn-down memory tracking participant")]
    ParticipantShutdown,

    /// Previous bug, memory quota tracker is corrupted
    #[error("{TrackerCorrupted}")]
    TrackerCorrupted,

    /// Bug
    #[error("internal error")]
    Bug(#[from] Bug),
}

/// Memory pressure means this data structure (or other facility) was torn down
///
/// Error type suitable for use by data structures and facilities
/// which participate in memory tracking.
///
/// Convertible from a [`tor_memtrack::Error`](enum@Error),
/// or constructible via `Default` or [`new`](MemoryReclaimedError::new).
#[derive(Debug, Clone, Error, Default)]
#[non_exhaustive]
#[error("{0}")]
pub struct MemoryReclaimedError(ReclaimedErrorInner);

/// Content of a [`MemoryReclaimedError`]
// Separate struct so we don't expose the variants
#[derive(Debug, Clone, Error, Default)]
enum ReclaimedErrorInner {
    /// Collapsed, from `ReclaimedError::new`
    #[error("data structure discarded due to memory pressure")]
    #[default]
    Collapsed,

    /// Other error from tracker
    #[error("{0}")]
    TrackerError(#[from] Error),
}

/// An error occurring when setting up a memory quota tracker
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum StartupError {
    /// Task spawn failed
    #[error("couldn't spawn reclamation task")]
    Spawn(#[source] Arc<SpawnError>),
}

impl From<SpawnError> for StartupError {
    fn from(e: SpawnError) -> StartupError {
        StartupError::Spawn(Arc::new(e))
    }
}

/// Tracker corrupted
///
/// The memory tracker state has been corrupted.
/// All is lost, at least as far as memory quotas are concerned.
//
// Separate type so we don't expose `PoisonError -> crate::Error` conversion
#[derive(Debug, Clone, Error)]
#[error("memory tracker is corrupted due to previous bug")]
pub struct TrackerCorrupted;

impl<T> From<PoisonError<T>> for TrackerCorrupted {
    fn from(_: PoisonError<T>) -> TrackerCorrupted {
        TrackerCorrupted
    }
}

impl From<TrackerCorrupted> for Error {
    fn from(_: TrackerCorrupted) -> Error {
        Error::TrackerCorrupted
    }
}

/// Error returned when reclaim task crashes
///
/// Does not escape the crate; is used for logging.
#[derive(Debug, Clone, Error)]
pub(crate) enum ReclaimCrashed {
    /// Previous bug, memory quota tracker is corrupted
    #[error("memory tracker corrupted due to previous bug")]
    TrackerCorrupted(#[from] TrackerCorrupted),

    /// Bug
    #[error("internal error")]
    Bug(#[from] Bug),
}

impl MemoryReclaimedError {
    /// Create a new `MemoryReclaimedError` (with no additional information)
    pub fn new() -> Self {
        MemoryReclaimedError::default()
    }
}

impl From<Error> for MemoryReclaimedError {
    fn from(e: Error) -> MemoryReclaimedError {
        MemoryReclaimedError(e.into())
    }
}

impl HasKind for MemoryReclaimedError {
    fn kind(&self) -> ErrorKind {
        self.0.kind()
    }
}

impl HasKind for ReclaimedErrorInner {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use ReclaimedErrorInner as REI;
        match self {
            REI::Collapsed => EK::LocalResourceExhausted,
            REI::TrackerError(e) => e.kind(),
        }
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::TrackerShutdown => EK::ArtiShuttingDown,
            E::AccountClosed => EK::LocalResourceExhausted,
            E::ParticipantShutdown => EK::LocalResourceExhausted,
            E::TrackerCorrupted => EK::Internal,
            E::Bug(e) => e.kind(),
        }
    }
}

impl HasKind for TrackerCorrupted {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        match self {
            TrackerCorrupted => EK::Internal,
        }
    }
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use StartupError as SE;
        match self {
            SE::Spawn(e) => e.kind(),
        }
    }
}

impl HasKind for ReclaimCrashed {
    fn kind(&self) -> ErrorKind {
        use ReclaimCrashed as RC;
        match self {
            RC::TrackerCorrupted(e) => e.kind(),
            RC::Bug(e) => e.kind(),
        }
    }
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use fmt::Display;

    #[test]
    fn error_display() {
        fn check_value(e: impl Debug + Display + HasKind) {
            println!("{e:?} / {e} / {:?}", e.kind());
        }

        let bug = internal!("error made for testingr");

        macro_rules! check_enum { {
            $ty:ident: // should be $ty:ty but macro_rules is too broken
            $( $variant:ident $fields:tt; )*
        } => {
            for e in [ $(
                $ty::$variant $fields,
            )* ] {
                check_value(e);
            }
            match None::<$ty> {
                None => {}
                $( Some($ty::$variant { .. }) => {}, )*
            }
        } }

        check_enum! {
            Error:
            TrackerShutdown {};
            AccountClosed {};
            ParticipantShutdown {};
            TrackerCorrupted {};
            Bug(bug.clone());
        }

        check_enum! {
            ReclaimedErrorInner:
            Collapsed {};
            TrackerError(Error::TrackerShutdown);
        }

        check_value(MemoryReclaimedError(ReclaimedErrorInner::Collapsed));

        check_enum! {
            StartupError:
            Spawn(SpawnError::shutdown().into());
        }

        check_value(TrackerCorrupted);

        check_enum! {
            ReclaimCrashed:
            TrackerCorrupted(TrackerCorrupted);
            Bug(bug.clone());
        }
    }
}
