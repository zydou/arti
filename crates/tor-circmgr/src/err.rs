//! Declare an error type for tor-circmgr

use std::{sync::Arc, time::Instant};

use futures::task::SpawnError;
use retry_error::RetryError;
use thiserror::Error;

use tor_async_utils::oneshot;
use tor_basic_utils::iter::FilterCount;
use tor_error::{Bug, ErrorKind, HasKind, HasRetryTime};
use tor_linkspec::{LoggedChanTarget, OwnedChanTarget};
use tor_proto::circuit::UniqId;

use crate::mgr::RestrictionFailed;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// We started building a circuit on a guard, but later decided not
    /// to use that guard.
    #[error("Discarded circuit {} because of speculative guard selection", _0.display_chan_circ())]
    GuardNotUsable(UniqId),

    /// We were waiting on a pending circuit, but it failed to report
    #[error("Pending circuit(s) failed without reporting status")]
    PendingCanceled,

    /// We were waiting on a pending circuit, but it failed.
    #[error("Circuit we were waiting for failed to complete")]
    PendingFailed(#[source] Box<Error>),

    /// We were told that we could use a given circuit, but before we got a
    /// chance to try it, its usage changed so that we had no longer find
    /// it suitable.
    ///
    /// This is a version of `UsageMismatched` for when a race is the
    /// likeliest explanation for the mismatch.
    #[error("Circuit seemed suitable, but another request got it first")]
    LostUsabilityRace(#[source] RestrictionFailed),

    /// A circuit succeeded, but was cancelled before it could be used.
    ///
    /// Circuits can be cancelled either by a call to
    /// `retire_all_circuits()`, or by a configuration change that
    /// makes old paths unusable.
    #[error("Circuit canceled")]
    CircCanceled,

    /// We were told that we could use a circuit, but when we tried, we found
    /// that its usage did not support what we wanted.
    ///
    /// This can happen due to a race when a number of tasks all decide that
    /// they can use the same pending circuit at once: one of them will restrict
    /// the circuit, and the others will get this error.
    ///
    /// See `LostUsabilityRace`.
    #[error("Couldn't apply circuit restriction")]
    UsageMismatched(#[from] RestrictionFailed),

    /// A circuit build took too long to finish.
    #[error("Circuit{} took too long to build", OptUniqId(_0))]
    CircTimeout(Option<UniqId>),

    /// A request spent too long waiting for a circuit
    #[error("Spent too long trying to construct circuits for this request")]
    RequestTimeout,

    /// No suitable relays for a request
    #[error(
        "Can't find {role} for circuit: Rejected {} because of family restrictions \
         and {} because of usage requirements.",
         can_share.display_frac_rejected(),
         correct_usage.display_frac_rejected(),
    )]
    NoPath {
        /// The role that we were trying to choose a relay for.
        role: &'static str,
        /// Relays accepted and rejected based on relay family policies.
        can_share: FilterCount,
        /// Relays accepted and rejected based on our usage requirements.
        correct_usage: FilterCount,
    },

    /// No suitable exit relay for a request.
    #[error(
        "Can't find exit for circuit: \
         Rejected {} because of family restrictions, {} because of port requirements, and {} because of country requirements",
        can_share.display_frac_rejected(),
        correct_ports.display_frac_rejected(),
        correct_country.display_frac_rejected()
    )]
    NoExit {
        /// Exit relays accepted and rejected based on relay family policies.
        can_share: FilterCount,
        /// Exit relays accepted and rejected base on the ports that we need.
        correct_ports: FilterCount,
        /// Exit relays accepted and rejected based on exit country code.
        correct_country: FilterCount,
    },

    /// Problem creating or updating a guard manager.
    #[error("Problem creating or updating guards list")]
    GuardMgr(#[source] tor_guardmgr::GuardMgrError),

    /// Problem selecting a guard relay.
    #[error("Unable to select a guard relay")]
    Guard(#[from] tor_guardmgr::PickGuardError),

    /// Unable to get or build a circuit, despite retrying.
    #[error("{0}")]
    RequestFailed(RetryError<Box<Error>>),

    /// Problem with channel
    #[error("Problem opening a channel to {peer}")]
    Channel {
        /// Which relay we were trying to connect to
        peer: LoggedChanTarget,

        /// What went wrong
        #[source]
        cause: tor_chanmgr::Error,
    },

    /// Protocol issue while building a circuit.
    #[error("Problem building a circuit, while {}{}", action, WithOptPeer(peer))]
    Protocol {
        /// The action that we were trying to take.
        action: &'static str,
        /// The peer that created the protocol error.
        ///
        /// This is set to None if we can't blame a single party.
        peer: Option<LoggedChanTarget>,
        /// The underlying error.
        #[source]
        error: tor_proto::Error,
    },

    /// Unable to spawn task
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Problem loading or storing persistent state.
    #[error("Problem loading or storing state")]
    State(#[from] tor_persist::Error),

    /// An error caused by a programming issue . or a failure in another
    /// library that we can't work around.
    #[error("Programming error")]
    Bug(#[from] Bug),
}

tor_error::define_asref_dyn_std_error!(Error);
tor_error::define_asref_dyn_std_error!(Box<Error>);

impl From<oneshot::Canceled> for Error {
    fn from(_: oneshot::Canceled) -> Error {
        Error::PendingCanceled
    }
}

impl From<tor_guardmgr::GuardMgrError> for Error {
    fn from(err: tor_guardmgr::GuardMgrError) -> Error {
        match err {
            tor_guardmgr::GuardMgrError::State(e) => Error::State(e),
            _ => Error::GuardMgr(err),
        }
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Channel { cause, .. } => cause.kind(),
            E::Bug(e) => e.kind(),
            E::NoPath { .. } => EK::NoPath,
            E::NoExit { .. } => EK::NoExit,
            E::PendingCanceled => EK::ReactorShuttingDown,
            E::PendingFailed(e) => e.kind(),
            E::CircTimeout(_) => EK::TorNetworkTimeout,
            E::GuardNotUsable(_) => EK::TransientFailure,
            E::UsageMismatched(_) => EK::Internal,
            E::LostUsabilityRace(_) => EK::TransientFailure,
            E::RequestTimeout => EK::TorNetworkTimeout,
            E::RequestFailed(errs) => E::summarized_error_kind(errs.sources().map(AsRef::as_ref)),
            E::CircCanceled => EK::TransientFailure,
            E::Protocol { error, .. } => error.kind(),
            E::State(e) => e.kind(),
            E::GuardMgr(e) => e.kind(),
            E::Guard(e) => e.kind(),
            E::Spawn { cause, .. } => cause.kind(),
        }
    }
}

impl HasRetryTime for Error {
    fn retry_time(&self) -> tor_error::RetryTime {
        use tor_error::RetryTime as RT;
        use Error as E;

        match self {
            // If we fail because of a timeout, there is no need to wait before trying again.
            E::CircTimeout(_) | E::RequestTimeout => RT::Immediate,

            // If a circuit that seemed usable was restricted before we got a
            // chance to try it, that's not our fault: we can try again
            // immediately.
            E::LostUsabilityRace(_) => RT::Immediate,

            // If we can't build a path for the usage at all, then retrying
            // won't help.
            //
            // TODO: In some rare cases, these errors can actually happen when
            // we have walked ourselves into a snag in our path selection.  See
            // additional "TODO" comments in exitpath.rs.
            E::NoPath { .. } | E::NoExit { .. } => RT::Never,

            // If we encounter UsageMismatched without first converting to
            // LostUsabilityRace, it reflects a real problem in our code.
            E::UsageMismatched(_) => RT::Never,

            // These don't reflect a real problem in the circuit building, but
            // rather mean that we were waiting for something that didn't pan out.
            // It's okay to try again after a short delay.
            E::GuardNotUsable(_) | E::PendingCanceled | E::CircCanceled | E::Protocol { .. } => {
                RT::AfterWaiting
            }

            // For Channel errors, we can mostly delegate the retry_time decision to
            // the inner error.
            //
            // (We have to handle UnusableTarget specially, since it just means
            // that we picked a guard or fallback we couldn't use.  A channel to
            // _that_ target will never succeed, but circuit operations using it
            // will do fine.)
            E::Channel {
                cause: tor_chanmgr::Error::UnusableTarget(_),
                ..
            } => RT::AfterWaiting,
            E::Channel { cause, .. } => cause.retry_time(),

            // These errors are safe to delegate.
            E::Guard(e) => e.retry_time(),
            E::PendingFailed(e) => e.retry_time(),

            // When we encounter a bunch of errors, choose the earliest.
            E::RequestFailed(errors) => {
                RT::earliest_approx(errors.sources().map(|err| err.retry_time()))
                    .unwrap_or(RT::Never)
            }

            // These all indicate an internal error, or an error that shouldn't
            // be able to happen when we're building a circuit.
            E::Spawn { .. } | E::GuardMgr(_) | E::State(_) | E::Bug(_) => RT::Never,
        }
    }

    fn abs_retry_time<F>(&self, now: Instant, choose_delay: F) -> tor_error::AbsRetryTime
    where
        F: FnOnce() -> std::time::Duration,
    {
        match self {
            // We special-case this kind of problem, since we want to choose the
            // earliest valid retry time.
            Self::RequestFailed(errors) => tor_error::RetryTime::earliest_absolute(
                errors.sources().map(|err| err.retry_time()),
                now,
                choose_delay,
            )
            .unwrap_or(tor_error::AbsRetryTime::Never),

            // For everything else, we just delegate.
            _ => self.retry_time().absolute(now, choose_delay),
        }
    }
}

impl Error {
    /// Construct a new `Error` from a `SpawnError`.
    pub(crate) fn from_spawn(spawning: &'static str, err: SpawnError) -> Error {
        Error::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }

    /// Return an integer representing the relative severity of this error.
    ///
    /// Used to determine which error to use when determining the kind of a retry error.
    fn severity(&self) -> usize {
        use Error as E;
        match self {
            E::GuardNotUsable(_) | E::LostUsabilityRace(_) => 10,
            E::PendingCanceled => 20,
            E::CircCanceled => 20,
            E::CircTimeout(_) => 30,
            E::RequestTimeout => 30,
            E::NoPath { .. } => 40,
            E::NoExit { .. } => 40,
            E::GuardMgr(_) => 40,
            E::Guard(_) => 40,
            E::RequestFailed(_) => 40,
            E::Channel { .. } => 40,
            E::Protocol { .. } => 45,
            E::Spawn { .. } => 90,
            E::State(_) => 90,
            E::UsageMismatched(_) => 90,
            E::Bug(_) => 100,
            E::PendingFailed(e) => e.severity(),
        }
    }

    /// Return true if this error should not count against our total number of
    /// failures.
    ///
    /// We count an error as an "internal reset" if it can happen in normal
    /// operation and doesn't indicate a real problem with building a circuit, so much as an externally generated "need to retry".
    pub(crate) fn is_internal_reset(&self) -> bool {
        match self {
            // This error is a reset because we expect it to happen while
            // we're picking guards; if it happens, it means that we now know a
            // good guard that we should have used instead.
            Error::GuardNotUsable(_) => true,
            // This error is a reset because it can only happen on the basis
            // of a caller action (for example, a decision to reconfigure the
            // `CircMgr`). If it happens, it just means that we should try again
            // with the new configuration.
            Error::CircCanceled => true,
            // This error is a reset because it doesn't indicate anything wrong
            // with the circuit: it just means that multiple requests all wanted
            // to use the circuit at once, and they turned out not to be
            // compatible with one another after the circuit was built.
            Error::LostUsabilityRace(_) => true,

            Error::PendingCanceled
            | Error::PendingFailed(_)
            | Error::UsageMismatched(_)
            | Error::CircTimeout(_)
            | Error::RequestTimeout
            | Error::NoPath { .. }
            | Error::NoExit { .. }
            | Error::GuardMgr(_)
            | Error::Guard(_)
            | Error::RequestFailed(_)
            | Error::Channel { .. }
            | Error::Protocol { .. }
            | Error::Spawn { .. }
            | Error::State(_)
            | Error::Bug(_) => false,
        }
    }

    /// Return a list of the peers to "blame" for this error, if there are any.
    pub fn peers(&self) -> Vec<&OwnedChanTarget> {
        match self {
            Error::RequestFailed(errors) => errors.sources().flat_map(|e| e.peers()).collect(),
            Error::Channel { peer, .. } => vec![peer.as_inner()],
            Error::Protocol {
                peer: Some(peer), ..
            } => vec![peer.as_inner()],
            _ => vec![],
        }
    }

    /// Given an iterator of errors that have occurred while attempting a single
    /// failed operation, return the [`ErrorKind`] for the entire attempt.
    pub fn summarized_error_kind<'a, I>(errs: I) -> ErrorKind
    where
        I: Iterator<Item = &'a Error>,
    {
        errs.max_by_key(|e| e.severity())
            .map(|e| e.kind())
            .unwrap_or(ErrorKind::Internal)
    }
}

/// A failure to build any preemptive circuits, with at least one error
/// condition.
///
/// This is a separate type since we never report it outside the crate.
#[derive(Debug)]
pub(crate) struct PreemptiveCircError;

/// Helper to display an optional peer, prefixed with the string " with".
struct WithOptPeer<'a, T>(&'a Option<T>);

impl<'a, T> std::fmt::Display for WithOptPeer<'a, T>
where
    T: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(peer) = self.0.as_ref() {
            write!(f, " with {}", peer)
        } else {
            Ok(())
        }
    }
}

/// Helper to display an optional UniqId.
struct OptUniqId<'a>(&'a Option<UniqId>);

impl<'a> std::fmt::Display for OptUniqId<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(unique_id) = self.0 {
            write!(f, " {}", unique_id.display_chan_circ())
        } else {
            write!(f, "")
        }
    }
}
