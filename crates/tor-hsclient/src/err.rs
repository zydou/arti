//! Errors relating to being a hidden service client
use std::sync::Arc;

use derive_more::{From, Into};
use futures::task::SpawnError;

use thiserror::Error;
use tracing::error;

use retry_error::RetryError;
use safelog::{Redacted, Sensitive};
use tor_cell::relaycell::hs::IntroduceAckStatus;
use tor_error::define_asref_dyn_std_error;
use tor_error::{internal, Bug, ErrorKind, ErrorReport as _, HasKind, HasRetryTime, RetryTime};
use tor_linkspec::RelayIds;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdir::Relay;

/// Identity of a rendezvous point, for use in error reports
pub(crate) type RendPtIdentityForError = Redacted<RelayIds>;

/// Given a `Relay` for a rendezvous pt, provides its identify for use in error reports
pub(crate) fn rend_pt_identity_for_error(relay: &Relay<'_>) -> RendPtIdentityForError {
    RelayIds::from_relay_ids(relay).into()
}

/// Index of an introduction point in the descriptor
///
/// Principally used in error reporting.
///
/// Formats as `#<n+1>`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, From, Into)]
#[allow(clippy::exhaustive_structs)]
#[derive(derive_more::Display)]
#[display("#{}", self.0 + 1)]
pub struct IntroPtIndex(pub usize);

/// Error that occurred attempting to reach a hidden service
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum ConnError {
    /// Invalid hidden service identity (`.onion` address)
    #[error("Invalid hidden service identity (`.onion` address)")]
    InvalidHsId,

    /// Unable to download hidden service descriptor
    #[error("Unable to download hidden service descriptor")]
    DescriptorDownload(RetryError<tor_error::Report<DescriptorError>>),

    /// Obtained descriptor but unable to connect to hidden service due to problem with IPT or RPT
    // TODO HS is this the right name for this variant?
    #[error("Unable to connect to hidden service using any Rendezvous Point / Introduction Point")]
    Failed(#[source] RetryError<FailedAttemptError>),

    /// The consensus network contains no suitable hidden service directories!
    #[error("consensus contains no suitable hidden service directories")]
    NoHsDirs,

    /// The descriptor contained only unusable introduction points!
    ///
    /// This is the fault of the service, or shows incompatibility between us and them.
    #[error("hidden service has no introduction points usable by us")]
    NoUsableIntroPoints,

    /// Unable to spawn
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

/// Error that occurred attempting to download a descriptor
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
#[error("tried hsdir {hsdir}: {error}")]
pub struct DescriptorError {
    /// Which hsdir we were trying
    // TODO #813 this should be Redacted<RelayDescription> or something
    // It seems likely that the set of redacted hsdir ids could identify the service,
    // so use Sensitive rather than Redacted.
    pub hsdir: Sensitive<Ed25519Identity>,

    /// What happened
    #[source]
    pub error: DescriptorErrorDetail,
}
define_asref_dyn_std_error!(DescriptorError);

/// Error that occurred attempting to download a descriptor
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
//
// NOTE! These are in an order!  "Most interesting" errors come last.
// Specifically, after various attempts, the ErrorKind of the overall error
// will be that of the error which is latest in this enum.
//
#[derive(strum::EnumDiscriminants)]
#[strum_discriminants(derive(PartialOrd, Ord))]
pub enum DescriptorErrorDetail {
    /// Timed out
    #[error("timed out")]
    Timeout,

    /// Failed to establish circuit to hidden service directory
    #[error("circuit failed")]
    Circuit(#[from] tor_circmgr::Error),

    /// Failed to establish stream to hidden service directory
    #[error("stream failed")]
    Stream(#[source] tor_proto::Error),

    /// Failed to make directory request
    #[error("directory error")]
    Directory(#[from] tor_dirclient::RequestError),

    /// Failed to parse or validate descriptor
    #[error("problem with descriptor")]
    Descriptor(#[from] tor_netdoc::doc::hsdesc::HsDescError),

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

/// Error that occurred making one attempt to connect to a hidden service using an IP and RP
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
//
// NOTE! These are in an order!  "Most interesting" errors come last.
// Specifically, after various attempts, the ErrorKind of the overall error
// will be that of the error which is latest in this enum.
//
#[derive(strum::EnumDiscriminants)]
#[strum_discriminants(derive(PartialOrd, Ord))]
// TODO HS is this the right name for this type?  It's a very mixed bag, so maybe it is.
pub enum FailedAttemptError {
    /// Introduction point unusable because it couldn't be used as a circuit target
    #[error("Unusable introduction point #{intro_index}")]
    UnusableIntro {
        /// Why it's not use able
        #[source]
        error: crate::relay_info::InvalidTarget,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,
    },

    /// Failed to obtain any circuit to use as a rendezvous circuit
    #[error("Failed to obtain any circuit to use as a rendezvous circuit")]
    RendezvousCircuitObtain {
        /// Why it's not use able
        #[source]
        error: tor_circmgr::Error,
    },

    /// Creating a rendezvous circuit and rendezvous point took too long
    #[error("Creating a rendezvous circuit and rendezvous point took too long")]
    RendezvousEstablishTimeout {
        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: RendPtIdentityForError,
    },

    /// Failed to establish rendezvous point
    #[error("Failed to establish rendezvous point at {rend_pt}")]
    RendezvousEstablish {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: RendPtIdentityForError,
    },

    /// Failed to obtain circuit to introduction point
    #[error("Failed to obtain circuit to introduction point {intro_index}")]
    IntroductionCircuitObtain {
        /// What happened
        #[source]
        error: tor_circmgr::Error,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,
    },

    /// Introduction exchange (with the introduction point) failed
    #[error("Introduction exchange (with the introduction point) failed")]
    IntroductionExchange {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,
    },

    /// Introduction point reported error in its INTRODUCE_ACK
    #[error("Introduction point reported error in its INTRODUCE_ACK: {status}")]
    IntroductionFailed {
        /// The status code provided by the introduction point
        status: IntroduceAckStatus,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,
    },

    /// Communication with introduction point {intro_index} took too long
    ///
    /// This might mean it took too long to establish a circuit to the IPT,
    /// or that the INTRODUCE exchange took too long.
    #[error("Communication with introduction point {intro_index} took too long")]
    IntroductionTimeout {
        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,
    },

    /// It took too long for the rendezvous to be completed
    ///
    /// This might be the fault of almost anyone.  All we know is that we got
    /// a successful `INTRODUCE_ACK` but the `RENDEZVOUS2` never arrived.
    #[error("Rendezvous at {rend_pt} using introduction point {intro_index} took too long")]
    RendezvousCompletionTimeout {
        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: RendPtIdentityForError,
    },

    /// Error on rendezvous circuit when expecting rendezvous completion (`RENDEZVOUS2`)
    #[error(
        "Error on rendezvous circuit when expecting rendezvous completion (RENDEZVOUS2 message)"
    )]
    RendezvousCompletionCircuitError {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: RendPtIdentityForError,
    },

    /// Error processing rendezvous completion (`RENDEZVOUS2`)
    ///
    /// This is might be the fault of the hidden service or the rendezvous point.
    #[error("Rendezvous completion end-to-end crypto handshake failed (bad RENDEZVOUS2 message)")]
    RendezvousCompletionHandshake {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: RendPtIdentityForError,
    },

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}
define_asref_dyn_std_error!(FailedAttemptError);

impl FailedAttemptError {
    /// Which introduction point did this error involve (or implicate), if any?
    ///
    /// This is an index into the table in the HS descriptor,
    /// so it can be less-than-useful outside the context where this error was generated.
    // TODO derive this, too much human error possibility
    pub(crate) fn intro_index(&self) -> Option<IntroPtIndex> {
        use FailedAttemptError as FAE;
        match self {
            FAE::UnusableIntro { intro_index, .. }
            | FAE::RendezvousCompletionCircuitError { intro_index, .. }
            | FAE::RendezvousCompletionHandshake { intro_index, .. }
            | FAE::RendezvousCompletionTimeout { intro_index, .. }
            | FAE::IntroductionCircuitObtain { intro_index, .. }
            | FAE::IntroductionExchange { intro_index, .. }
            | FAE::IntroductionFailed { intro_index, .. }
            | FAE::IntroductionTimeout { intro_index, .. } => Some(*intro_index),
            FAE::RendezvousCircuitObtain { .. }
            | FAE::RendezvousEstablish { .. }
            | FAE::RendezvousEstablishTimeout { .. }
            | FAE::Bug(_) => None,
        }
    }
}

/// When *an attempt like this* should be retried.
///
/// For error variants with an introduction point index
/// (`FailedAttemptError::intro_index` returns `Some`)
/// that's when we might retry *with that introduction point*.
///
/// For error variants with a rendezvous point,
/// that's when we might retry *with that rendezvous point*.
///
/// For variants with both, we don't know
/// which of the introduction point or rendezvous point is implicated.
/// Retrying earlier with *one* different relay out of the two relays would be reasonable,
/// as would delaying retrying with *either* of the same relays.
//
// Our current code doesn't keep history about rendezvous points.
// We use this to choose what order to try the service's introduction points.
// See `IptSortKey` in connect.rs.
impl HasRetryTime for FailedAttemptError {
    fn retry_time(&self) -> RetryTime {
        use FailedAttemptError as FAE;
        use RetryTime as RT;
        match self {
            // Delegate to the cause
            FAE::UnusableIntro { error, .. } => error.retry_time(),
            FAE::RendezvousCircuitObtain { error } => error.retry_time(),
            FAE::IntroductionCircuitObtain { error, .. } => error.retry_time(),
            FAE::IntroductionFailed { status, .. } => status.retry_time(),
            // tor_proto::Error doesn't impl HasRetryTime, so we guess
            FAE::RendezvousCompletionCircuitError { error: _e, .. }
            | FAE::IntroductionExchange { error: _e, .. }
            | FAE::RendezvousEstablish { error: _e, .. } => RT::AfterWaiting,
            // Timeouts
            FAE::RendezvousEstablishTimeout { .. }
            | FAE::RendezvousCompletionTimeout { .. }
            | FAE::IntroductionTimeout { .. } => RT::AfterWaiting,
            // Other cases where we define the ErrorKind ourselves
            // If service didn't cause this, it was the RPT, so prefer to try another RPT
            FAE::RendezvousCompletionHandshake { error: _e, .. } => RT::Never,
            FAE::Bug(_) => RT::Never,
        }
    }
}

impl HasKind for ConnError {
    fn kind(&self) -> ErrorKind {
        use ConnError as CE;
        use ErrorKind as EK;
        match self {
            CE::InvalidHsId => EK::InvalidStreamTarget,
            CE::NoHsDirs => EK::TorDirectoryUnusable,
            CE::NoUsableIntroPoints => EK::OnionServiceProtocolViolation,
            CE::Spawn { cause, .. } => cause.kind(),
            CE::Bug(e) => e.kind(),

            CE::DescriptorDownload(attempts) => attempts
                .sources()
                .max_by_key(|attempt| DescriptorErrorDetailDiscriminants::from(&attempt.0.error))
                .map(|attempt| attempt.0.kind())
                .unwrap_or_else(|| {
                    let bug = internal!("internal error, empty CE::DescriptorDownload");
                    error!("bug: {}", bug.report());
                    bug.kind()
                }),

            CE::Failed(attempts) => attempts
                .sources()
                .max_by_key(|attempt| FailedAttemptErrorDiscriminants::from(*attempt))
                .map(|attempt| attempt.kind())
                .unwrap_or_else(|| {
                    let bug = internal!("internal error, empty CE::DescriptorDownload");
                    error!("bug: {}", bug.report());
                    bug.kind()
                }),
        }
    }
}

impl HasKind for DescriptorError {
    fn kind(&self) -> ErrorKind {
        self.error.kind()
    }
}

impl HasKind for DescriptorErrorDetail {
    fn kind(&self) -> ErrorKind {
        use tor_dirclient::RequestError as RE;
        use DescriptorErrorDetail as DED;
        use ErrorKind as EK;
        match self {
            DED::Timeout => EK::TorNetworkTimeout,
            DED::Circuit(e) => e.kind(),
            DED::Stream(e) => e.kind(),
            DED::Directory(RE::HttpStatus(st, _)) if *st == 404 => EK::OnionServiceNotFound,
            DED::Directory(RE::ResponseTooLong(_)) => EK::OnionServiceProtocolViolation,
            DED::Directory(RE::Utf8Encoding(_)) => EK::OnionServiceProtocolViolation,
            DED::Directory(other_re) => other_re.kind(),
            DED::Descriptor(e) => e.kind(),
            DED::Bug(e) => e.kind(),
        }
    }
}

impl HasKind for FailedAttemptError {
    fn kind(&self) -> ErrorKind {
        /*use tor_dirclient::RequestError as RE;
        use tor_netdoc::NetdocErrorKind as NEK;
        use DescriptorErrorDetail as DED;*/
        use ErrorKind as EK;
        use FailedAttemptError as FAE;
        match self {
            FAE::UnusableIntro { .. } => EK::OnionServiceProtocolViolation,
            FAE::RendezvousCircuitObtain { error, .. } => error.kind(),
            FAE::RendezvousEstablish { error, .. } => error.kind(),
            FAE::RendezvousCompletionCircuitError { error, .. } => error.kind(),
            FAE::RendezvousCompletionHandshake { error, .. } => error.kind(),
            FAE::RendezvousEstablishTimeout { .. } => EK::TorNetworkTimeout,
            FAE::IntroductionCircuitObtain { error, .. } => error.kind(),
            FAE::IntroductionExchange { error, .. } => error.kind(),
            FAE::IntroductionFailed { .. } => EK::OnionServiceConnectionFailed,
            FAE::IntroductionTimeout { .. } => EK::TorNetworkTimeout,
            FAE::RendezvousCompletionTimeout { .. } => EK::RemoteNetworkTimeout,
            FAE::Bug(e) => e.kind(),
        }
    }
}

/// Error that occurred attempting to start up a hidden service client connector
#[derive(Error, Clone, Debug)]
#[non_exhaustive]
pub enum StartupError {
    /// Unable to spawn
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn
        spawning: &'static str,
        /// What happened when we tried to spawn it
        #[source]
        cause: Arc<SpawnError>,
    },

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use StartupError as SE;
        match self {
            SE::Spawn { cause, .. } => cause.kind(),
            SE::Bug(e) => e.kind(),
        }
    }
}
