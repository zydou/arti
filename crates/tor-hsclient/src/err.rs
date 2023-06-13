//! Errors relating to being a hidden service client
use std::sync::Arc;

use derive_more::{From, Into};
use futures::task::SpawnError;

use thiserror::Error;
use tracing::error;

use retry_error::RetryError;
use safelog::Redacted;
use tor_error::define_asref_dyn_std_error;
use tor_error::{internal, Bug, ErrorKind, ErrorReport as _, HasKind};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::Relay;

/// Identity of a rendezvous point, for use in error reports
//
// TODO HS this should be `Redacted<RelayIds>`, as per
//   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1228#note_2910283
pub(crate) type RendPtIdentityForError = Redacted<RsaIdentity>;

/// Given a `Relay` for a rendezvous pt, provides its identify for use in error reports
pub(crate) fn rend_pt_identity_for_error(relay: &Relay<'_>) -> RendPtIdentityForError {
    (*relay.rsa_id()).into()
}

/// Index of an introduction point in the descriptor
///
/// Principally used in error reporting.
///
/// Formats as `#<n+1>`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, From, Into)]
#[allow(clippy::exhaustive_structs)]
#[derive(derive_more::Display)]
#[display(fmt = "#{}", self + 1)]
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
    Failed(#[source] RetryError<tor_error::Report<FailedAttemptError>>),

    /// The consensus network contains no suitable hidden service directories!
    #[error("consensus contains no suitable hidden service directories")]
    NoHsDirs,

    /// The descriptor contained only unuseable introduction points!
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
    // TODO HS: is even this too much leakage?
    // Perhaps the set of redacted hsdir ids may identify the service;
    // in that case this should be `Sensitive` instead.
    pub hsdir: Redacted<Ed25519Identity>,

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
    #[error("invalid descriptor")]
    InvalidDescriptor(#[from] tor_netdoc::Error),

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
    RendezvousObtainCircuit {
        /// Why it's not use able
        #[source]
        error: tor_circmgr::Error,
    },

    /// Failed to establish rendezvous point
    #[error("Failed to establish rendezvous point at {rend_pt}")]
    RendezvousEstablish {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: Redacted<RsaIdentity>,
    },

    /// Creating a rendezvous circuit and rendezvous point took too long
    #[error("Creating a rendezvous circuit and rendezvous point took too long")]
    RendezvousTimeout {
        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: Redacted<RsaIdentity>,
    },

    /// Failed to obtain circuit to introduction point
    #[error("Failed to obtain circuit to introduction point {intro_index}")]
    IntroObtainCircuit {
        /// What happened
        #[source]
        error: tor_circmgr::Error,

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

    /// Error when expecting rendezvous completion on rendezvous circuit
    #[error("Error when expecting rendezvous completion on rendezvous circuit")]
    RendezvousCircuitCompletionExpected {
        /// What happened
        #[source]
        error: tor_proto::Error,

        /// The index of the IPT in the list of IPTs in the descriptor
        intro_index: IntroPtIndex,

        /// Which relay did we choose for rendezvous point
        // TODO #813 this should be Redacted<RelayDescription> or something
        rend_pt: Redacted<RsaIdentity>,
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
        rend_pt: Redacted<RsaIdentity>,
    },

    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}
define_asref_dyn_std_error!(FailedAttemptError);

impl HasKind for ConnError {
    fn kind(&self) -> ErrorKind {
        use ConnError as CE;
        use ErrorKind as EK;
        match self {
            CE::InvalidHsId => EK::InvalidStreamTarget,
            CE::NoHsDirs => EK::TorDirectoryUnusable,
            CE::NoUsableIntroPoints => EK::OnionServiceDescriptorValidationFailed,
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
                .max_by_key(|attempt| FailedAttemptErrorDiscriminants::from(&attempt.0))
                .map(|attempt| attempt.0.kind())
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
        use tor_netdoc::NetdocErrorKind as NEK;
        use DescriptorErrorDetail as DED;
        use ErrorKind as EK;
        match self {
            DED::Timeout => EK::TorNetworkTimeout,
            DED::Circuit(e) => e.kind(),
            DED::Stream(e) => e.kind(),
            DED::Directory(RE::HttpStatus(st)) if *st == 404 => EK::OnionServiceNotFound,
            DED::Directory(RE::ResponseTooLong(_)) => EK::OnionServiceProtocolViolation,
            DED::Directory(RE::Utf8Encoding(_)) => EK::OnionServiceProtocolViolation,
            DED::Directory(other_re) => other_re.kind(),
            DED::InvalidDescriptor(e) => match e.netdoc_error_kind() {
                NEK::BadTimeBound | NEK::BadSignature => EK::OnionServiceDescriptorValidationFailed,
                _ => EK::OnionServiceDescriptorParsingFailed,
            },
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
            FAE::UnusableIntro { error, .. } => EK::OnionServiceDescriptorValidationFailed,
            FAE::RendezvousObtainCircuit { error, .. } => error.kind(),
            FAE::RendezvousEstablish { error, .. } => error.kind(),
            FAE::RendezvousCircuitCompletionExpected { error, .. } => error.kind(),
            FAE::RendezvousTimeout { .. } => EK::TorNetworkTimeout,
            FAE::IntroObtainCircuit { error, .. } => error.kind(),
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
    /// Internal error
    #[error("{0}")]
    Bug(#[from] Bug),
}

impl HasKind for StartupError {
    fn kind(&self) -> ErrorKind {
        use StartupError as SE;
        match self {
            SE::Bug(e) => e.kind(),
        }
    }
}
