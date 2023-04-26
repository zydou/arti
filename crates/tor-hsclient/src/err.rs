//! Errors relating to being a hidden service client
use std::sync::Arc;

use futures::task::SpawnError;

use thiserror::Error;
use tracing::error;

use retry_error::RetryError;
use safelog::Redacted;
use tor_error::{internal, Bug, ErrorKind, ErrorReport as _, HasKind};
use tor_llcrypto::pk::ed25519::Ed25519Identity;

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

    /// The consensus network contains no suitable hidden service directories!
    #[error("consensus contains no suitable hidden service directories")]
    NoHsDirs,

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

// This trivial AsRef impl enables use of `tor_error::Report`
// TODO: It would nice if this could be generated more automatically;
// it's basically `impl AsRef<dyn Trait> for T where T: Trait`.
impl AsRef<dyn std::error::Error + 'static> for DescriptorError {
    fn as_ref(&self) -> &(dyn std::error::Error + 'static) {
        self as _
    }
}

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

impl HasKind for ConnError {
    fn kind(&self) -> ErrorKind {
        use ConnError as CE;
        use ErrorKind as EK;
        match self {
            CE::InvalidHsId => EK::InvalidStreamTarget,
            CE::NoHsDirs => EK::TorDirectoryUnusable,
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
        use tor_netdoc::ParseErrorKind as PEK;
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
            DED::InvalidDescriptor(e) => match e.parse_error_kind() {
                PEK::BadTimeBound | PEK::BadSignature => EK::OnionServiceDescriptorValidationFailed,
                _ => EK::OnionServiceDescriptorParsingFailed,
            },
            DED::Bug(e) => e.kind(),
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
