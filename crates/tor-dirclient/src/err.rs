//! Declare dirclient-specific errors.

use std::sync::Arc;

use thiserror::Error;
use tor_error::{Bug, ErrorKind, HasKind};
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::TimeoutError;

use crate::SourceInfo;

/// An error originating from the tor-dirclient crate.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // TODO(nickm) worth fixing as we do #587
pub enum Error {
    /// Error while getting a circuit
    #[error("Error while getting a circuit")]
    CircMgr(#[from] tor_circmgr::Error),

    /// An error that has occurred after we have contacted a directory cache and made a circuit to it.
    #[error("Error fetching directory information")]
    RequestFailed(#[from] RequestFailedError),

    /// We ran into a problem that is probably due to a programming issue.
    #[error("Internal error")]
    Bug(#[from] Bug),
}

/// An error that has occurred after we have contacted a directory cache and made a circuit to it.
#[derive(Error, Debug, Clone)]
#[allow(clippy::exhaustive_structs)] // TODO should not be exhaustive
#[error("Request failed{}", FromSource(.source))]
pub struct RequestFailedError {
    /// The source that gave us this error.
    pub source: Option<SourceInfo>,

    /// The underlying error that occurred.
    #[source]
    pub error: RequestError,
}

/// Helper type to display an optional source of directory information.
struct FromSource<'a>(&'a Option<SourceInfo>);

impl std::fmt::Display for FromSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(si) = self.0 {
            write!(f, " from {}", si)
        } else {
            Ok(())
        }
    }
}

/// An error originating from the tor-dirclient crate.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum RequestError {
    /// The directory cache took too long to reply to us.
    #[error("directory timed out")]
    DirTimeout,

    /// We got an EOF before we were done with the headers.
    #[error("truncated HTTP headers")]
    TruncatedHeaders,

    /// Received a response that was longer than we expected.
    #[error("response too long; gave up after {0} bytes")]
    ResponseTooLong(usize),

    /// Data received was not UTF-8 encoded.
    #[error("Couldn't decode data as UTF-8.")]
    Utf8Encoding(#[from] std::string::FromUtf8Error),

    /// Io error while reading on connection
    #[error("IO error")]
    IoError(#[source] Arc<std::io::Error>),

    /// A protocol error while launching a stream
    #[error("Protocol error while launching a stream")]
    Proto(#[from] tor_proto::Error),

    /// Error when parsing http
    #[error("Couldn't parse HTTP headers")]
    HttparseError(#[from] httparse::Error),

    /// Error while creating http request
    //
    // TODO this should be abolished, in favour of a `Bug` variant,
    // so that we get a stack trace, as per the notes for EK::Internal.
    // We could convert via into_internal!, or a custom `From` impl.
    #[error("Couldn't create HTTP request")]
    HttpError(#[source] Arc<http::Error>),

    /// Unrecognized content-encoding
    #[error("Unrecognized content encoding: {0:?}")]
    ContentEncoding(String),

    /// Too much clock skew between us and the directory.
    ///
    /// (We've giving up on this request early, since any directory that it
    /// believes in, we would reject as untimely.)
    #[error("Too much clock skew with directory cache")]
    TooMuchClockSkew,

    /// We tried to launch a request without any requested objects.
    ///
    /// This can happen if (for example) we request an empty list of
    /// microdescriptors or certificates.
    #[error("We didn't have any objects to request")]
    EmptyRequest,

    /// HTTP status code indicates a not completely successful request
    #[error("HTTP status code {0}: {1:?}")]
    HttpStatus(u16, String),
}

impl From<TimeoutError> for RequestError {
    fn from(_: TimeoutError) -> Self {
        RequestError::DirTimeout
    }
}

impl From<std::io::Error> for RequestError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(Arc::new(err))
    }
}

impl From<http::Error> for RequestError {
    fn from(err: http::Error) -> Self {
        Self::HttpError(Arc::new(err))
    }
}

impl Error {
    /// Return true if this error means that the circuit shouldn't be used
    /// for any more directory requests.
    pub fn should_retire_circ(&self) -> bool {
        // TODO: probably this is too aggressive, and we should
        // actually _not_ dump the circuit under all circumstances.
        match self {
            Error::CircMgr(_) => true, // should be unreachable.
            Error::RequestFailed(RequestFailedError { error, .. }) => error.should_retire_circ(),
            Error::Bug(_) => true,
        }
    }

    /// Return the peer or peers that are to be blamed for the error.
    ///
    /// (This can return multiple peers if the request failed because multiple
    /// circuit attempts all failed.)
    pub fn cache_ids(&self) -> Vec<&OwnedChanTarget> {
        match &self {
            Error::CircMgr(e) => e.peers(),
            Error::RequestFailed(RequestFailedError {
                source: Some(source),
                ..
            }) => vec![source.cache_id()],
            _ => Vec::new(),
        }
    }
}

impl RequestError {
    /// Return true if this error means that the circuit shouldn't be used
    /// for any more directory requests.
    pub fn should_retire_circ(&self) -> bool {
        // TODO: probably this is too aggressive, and we should
        // actually _not_ dump the circuit under all circumstances.
        true
    }
}

impl HasKind for RequestError {
    fn kind(&self) -> ErrorKind {
        use ErrorKind as EK;
        use RequestError as E;
        match self {
            E::DirTimeout => EK::TorNetworkTimeout,
            E::TruncatedHeaders => EK::TorProtocolViolation,
            E::ResponseTooLong(_) => EK::TorProtocolViolation,
            E::Utf8Encoding(_) => EK::TorProtocolViolation,
            // TODO: it would be good to get more information out of the IoError
            // in this case, but that would require a bunch of gnarly
            // downcasting.
            E::IoError(_) => EK::TorDirectoryError,
            E::Proto(e) => e.kind(),
            E::HttparseError(_) => EK::TorProtocolViolation,
            E::HttpError(_) => EK::Internal,
            E::ContentEncoding(_) => EK::TorProtocolViolation,
            E::TooMuchClockSkew => EK::TorDirectoryError,
            E::EmptyRequest => EK::Internal,
            E::HttpStatus(_, _) => EK::TorDirectoryError,
        }
    }
}

impl HasKind for RequestFailedError {
    fn kind(&self) -> ErrorKind {
        self.error.kind()
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        match self {
            E::CircMgr(e) => e.kind(),
            E::RequestFailed(e) => e.kind(),
            E::Bug(e) => e.kind(),
        }
    }
}
