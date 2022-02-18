//! Declare dirclient-specific errors.

use std::sync::Arc;

use thiserror::Error;
use tor_error::{ErrorKind, HasKind};
use tor_rtcompat::TimeoutError;

/// An error originating from the tor-dirclient crate.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
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
    #[error("IO error: {0}")]
    IoError(#[source] Arc<std::io::Error>),

    /// A protocol error while launching a stream
    #[error("Protocol error while launching a stream: {0}")]
    Proto(#[from] tor_proto::Error),

    /// Error while getting a circuit
    #[error("Error while getting a circuit {0}")]
    CircMgr(#[from] tor_circmgr::Error),

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
}

impl From<TimeoutError> for Error {
    fn from(_: TimeoutError) -> Self {
        Error::DirTimeout
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(Arc::new(err))
    }
}

impl From<http::Error> for Error {
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
        true
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::DirTimeout => EK::TorNetworkTimeout,
            E::TruncatedHeaders => EK::TorProtocolViolation,
            E::ResponseTooLong(_) => EK::TorProtocolViolation,
            E::Utf8Encoding(_) => EK::TorProtocolViolation,
            // TODO: it would be good to get more information out of the IoError
            // in this case, but that would require a bunch of gnarly
            // downcasting.
            E::IoError(_) => EK::TorNetworkError,
            E::Proto(e) => e.kind(),
            E::CircMgr(e) => e.kind(),
            E::HttparseError(_) => EK::TorProtocolViolation,
            E::HttpError(_) => EK::Internal,
            E::ContentEncoding(_) => EK::TorProtocolViolation,
        }
    }
}
