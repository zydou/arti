//! Declare dirclient-specific errors.

use thiserror::Error;
use tor_rtcompat::TimeoutError;

/// An error originating from the tor-dirclient crate.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// We received an object with a suspiciously good compression ratio
    #[error("possible compression bomb")]
    CompressionBomb,

    /// The directory cache took too long to reply to us.
    #[error("directory timed out")]
    DirTimeout,

    /// We got an EOF before we were done with the headers.
    #[error("truncated HTTP headers")]
    TruncatedHeaders,

    /// Got an HTTP status other than 200
    #[error("unexpected HTTP status {0:?}")]
    HttpStatus(Option<u16>),

    /// Received a response that was longer than we expected.
    #[error("response too long; gave up after {0} bytes")]
    ResponseTooLong(usize),

    /// Data received was not UTF-8 encoded.
    #[error("Couldn't decode data as UTF-8.")]
    Utf8Encoding(#[from] std::string::FromUtf8Error),

    /// Io error while reading on connection
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

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
    #[error("Couldn't create HTTP request")]
    HttpError(#[from] http::Error),

    /// Unrecognized content-encoding
    #[error("Unrecognized content encoding: {0:?}")]
    ContentEncoding(String),
}

impl From<TimeoutError> for Error {
    fn from(_: TimeoutError) -> Self {
        Error::DirTimeout
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
