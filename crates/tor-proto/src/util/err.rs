//! Define an error type for the tor-proto crate.
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tor_cell::relaycell::{msg::EndReason, StreamId};
use tor_error::{ErrorKind, HasKind};
use tor_linkspec::RelayIdType;

/// An error type for the tor-proto crate.
///
/// This type should probably be split into several.  There's more
/// than one kind of error that can occur while doing something with
/// the Tor protocol.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// An error that occurred in the tor_bytes crate while decoding an
    /// object.
    #[error("Unable to parse {object}")]
    BytesErr {
        /// What we were trying to parse.
        object: &'static str,
        /// The error that occurred while parsing it.
        #[source]
        err: tor_bytes::Error,
    },
    /// An error that occurred from the io system when using a
    /// channel.
    #[error("IO error on channel with peer")]
    ChanIoErr(#[source] Arc<std::io::Error>),
    /// An error from the io system that occurred when trying to connect a channel.
    #[error("IO error while handshaking with peer")]
    HandshakeIoErr(#[source] Arc<std::io::Error>),
    /// An error occurred while trying to create or encode a cell.
    #[error("Unable to generate or encode {object}")]
    CellEncodeErr {
        /// The object we were trying to create or encode.
        object: &'static str,
        /// The error that occurred.
        #[source]
        err: tor_cell::Error,
    },
    /// An error occurred while trying to decode or parse a cell.
    #[error("Error while parsing {object}")]
    CellDecodeErr {
        /// The object we were trying to decode.
        object: &'static str,
        /// The error that occurred.
        #[source]
        err: tor_cell::Error,
    },
    /// An error occurred while trying to create or encode some non-cell
    /// message.
    ///
    /// This is likely the result of a bug: either in this crate, or the code
    /// that provided the input.
    #[error("Problem while encoding {object}")]
    EncodeErr {
        /// What we were trying to create or encode.
        object: &'static str,
        /// The error that occurred.
        #[source]
        err: tor_bytes::EncodeError,
    },
    /// We found a problem with one of the certificates in the channel
    /// handshake.
    #[error("Problem with certificate on handshake")]
    HandshakeCertErr(#[source] tor_cert::CertError),
    /// We tried to produce too much output for a key derivation function.
    #[error("Tried to extract too many bytes from a KDF")]
    InvalidKDFOutputLength,
    /// We tried to encrypt a message to a hop that wasn't there.
    #[error("Tried to encrypt a cell for a nonexistent hop")]
    NoSuchHop,
    /// The authentication information on this cell was completely wrong,
    /// or the cell was corrupted.
    #[error("Bad relay cell authentication")]
    BadCellAuth,
    /// A circuit-extension handshake failed due to a mismatched authentication
    /// value.
    #[error("Circuit-extension handshake authentication failed")]
    BadCircHandshakeAuth,
    /// Handshake protocol violation.
    #[error("Handshake protocol violation: {0}")]
    HandshakeProto(String),
    /// Handshake broken, maybe due to clock skew.
    ///
    /// (If the problem can't be due to clock skew, we return HandshakeProto
    /// instead.)
    #[error("Handshake failed due to expired certificates (possible clock skew)")]
    HandshakeCertsExpired {
        /// For how long has the circuit been expired?
        expired_by: Duration,
    },
    /// Protocol violation at the channel level, other than at the handshake
    /// stage.
    #[error("Channel protocol violation: {0}")]
    ChanProto(String),
    /// Protocol violation at the circuit level
    #[error("Circuit protocol violation: {0}")]
    CircProto(String),
    /// Channel is closed, or became closed while we were trying to do some
    /// operation.
    #[error("Channel closed")]
    ChannelClosed(#[from] ChannelClosed),
    /// Circuit is closed, or became closed while we were trying to so some
    /// operation.
    #[error("Circuit closed")]
    CircuitClosed,
    /// Can't allocate any more circuit or stream IDs on a channel.
    #[error("Too many entries in map: can't allocate ID")]
    IdRangeFull,
    /// Received a stream request with a stream ID that is already in use for another stream.
    #[error("Stream ID {0} is already in use")]
    IdUnavailable(StreamId),
    /// Received a cell with a stream ID of zero.
    #[error("Received a cell with a stream ID of zero")]
    StreamIdZero,
    /// Couldn't extend a circuit because the extending relay or the
    /// target relay refused our request.
    #[error("Circuit extension refused: {0}")]
    CircRefused(&'static str),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("Invalid stream target address")]
    BadStreamAddress,
    /// Received an End cell from the other end of a stream.
    #[error("Received an END cell with reason {0}")]
    EndReceived(EndReason),
    /// Stream was already closed when we tried to use it.
    #[error("Stream not connected")]
    NotConnected,
    /// Stream protocol violation
    #[error("Stream protocol violation: {0}")]
    StreamProto(String),

    /// Channel does not match target
    #[error("Peer identity mismatch: {0}")]
    ChanMismatch(String),
    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error")]
    Bug(#[from] tor_error::Bug),
    /// Remote DNS lookup failed.
    #[error("Remote resolve failed")]
    ResolveError(#[source] ResolveError),
    /// We tried to do something with a that we couldn't, because of an identity key type
    /// that the relay doesn't have.
    #[error("Relay has no {0} identity")]
    MissingId(RelayIdType),
    /// Memory quota error
    #[error("memory quota error")]
    Memquota(#[from] tor_memquota::Error),
}

/// Error which indicates that the channel was closed.
#[derive(Error, Debug, Clone)]
#[error("Channel closed")]
pub struct ChannelClosed;

impl HasKind for ChannelClosed {
    fn kind(&self) -> ErrorKind {
        ErrorKind::CircuitCollapse
    }
}

/// Details about an error received while resolving a domain
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ResolveError {
    /// A transient error which can be retried
    #[error("Received retriable transient error")]
    Transient,
    /// A non transient error, which shouldn't be retried
    #[error("Received non-retriable error")]
    Nontransient,
    /// Could not parse the response properly
    #[error("Received unrecognized result")]
    Unrecognized,
}

impl Error {
    /// Create an error from a tor_cell error that has occurred while trying to
    /// encode or create something of type `object`
    pub(crate) fn from_cell_enc(err: tor_cell::Error, object: &'static str) -> Error {
        Error::CellEncodeErr { object, err }
    }

    /// Create an error from a tor_cell error that has occurred while trying to
    /// decode something of type `object`
    pub(crate) fn from_cell_dec(err: tor_cell::Error, object: &'static str) -> Error {
        match err {
            tor_cell::Error::ChanProto(msg) => Error::ChanProto(msg),
            _ => Error::CellDecodeErr { err, object },
        }
    }

    /// Create an error for a tor_bytes error that occurred while parsing
    /// something of type `object`.
    pub(crate) fn from_bytes_err(err: tor_bytes::Error, object: &'static str) -> Error {
        Error::BytesErr { err, object }
    }

    /// Create an error for a tor_bytes error that occurred while encoding
    /// something of type `object`.
    pub(crate) fn from_bytes_enc(err: tor_bytes::EncodeError, object: &'static str) -> Error {
        Error::EncodeErr { err, object }
    }
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        use std::io::ErrorKind;
        use Error::*;
        let kind = match err {
            ChanIoErr(e) | HandshakeIoErr(e) => match Arc::try_unwrap(e) {
                Ok(e) => return e,
                Err(arc) => return std::io::Error::new(arc.kind(), arc),
            },

            InvalidKDFOutputLength | NoSuchHop | BadStreamAddress => ErrorKind::InvalidInput,

            NotConnected => ErrorKind::NotConnected,

            EndReceived(end_reason) => end_reason.into(),

            CircuitClosed => ErrorKind::ConnectionReset,

            Memquota { .. } => ErrorKind::OutOfMemory,

            BytesErr { .. }
            | BadCellAuth
            | BadCircHandshakeAuth
            | HandshakeProto(_)
            | HandshakeCertErr(_)
            | ChanProto(_)
            | HandshakeCertsExpired { .. }
            | ChannelClosed(_)
            | CircProto(_)
            | CellDecodeErr { .. }
            | CellEncodeErr { .. }
            | EncodeErr { .. }
            | ChanMismatch(_)
            | StreamProto(_)
            | MissingId(_)
            | IdUnavailable(_)
            | StreamIdZero => ErrorKind::InvalidData,

            Bug(ref e) if e.kind() == tor_error::ErrorKind::BadApiUsage => ErrorKind::InvalidData,

            IdRangeFull | CircRefused(_) | ResolveError(_) | Bug(_) => ErrorKind::Other,
        };
        std::io::Error::new(kind, err)
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use tor_bytes::Error as BytesError;
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::BytesErr {
                err: BytesError::Bug(e),
                ..
            } => e.kind(),
            E::BytesErr { .. } => EK::TorProtocolViolation,
            E::ChanIoErr(_) => EK::LocalNetworkError,
            E::HandshakeIoErr(_) => EK::TorAccessFailed,
            E::HandshakeCertErr(_) => EK::TorProtocolViolation,
            E::CellEncodeErr { err, .. } => err.kind(),
            E::CellDecodeErr { err, .. } => err.kind(),
            E::EncodeErr { .. } => EK::BadApiUsage,
            E::InvalidKDFOutputLength => EK::Internal,
            E::NoSuchHop => EK::BadApiUsage,
            E::BadCellAuth => EK::TorProtocolViolation,
            E::BadCircHandshakeAuth => EK::TorProtocolViolation,
            E::HandshakeProto(_) => EK::TorAccessFailed,
            E::HandshakeCertsExpired { .. } => EK::ClockSkew,
            E::ChanProto(_) => EK::TorProtocolViolation,
            E::CircProto(_) => EK::TorProtocolViolation,
            E::ChannelClosed(e) => e.kind(),
            E::CircuitClosed => EK::CircuitCollapse,
            E::IdRangeFull => EK::BadApiUsage,
            E::CircRefused(_) => EK::CircuitRefused,
            E::BadStreamAddress => EK::BadApiUsage,
            E::EndReceived(reason) => reason.kind(),
            E::NotConnected => EK::BadApiUsage,
            E::StreamProto(_) => EK::TorProtocolViolation,
            E::ChanMismatch(_) => EK::RelayIdMismatch,
            E::ResolveError(ResolveError::Nontransient) => EK::RemoteHostNotFound,
            E::ResolveError(ResolveError::Transient) => EK::RemoteHostResolutionFailed,
            E::ResolveError(ResolveError::Unrecognized) => EK::RemoteHostResolutionFailed,
            E::MissingId(_) => EK::BadApiUsage,
            E::IdUnavailable(_) => EK::BadApiUsage,
            E::StreamIdZero => EK::BadApiUsage,
            E::Memquota(err) => err.kind(),
            E::Bug(e) => e.kind(),
        }
    }
}

/// Internal type: Error return value from reactor's run_once
/// function: indicates an error or a shutdown.
#[derive(Debug)]
pub(crate) enum ReactorError {
    /// The reactor should shut down with an abnormal exit condition.
    Err(Error),
    /// The reactor should shut down without an error, since all is well.
    Shutdown,
}
impl From<Error> for ReactorError {
    fn from(e: Error) -> ReactorError {
        ReactorError::Err(e)
    }
}
impl From<ChannelClosed> for ReactorError {
    fn from(e: ChannelClosed) -> ReactorError {
        ReactorError::Err(e.into())
    }
}
#[cfg(test)]
impl ReactorError {
    /// Tests only: assert that this is an Error, and return it.
    pub(crate) fn unwrap_err(self) -> Error {
        match self {
            ReactorError::Shutdown => panic!(),
            ReactorError::Err(e) => e,
        }
    }
}
