//! Define an error type for the tor-proto crate.
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tor_cell::relaycell::msg::EndReason;
use tor_error::{ErrorKind, HasKind};

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
    #[error("parsing error: {0}")]
    BytesErr(#[from] tor_bytes::Error),
    /// An error that occurred from the io system when using a
    /// channel.
    #[error("io error on channel: {0}")]
    ChanIoErr(#[source] Arc<std::io::Error>),
    /// An error from the io system that occurred when trying to connect a channel.
    #[error("io error in handshake: {0}")]
    HandshakeIoErr(#[source] Arc<std::io::Error>),
    /// An error occurred in the cell-handling layer.
    #[error("cell encoding error: {0}")]
    CellErr(#[source] tor_cell::Error),
    /// We tried to produce too much output for some function.
    #[error("couldn't produce that much output")]
    InvalidOutputLength,
    /// We tried to encrypt a message to a hop that wasn't there.
    #[error("tried to encrypt to nonexistent hop")]
    NoSuchHop,
    /// The authentication information on this cell was completely wrong,
    /// or the cell was corrupted.
    #[error("bad relay cell authentication")]
    BadCellAuth,
    /// A circuit-extension handshake failed.
    #[error("handshake failed")]
    BadCircHandshake,
    /// Handshake protocol violation.
    #[error("handshake protocol violation: {0}")]
    HandshakeProto(String),
    /// Handshake broken, maybe due to clock skew.
    ///
    /// (If the problem can't be due to clock skew, we return HandshakeProto
    /// instead.)
    #[error("handshake failed due to expired certificates (possible clock skew)")]
    HandshakeCertsExpired {
        /// For how long has the circuit been expired?
        expired_by: Duration,
    },
    /// Protocol violation at the channel level, other than at the handshake
    /// stage.
    #[error("channel protocol violation: {0}")]
    ChanProto(String),
    /// Protocol violation at the circuit level
    #[error("circuit protocol violation: {0}")]
    CircProto(String),
    /// Channel is closed.
    #[error("{0}")]
    ChannelClosed(#[from] ChannelClosed),
    /// Circuit is closed.
    #[error("circuit closed")]
    CircuitClosed,
    /// Can't allocate any more circuit or stream IDs on a channel.
    #[error("too many entries in map: can't allocate ID")]
    IdRangeFull,
    /// Couldn't extend a circuit because the extending relay or the
    /// target relay refused our request.
    #[error("circuit extension handshake error: {0}")]
    CircRefused(&'static str),
    /// Tried to make or use a stream to an invalid destination address.
    #[error("invalid stream target address")]
    BadStreamAddress,
    /// Received an End cell from the other end of a stream.
    #[error("Received an End cell with reason {0}")]
    EndReceived(EndReason),
    /// Stream was already closed when we tried to use it.
    #[error("stream not connected")]
    NotConnected,
    /// Stream protocol violation
    #[error("stream protocol violation: {0}")]
    StreamProto(String),

    /// Channel does not match target
    #[error("channel mismatch: {0}")]
    ChanMismatch(String),
    /// There was a programming error somewhere in our code, or the calling code.
    #[error("Programming error: {0}")]
    Bug(#[from] tor_error::Bug),
    /// Remote DNS lookup failed.
    #[error("remote resolve failed: {0}")]
    ResolveError(ResolveError),
}

/// Error which indicates that the channel was closed
#[derive(Error, Debug, Clone)]
#[error("channel closed")]
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
    #[error("received retriable transient error")]
    Transient,
    /// A non transient error, which shouldn't be retried
    #[error("received not retriable error")]
    Nontransient,
    /// Could not parse the response properly
    #[error("received unrecognized result")]
    Unrecognized,
}

impl From<tor_cell::Error> for Error {
    fn from(err: tor_cell::Error) -> Error {
        match err {
            tor_cell::Error::ChanProto(msg) => Error::ChanProto(msg),
            _ => Error::CellErr(err),
        }
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

            InvalidOutputLength | NoSuchHop | BadStreamAddress => ErrorKind::InvalidInput,

            NotConnected => ErrorKind::NotConnected,

            EndReceived(end_reason) => end_reason.into(),

            CircuitClosed => ErrorKind::ConnectionReset,

            BytesErr(_)
            | BadCellAuth
            | BadCircHandshake
            | HandshakeProto(_)
            | ChanProto(_)
            | HandshakeCertsExpired { .. }
            | ChannelClosed(_)
            | CircProto(_)
            | CellErr(_)
            | ChanMismatch(_)
            | StreamProto(_) => ErrorKind::InvalidData,

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
            E::BytesErr(BytesError::Bug(e)) => e.kind(),
            E::BytesErr(_) => EK::TorProtocolViolation,
            E::ChanIoErr(_) => EK::LocalNetworkError,
            E::HandshakeIoErr(_) => EK::TorAccessFailed,
            E::CellErr(e) => e.kind(),
            E::InvalidOutputLength => EK::Internal,
            E::NoSuchHop => EK::BadApiUsage,
            E::BadCellAuth => EK::TorProtocolViolation,
            E::BadCircHandshake => EK::TorProtocolViolation,
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
