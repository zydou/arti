//! Declare an error type for tor_socksproto
use std::borrow::Cow;

use thiserror::Error;

use tor_error::{ErrorKind, HasKind};

/// An error that occurs while negotiating a SOCKS handshake.
#[derive(Clone, Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The SOCKS client didn't implement SOCKS correctly.
    ///
    /// (Or, more likely, we didn't account for its behavior.)
    #[error("SOCKS protocol syntax violation")]
    Syntax,

    /// Failed to decode a SOCKS message.
    #[error("Error decoding SOCKS message")]
    Decode(#[from] tor_bytes::Error),

    /// The SOCKS client declared a SOCKS version number that isn't
    /// one we support.
    ///
    /// In all likelihood, this is somebody trying to use the port for
    /// some protocol other than SOCKS.
    #[error("Unrecognized SOCKS protocol version {0}")]
    BadProtocol(u8),

    /// The SOCKS client tried to use a SOCKS feature that we don't
    /// support at all.
    #[error("SOCKS feature ({0}) not implemented")]
    NotImplemented(Cow<'static, str>),

    /// Tried to progress the SOCKS handshake when it was already
    /// finished.  This is a programming error.
    #[error("SOCKS handshake was finished; no need to call this again")]
    AlreadyFinished(tor_error::Bug),

    /// The SOCKS proxy refused our authentication.
    #[error("SOCKS Authentication failed")]
    AuthRejected,

    /// During the protocol exchange, we needed to handle a handshake bigger than our buffer
    #[error("SOCKS protocol message size limit {limit} exceeded")]
    MessageTooLong {
        /// The limit in bytes
        limit: usize,
    },

    /// Peer closed connection during SOCKS handshake
    #[error("peer closed connection during SOCKS handshake")]
    UnexpectedEof,

    /// The peer sent payload data too early
    ///
    /// The peer sent data after its part of the protocol exchange,
    /// without waiting for our side of it to complete,
    /// in circumstances where we consider that a protocol violation by the peer.
    ///
    /// Returned only by
    /// [`Finished::into_output_forbid_pipelining`](crate::Finished::into_output_forbid_pipelining).
    #[error("SOCKS peer inappropriately pipelined (optimistically sent) payload data")]
    ForbiddenPipelining,

    /// The program (perhaps this module, perhaps Arti, perhaps the caller) is buggy
    #[error("Bug while handling SOCKS handshake")]
    Bug(#[from] tor_error::Bug),
}

// Note: at present, tor-socksproto isn't used in any settings where ErrorKind
// is used.  This is provided for future-proofing, since someday we'll want to
// have SOCKS protocol support internally as well as in the `arti` proxy.
impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::Decode(tor_bytes::Error::Incomplete { .. }) => {
                // This variant should always get converted before a user can
                // see it.
                EK::Internal
            }
            E::Syntax | E::Decode(_) | E::BadProtocol(_) => EK::LocalProtocolViolation,
            E::NotImplemented(_) => EK::NotImplemented,
            E::AuthRejected => EK::LocalProtocolViolation,
            E::UnexpectedEof => EK::LocalProtocolViolation,
            E::ForbiddenPipelining => EK::LocalProtocolViolation,
            E::MessageTooLong { .. } => EK::Internal, // We should select a buffer big enough!
            E::AlreadyFinished(e) => e.kind(),
            E::Bug(e) => e.kind(),
        }
    }
}
