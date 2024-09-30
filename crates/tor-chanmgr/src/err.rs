//! Declare error types for tor-chanmgr

use std::net::SocketAddr;
use std::sync::Arc;

use futures::task::SpawnError;
use thiserror::Error;

use crate::factory::AbstractPtError;
use tor_error::{internal, ErrorKind};
use tor_linkspec::{BridgeAddr, ChanTarget, IntoOwnedChanTarget, LoggedChanTarget};
use tor_proto::ClockSkew;

// We use "ChanSensitive" for values which are sensitive because they relate to
// channel-layer trouble, rather than circuit-layer or higher.  This will let us find these later:
// if we want to change `LoggedChanTarget` to `Redacted` (say), we should change these too.
// (`Redacted` like https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/882)
use safelog::{BoxSensitive as BoxChanSensitive, Sensitive as ChanSensitive};

use crate::transport::proxied::ProxyError;

/// An error returned by a channel manager.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum Error {
    /// A ChanTarget was given for which no channel could be built.
    #[error("Bug: Target was unusable")]
    UnusableTarget(#[source] tor_error::Bug),

    /// We were waiting on a pending channel, but it didn't succeed.
    #[error("Pending channel for {peer} failed to launch")]
    PendingFailed {
        /// Who we were talking to
        peer: LoggedChanTarget,
    },

    /// It took too long for us to establish this connection.
    #[error("Channel for {peer} timed out")]
    ChanTimeout {
        /// Who we were trying to talk to
        peer: LoggedChanTarget,
    },

    /// A protocol error while making a channel
    #[error("Protocol error while opening a channel with {peer}")]
    Proto {
        /// The underlying error
        #[source]
        source: tor_proto::Error,
        /// Who we were trying to talk to
        peer: LoggedChanTarget,
        /// An authenticated ClockSkew (if available) that we received from the
        /// peer.
        clock_skew: Option<ClockSkew>,
    },

    /// Network IO error or TLS error
    #[error("Network IO error, or TLS error, in {action}, talking to {peer:?}")]
    Io {
        /// Who we were talking to
        peer: Option<BoxChanSensitive<BridgeAddr>>,

        /// What we were doing
        action: &'static str,

        /// What happened.  Might be some TLS library error wrapped up in io::Error
        #[source]
        source: Arc<std::io::Error>,
    },

    /// Failed to build a channel, after trying multiple addresses.
    #[error("Channel build failed: [(address, error)] = {addresses:?}")]
    ChannelBuild {
        /// The list of addresses we tried to connect to, coupled with
        /// the error we encountered connecting to each one.
        addresses: Vec<(ChanSensitive<SocketAddr>, Arc<std::io::Error>)>,
    },

    /// Unable to spawn task
    #[error("unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },

    /// A relay did not have the set of identity keys that we expected.
    ///
    /// (Currently, `tor-chanmgr` only works on relays that have at least
    /// one recognized identity key.)
    #[error("Could not identify relay by identity key")]
    MissingId,

    /// A successful relay channel had one of the identity keys we wanted,
    /// but not the other(s).
    ///
    /// This means that (assuming the relay is well behaved), we will not
    /// find the ID combination we want.
    #[error("Relay identity keys were only a partial match for what we wanted.")]
    IdentityConflict,

    /// Tried to connect via a transport that we don't support.
    #[error("No plugin available for the transport {0}")]
    NoSuchTransport(tor_linkspec::TransportId),

    /// An attempt to open a channel failed because it was cancelled or
    /// superseded by another request or configuration change.
    #[error("Channel request cancelled or superseded")]
    RequestCancelled,

    /// We tried to create a channel through a proxy, and encountered an error.
    #[error("Problem while connecting to Tor via a proxy")]
    Proxy(#[from] ProxyError),

    /// An error occurred in a pluggable transport manager.
    ///
    /// We can't know the type, because any pluggable transport manager implementing
    /// `AbstractPtMgr` can be used.
    /// However, if you're using Arti in the standard configuration, this will be
    /// `tor-ptmgr`'s `PtError`.
    #[error("Pluggable transport error: {0}")]
    Pt(#[source] Arc<dyn AbstractPtError>),

    /// An internal error of some kind that should never occur.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Error {
        Error::Internal(internal!("Thread failed while holding lock"))
    }
}

impl From<tor_linkspec::ByRelayIdsError> for Error {
    fn from(_: tor_linkspec::ByRelayIdsError) -> Self {
        Error::MissingId
    }
}

impl From<tor_linkspec::ListByRelayIdsError> for Error {
    fn from(_: tor_linkspec::ListByRelayIdsError) -> Self {
        Error::MissingId
    }
}

impl tor_error::HasKind for Error {
    fn kind(&self) -> ErrorKind {
        use tor_proto::Error as ProtoErr;
        use Error as E;
        use ErrorKind as EK;
        match self {
            E::ChanTimeout { .. }
            | E::Io { .. }
            | E::Proto {
                source: ProtoErr::ChanIoErr(_),
                ..
            } => EK::TorAccessFailed,
            E::Spawn { cause, .. } => cause.kind(),
            E::Proto { source, .. } => source.kind(),
            E::PendingFailed { .. } => EK::TorAccessFailed,
            E::NoSuchTransport(_) => EK::InvalidConfig,
            E::UnusableTarget(_) | E::Internal(_) => EK::Internal,
            E::MissingId => EK::BadApiUsage,
            E::IdentityConflict => EK::TorAccessFailed,
            E::ChannelBuild { .. } => EK::TorAccessFailed,
            E::RequestCancelled => EK::TransientFailure,
            E::Proxy(e) => e.kind(),
            E::Pt(e) => e.kind(),
        }
    }
}

impl tor_error::HasRetryTime for Error {
    fn retry_time(&self) -> tor_error::RetryTime {
        use tor_error::RetryTime as RT;
        use Error as E;
        match self {
            // We can retry this action immediately; there was already a time delay.
            E::ChanTimeout { .. } => RT::Immediate,

            // These are worth retrying in a little while.
            //
            // TODO: Someday we might want to distinguish among different kinds of IO
            // errors.
            E::PendingFailed { .. } | E::Proto { .. } | E::Io { .. } => RT::AfterWaiting,

            // Delegate.
            E::Proxy(e) => e.retry_time(),
            E::Pt(e) => e.retry_time(),

            // This error reflects multiple attempts, but every failure is an IO
            // error, so we can also retry this after a delay.
            //
            // TODO: Someday we might want to distinguish among different kinds
            // of IO errors.
            E::ChannelBuild { .. } => RT::AfterWaiting,

            // This one can't succeed: if the ChanTarget have addresses to begin with,
            // it won't have addresses in the future.
            E::UnusableTarget(_) => RT::Never,

            // This can't succeed until the relay is reconfigured.
            E::IdentityConflict => RT::Never,

            // This one can't succeed until the bridge, or our set of
            // transports, is reconfigured.
            E::NoSuchTransport(_) => RT::Never,

            E::RequestCancelled => RT::Never,

            // These aren't recoverable at all.
            E::Spawn { .. } | E::MissingId | E::Internal(_) => RT::Never,
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

    /// Construct a new `Error` from a `tor_proto::Error`, with no additional
    /// clock skew information.
    ///
    /// This is not an `Into` implementation because we don't want to call it
    /// accidentally when we actually do have clock skew information.
    pub(crate) fn from_proto_no_skew<T: ChanTarget + ?Sized>(
        source: tor_proto::Error,
        peer: &T,
    ) -> Self {
        Error::Proto {
            source,
            peer: peer.to_logged(),
            clock_skew: None,
        }
    }

    /// Return the clock skew information from this error (or from an internal
    /// error).
    ///
    /// Only returns the clock skew information if it is authenticated.
    pub fn clock_skew(&self) -> Option<ClockSkew> {
        match self {
            Error::Proto { clock_skew, .. } => *clock_skew,
            _ => None,
        }
    }
}
