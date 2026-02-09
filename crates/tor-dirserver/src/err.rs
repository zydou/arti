//! Error module for `tor-dirserver`.

use thiserror::Error;
use tor_netdoc::parse2;

/// Indicates that an error variant is fatal.
///
/// A fatal error means that the application should abort execution and may
/// not retry again in the future.
///
/// This trait should only be implemented for error variants where some error
/// variants are fatal and others are not.  In other words: An error where all
/// variants are either fatal or non-fatal does not qualify for this trait.
// TODO DIRMIRROR: Move this to tor_error.
pub(crate) trait IsFatal: std::error::Error {
    /// Checks whether the current error is considered to be fatal.
    fn is_fatal(&self) -> bool;
}

/// An error while performing a request at a directory authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum AuthorityRequestError {
    /// TCP connection to the endpoint failed.
    #[error("tcp connection error: {0}")]
    TcpConnect(std::io::Error),

    /// [`tor_dirclient`] failed at performing the request.
    ///
    /// This usually indicates some failures in HTTP/1.0, such as the response
    /// not being valid HTTP/1.0; although Tor generally has some specialities
    /// here and there with regard to this, hence why we have dirclient in the
    /// first place.
    #[error("dirclient error: {0}")]
    Request(#[from] tor_dirclient::RequestFailedError),

    /// A response does not make semantic sense.
    ///
    /// This for example may include cases where we got more netdocs than we
    /// requested for.
    #[error("response error: {0}")]
    Response(&'static str),

    /// Invalid netdoc received from the authority.
    #[error("netdoc parse error: {0}")]
    Parse(#[from] parse2::ParseError),

    /// An internal error.
    #[error("internal error")]
    Bug(#[from] tor_error::Bug),
}

impl IsFatal for AuthorityRequestError {
    /// The [`AuthorityRequestError`] is considered to be fatal.
    ///
    /// Right now, the following variants are considered to be fatal:
    /// * [`AuthorityRequestError::Bug`]
    fn is_fatal(&self) -> bool {
        matches!(&self, Self::Bug(_))
    }
}

/// An error while interacting with a database.
///
/// This error should be returned by all functions that interact with the
/// database in one way or another.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum DatabaseError {
    /// A low-level SQLite error has occurred, which can have a bascially
    /// infinite amount of reasons, all of them outlined in the actual SQLite
    /// and [`rusqlite`] documentation.
    #[error("low-level rusqlite error: {0}")]
    LowLevel(#[from] rusqlite::Error),

    /// This is an application level error meaning that the database can be
    /// successfully accessed but its content implies it is of a schema version
    /// we do not support.
    ///
    /// Keep in mind that an unrecognized schema is not equal to no schema.
    /// In the latter case we actually initialize the database, whereas in the
    /// previous one, we fail early in order to not corrupt an existing database.
    /// Future versions of this crate should continue with this promise in order
    /// to ensure forward compatability.
    #[error("incompatible schema version: {version}")]
    IncompatibleSchema {
        /// The incompatible schema version found in the database.
        version: String,
    },

    /// Interaction with our database pool, [`r2d2`], has failed.
    ///
    /// Unlike other database pools, this error is fairly straightforward and
    /// may only be obtained in the cases in which we try to obtain a connection
    /// handle from the pool.  Notably, it does not fail if, for example,
    /// the low-level [`rusqlite`] has a failure.
    #[error("pool error: {0}")]
    Pool(#[from] r2d2::Error),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error related to an operation in the dirmirror FSM.
//
// TODO: Rename this to MirrorOperationError.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum OperationError {
    /// Request to a directory authority failed.
    #[error("authority request error: {0}")]
    AuthorityRequest(#[from] Box<AuthorityRequestError>),

    /// Access to the database failed for good.
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl From<AuthorityRequestError> for OperationError {
    fn from(value: AuthorityRequestError) -> Self {
        Self::AuthorityRequest(Box::new(value))
    }
}

impl IsFatal for OperationError {
    /// The [`OperationError`] is considered to be fatal.
    ///
    /// Right now, the following variants are considered to be fatal:
    /// * [`OperationError::Database`]
    /// * [`OperationError::Bug`]
    fn is_fatal(&self) -> bool {
        matches!(&self, Self::Database(_) | Self::Bug(_))
    }
}
