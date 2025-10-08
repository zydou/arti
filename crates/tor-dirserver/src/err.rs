//! Error module for `tor-dirserver`.

use deadpool::managed::PoolError;
use thiserror::Error;
use void::Void;

/// An error while interacting with a database.
///
/// This error should be returned by all functions that interact with the
/// database in one way or another.  Primarily, it wraps errors from crates such
/// as [`rusqlite`], [`deadpool`], and [`deadpool_sqlite`]
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

    /// Interaction with our database pool, [`deadpool`], has failed.
    ///
    /// This error is only constructed by **some** error-variants of [`PoolError`].
    /// In general, this application handles [`PoolError`] types as follows:
    /// * [`PoolError::Backend`] is mapped to [`DatabaseError::LowLevel`].
    /// * [`PoolError::PostCreateHook`] is mapped to [`DatabaseError::Bug`].
    /// * Everything else is mapped to [`DatabaseError::Pool`].
    ///
    /// The motivation for this is, that [`PoolError::Backend`] and
    /// [`PoolError::PostCreateHook`] contain [`rusqlite::Error`] as their
    /// generic argument in the way we use it across the code base.  However,
    /// for handling [`PoolError::Backend`], we already have
    /// [`DatabaseError::LowLevel`], which exists to indicate underlying issues
    /// with the database driver.  For handling [`PoolError::PostCreateHook`],
    /// we opt for going with [`DatabaseError::Bug`], as we do not make use of
    /// any post create hooks.
    #[error("pool error: {0}")]
    Pool(#[from] PoolError<Void>),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}
