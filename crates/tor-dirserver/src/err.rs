//! Error module for `tor-dirserver`.

use deadpool::managed::PoolError;
use thiserror::Error;

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
    /// Unfortuantely, those errors may overlap with [`DatabaseError::LowLevel`]
    /// under a few circumstances, but separating them is still crucial because
    /// they differ in their origin.  [`DatabaseError::Pool`] is a direct mapping
    /// to [`PoolError`], which only gets returned by functions from the
    /// [`deadpool`] and [`deadpool_sqlite`] crates, whereas
    /// [`DatabaseError::LowLevel`] refers to low-level SQLite errors directly
    /// triggered by our code in the places where we interact with parts of
    /// [`rusqlite`], such as the interaction methods of [`deadpool`].
    #[error("pool error: {0}")]
    Pool(#[from] PoolError<rusqlite::Error>),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}
