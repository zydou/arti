//! Error module for `tor-dirserver`

#[allow(unused_imports)]
use deadpool::managed::Pool;

use deadpool::managed::PoolError;
use deadpool_sqlite::InteractError;
use thiserror::Error;

/// An error while building a builder struct to the target structure.
#[derive(Debug, Error)]
pub enum BuilderError {
    /// Some builders have mandatory fields (i.e. fields that must be set before
    /// calling `.build()`).  In those cases, we need to yield a semantic error.
    #[error("missing field: {0}")]
    MissingField(&'static str),
}

/// An error while interacting with the database.
#[derive(Debug, Error)]
pub enum DatabaseError {
    /// The interaction with the [`Pool`] object returned from [`Pool::get()`]
    /// failed, meaning we were unable to interact with the low-level SQLite
    /// database.
    #[error("pool interaction error: {0}")]
    Interaction(#[from] InteractError),
    /// A low-level SQLite error, independent of deadpool, has occurred, which
    /// can have a basically infinite amount of reasons, all of them outlined in
    /// the actual SQLite and rusqlite documentations.
    #[error("low-level rusqlite error: {0}")]
    LowLevel(#[from] rusqlite::Error),
    /// The [`Pool::get()`] method failed, meaning we were unable to obtain
    /// a database connection from the [`Pool`], for various reasons outlined in
    /// the actual [`PoolError`].
    #[error("pool error: {0}")]
    Pool(#[from] PoolError<rusqlite::Error>),
    /// This is an application level error meaning that the database can be
    /// successfully accessed but its content implies it is of a schema version
    /// we do not support.
    ///
    /// Keep in mind that an unrecognized schema is not equal to no schema.
    /// In the latter case we actually initialize the database, whereas in the
    /// previous one, we fail early in order to not corrupt an existing database.
    /// Future versions of this crate should continue with this promise in order
    /// to ensure forward compatability.
    #[error("unrecognized schema version: {0}")]
    UnrecognizedSchema(String),
}

/// An error related around the HTTP protocol.
#[derive(Debug, Error)]
pub enum HttpError {
    /// The `Content-Encoding` and/or `Accept-Encoding` header are (partially)
    /// invalid.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}
