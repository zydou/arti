//! Error module for `tor-dirserver`
//!
//! TODO DIRMIRROR: The way on how we structure errors needs further discussion.

#[allow(unused_imports)]
use deadpool::managed::Pool;
#[allow(unused_imports)]
use std::sync::PoisonError;

use thiserror::Error;

/// An error while building a builder struct to the target structure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuilderError {
    /// Some builders have mandatory fields (i.e. fields that must be set before
    /// calling `.build()`).  In those cases, we need to yield a semantic error.
    #[error("missing field: {0}")]
    MissingField(&'static str),
}

/// An error while interacting with the database.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum DatabaseError {
    /// A low-level SQLite error, independent of deadpool, has occurred, which
    /// can have a basically infinite amount of reasons, all of them outlined in
    /// the actual SQLite and rusqlite documentations.
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
    #[error("unrecognized schema version: {0}")]
    IncompatibleSchema(String),
}

/// An error related around the HTTP protocol.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum HttpError {
    /// The `Content-Encoding` and/or `Accept-Encoding` header are (partially)
    /// invalid.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),
}

/// An error related around the StoreCache.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum StoreCacheError {
    /// An interaction with the database failed.
    #[error("database error: {0}")]
    Database(#[from] DatabaseError),
    /// An underlying programming problem.
    #[error("internal problem")]
    Bug(#[from] tor_error::Bug),
}
