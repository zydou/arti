//! Error module for `tor-dirserver`

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
    UnrecognizedSchema(String),
}
