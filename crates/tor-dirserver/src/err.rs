//! Error module for `tor-dirserver`.

use thiserror::Error;

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

/// An unrecoverable error during daemon operation.
///
/// This error is inteded for functions that generally run forever, unless they
/// encounter an error that is not recoverable, in which case, they will return
/// this error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum FatalError {
    /// The selection of a consensus from the database has failed.
    ///
    /// This most likely indicates that something with the underlying database
    /// is wrong in a persistent fashion, i.e. retries will not work anymore.
    #[error("consensus selection error: {0}")]
    ConsensusSelection(DatabaseError),
}
