//! Error module for `tor-dirserver`.

use std::{net::SocketAddr, string::FromUtf8Error};

use retry_error::RetryError;
use thiserror::Error;

/// An error while communicating with a directory authority.
///
/// This error should be returned by all functions that download or upload
/// resources to authorities, in other words: every function that interacts or
/// communicates with a directory authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum AuthorityCommunicationError {
    /// A TCP connection to an authority failed.
    ///
    /// A failure of this implies that both, the V4 and V6 (if present), have
    /// failed.
    #[error("TCP connection failure: {endpoints:?}: {error}")]
    TcpConnect {
        /// The [`SocketAddr`] items we tried to connect to, most typically
        /// the IPv4 and IPv6 address + port of the directory authority.
        endpoints: Vec<SocketAddr>,

        /// The actual I/O error that happened.
        error: std::io::Error,
    },

    /// A failure related to [`tor_dirclient`].
    ///
    /// Most likely, this will be of type [`tor_dirclient::Error::RequestFailed`],
    /// but in order to stay compatible with `non_exhaustive` we map the error.
    ///
    /// The value is in a [`Box`] to satisfy `clippy::large_enum_variant`.
    /// It is already noted in a TODO within the respective crate.
    #[error("dirclient error: {0}")]
    Dirclient(#[from] Box<tor_dirclient::Error>),

    /// An internal error.
    #[error("internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error while interacting with a database.
///
/// This error should be returned by all functions that interact with the
/// database in one way or another.
#[derive(Debug, Error)]
#[non_exhaustive]
pub(crate) enum DatabaseError {
    /// Compressing data into the database failed with an I/O error.
    #[error("compression error: {0}")]
    Compression(std::io::Error),

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
/// An error related to the request of a network document.
///
/// It mostly serves as an amalgamation of [`AuthorityCommunicationError`] and
/// [`FromUtf8Error`] because UTF-8 is the mandatory encoding for network
/// documents that is not enforced in the downloader per se.
///
/// TODO: Maybe the downloader should perform the UTF-8 conversion?
#[derive(Debug, Error)]
pub(crate) enum NetdocRequestError {
    /// Downloading the network document failed.
    #[error("download failed: {0:?}")]
    Download(RetryError<AuthorityCommunicationError>),

    /// Converting the network document to UTF-8 failed.
    #[error("UTF-8 conversion failed: {0}")]
    Utf8(#[from] FromUtf8Error),
}
