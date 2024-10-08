//! An error type for [C Tor](crate::keystore::ctor) keystores.

use crate::keystore::fs_utils;
use crate::{KeyType, KeystoreError};
use tor_error::{ErrorKind, HasKind};
use tor_hscrypto::pk::HsIdParseError;

use std::path::PathBuf;
use std::sync::Arc;

/// An error returned by a C Tor
/// [`Keystore`](crate::Keystore) implementation.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum CTorKeystoreError {
    /// An error that occurred while accessing the filesystem.
    #[error("{0}")]
    Filesystem(#[from] fs_utils::FilesystemError),

    /// Found a malformed.
    #[error("Key {path} is malformed")]
    MalformedKey {
        /// The path of the key.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: MalformedKeyError,
    },

    /// An unsupported operation.
    #[error("Operation not supported: {action}")]
    NotSupported {
        /// The action we were trying to perform.
        action: &'static str,
    },

    /// Key type and specifier mismatch.
    #[error("Invalid key type {key_type:?} for {key}")]
    InvalidKeyType {
        /// The key type.
        key_type: KeyType,
        /// The key we tried to access.
        key: String,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// Encountered a malformed C Tor key.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum MalformedKeyError {
    /// A malformed hidden service key.
    #[error("{0}")]
    Service(#[from] MalformedServiceKeyError),

    /// A malformed hidden service client key.
    #[error("{0}")]
    Client(#[from] MalformedClientKeyError),
}

/// Encountered a malformed C Tor service key.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum MalformedServiceKeyError {
    /// Found a key with an invalid tag
    #[error("invalid key length: {len} (expected {expected_len})")]
    InvalidKeyLen {
        /// The length of the invalid key.
        len: usize,
        /// The expected length of this key.
        expected_len: usize,
    },

    /// Found a key with an invalid tag
    #[error("invalid tag: {tag:?} (expected {expected_tag:?})")]
    InvalidTag {
        /// The invalid tag.
        tag: Vec<u8>,
        /// The expected value of the tag.
        expected_tag: Vec<u8>,
    },

    /// Found an invalid ed25519 public key
    #[error("invalid ed25519 public key")]
    Ed25519Public(#[from] Arc<signature::Error>),

    /// Found an invalid ed25519 keypair
    //
    // Note: this error doesn't have any context, because we use
    // ed25519::ExpandedKeypair::from_secret_key_bytes to parse the key,
    // which returns `None` if the key can't be parsed
    // (so we don't have any information about what actually went wrong).
    #[error("invalid ed25519 keypair")]
    Ed25519Keypair,

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// Encountered a malformed C Tor client key.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum MalformedClientKeyError {
    /// The auth type is not "descriptor".
    #[error("Invalid auth type {0}")]
    InvalidAuthType(String),

    /// The key type is not "x25519".
    #[error("Invalid key type {0}")]
    InvalidKeyType(String),

    /// The key is not in the `<auth-type>:x25519:<base32-encoded-public-key>` format.
    #[error("Invalid key format")]
    InvalidFormat,

    /// The encoded key material is invalid.
    #[error("Invalid key material")]
    InvalidKeyMaterial,

    /// Base32 decoding failed.
    #[error("Invalid base32 in client key")]
    InvalidBase32(#[from] data_encoding::DecodeError),

    /// Failed to parse the HsId.
    #[error("Invalid HsId client key")]
    InvalidHsId(#[from] HsIdParseError),
}

impl KeystoreError for CTorKeystoreError {}

impl HasKind for CTorKeystoreError {
    fn kind(&self) -> ErrorKind {
        use CTorKeystoreError as KE;

        match self {
            KE::Filesystem(e) => e.kind(),
            KE::MalformedKey { .. } => ErrorKind::KeystoreCorrupted,
            KE::NotSupported { .. } => ErrorKind::BadApiUsage,
            KE::InvalidKeyType { .. } => ErrorKind::BadApiUsage,
            KE::Bug(e) => e.kind(),
        }
    }
}

impl From<CTorKeystoreError> for crate::Error {
    fn from(e: CTorKeystoreError) -> Self {
        crate::Error::Keystore(Arc::new(e))
    }
}
