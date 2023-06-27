//! Traits for converting keys to and from OpenSSH format.
//
// TODO HSS (#902): OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

use ssh_key::private::KeypairData;
pub(crate) use ssh_key::Algorithm as SshKeyAlgorithm;

use crate::{EncodableKey, ErasedKey, KeyType, KeystoreError, Result};

use tor_error::{ErrorKind, HasKind};
use tor_llcrypto::pk::ed25519;
use zeroize::Zeroizing;

use std::path::PathBuf;
use std::sync::Arc;

/// An unparsed OpenSSH key.
///
/// Note: This is a wrapper around the contents of a file we think is an OpenSSH key. The inner
/// value is unchecked/unvalidated, and might not actually be a valid OpenSSH key.
///
/// The inner value is zeroed on drop.
pub(crate) struct UnparsedOpenSshKey {
    /// The contents of an OpenSSH key file.
    inner: Zeroizing<Vec<u8>>,
    /// The path of the file (for error reporting).
    path: PathBuf,
}

impl UnparsedOpenSshKey {
    /// Create a new [`UnparsedOpenSshKey`].
    ///
    /// The contents of `inner` are erased on drop.
    pub(crate) fn new(inner: Vec<u8>, path: PathBuf) -> Self {
        Self {
            inner: Zeroizing::new(inner),
            path,
        }
    }
}

/// An error that occurred while processing an OpenSSH key.
//
// TODO hs: use this error type instead of crate::Error.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum SshKeyError {
    /// Failed to parse an OpenSSH key
    #[error("Failed to parse OpenSSH with type {key_type:?}")]
    SshKeyParse {
        /// The path of the malformed key.
        path: PathBuf,
        /// The type of key we were trying to fetch.
        key_type: KeyType,
        /// The underlying error.
        #[source]
        err: Arc<ssh_key::Error>,
    },

    /// The OpenSSH key we retrieved is of the wrong type.
    #[error("Unexpected OpenSSH key type: wanted {wanted_key_algo}, found {found_key_algo}")]
    UnexpectedSshKeyType {
        /// The path of the malformed key.
        path: PathBuf,
        /// The algorithm we expected the key to use.
        wanted_key_algo: SshKeyAlgorithm,
        /// The algorithm of the key we got.
        found_key_algo: SshKeyAlgorithm,
    },

    // TODO hs: remove
    /// Unsupported key type.
    #[error("Found a key type we don't support yet: {0:?}")]
    Unsupported(KeyType),
}

impl KeystoreError for SshKeyError {}

impl SshKeyError {
    /// A convenience method for boxing `self`.
    pub(crate) fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl HasKind for SshKeyError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::KeystoreCorrupted
    }
}

/// A helper for reading Ed25519 OpenSSH private keys from disk.
fn read_ed25519_keypair(key_type: KeyType, key: UnparsedOpenSshKey) -> Result<ErasedKey> {
    let sk = ssh_key::PrivateKey::from_openssh(&*key.inner).map_err(|e| {
        SshKeyError::SshKeyParse {
            // TODO: rust thinks this clone is necessary because key.path is also used below (but
            // if we get to this point, we're going to return an error and never reach the other
            // error handling branches where we use key.path).
            path: key.path.clone(),
            key_type,
            err: e.into(),
        }
    })?;

    // Build the expected key type (i.e. convert ssh_key key types to the key types
    // we're using internally).
    let key = match sk.key_data() {
        KeypairData::Ed25519(key) => {
            ed25519::Keypair::from_bytes(&key.to_bytes()).map_err(|_| {
                tor_error::internal!("failed to build ed25519 key out of ed25519 OpenSSH key")
            })?;
        }
        _ => {
            return Err(SshKeyError::UnexpectedSshKeyType {
                path: key.path,
                wanted_key_algo: key_type.ssh_algorithm(),
                found_key_algo: sk.algorithm(),
            }
            .boxed());
        }
    };

    Ok(Box::new(key))
}

impl KeyType {
    /// Get the algorithm of this key type.
    pub(crate) fn ssh_algorithm(&self) -> SshKeyAlgorithm {
        match self {
            KeyType::Ed25519Keypair => SshKeyAlgorithm::Ed25519,
            KeyType::X25519StaticSecret => {
                // The ssh-key crate doesn't support curve25519 keys. We might need a more
                // general-purpose crate for parsing keys in SSH key format (one that allows
                // arbitrary values for the algorithm).
                //
                // Alternatively, we could store curve25519 keys in openssh format as ssh-ed25519
                // (though intentionally storing the key in the wrong format only to convert it
                // back to x25519 upon retrieval is sort of ugly).
                todo!() // TODO hs
            }
        }
    }

    /// Parse an OpenSSH key, convert the key material into a known key type, and return the
    /// type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    pub(crate) fn parse_ssh_format_erased(&self, key: UnparsedOpenSshKey) -> Result<ErasedKey> {
        // TODO hs: perhaps this needs to be a method on EncodableKey instead?
        match self {
            KeyType::Ed25519Keypair => read_ed25519_keypair(*self, key),
            KeyType::X25519StaticSecret => {
                // TODO hs: implement
                Err(SshKeyError::Unsupported(*self).boxed())
            }
        }
    }

    /// Encode an OpenSSH-formatted key.
    //
    // TODO hs: remove "allow" and choose a better name for this function
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_ssh_format(&self, _key: &dyn EncodableKey) -> Result<String> {
        todo!() // TODO hs
    }
}
