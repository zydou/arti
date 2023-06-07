//! Traits for converting keys to and from OpenSSH format.
//
// TODO hs: OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

use ssh_key::private::KeypairData;
pub(crate) use ssh_key::Algorithm as SshKeyAlgorithm;

use std::io::ErrorKind;
use std::path::Path;

use crate::{EncodableKey, ErasedKey, Error, KeyType, Result};

use tor_llcrypto::pk::ed25519;

/// A helper for reading Ed25519 OpenSSH private keys from disk.
fn read_ed25519_keypair(key_type: KeyType, path: &Path) -> Result<ErasedKey> {
    let key = ssh_key::PrivateKey::read_openssh_file(path).map_err(|e| {
        if matches!(e, ssh_key::Error::Io(ErrorKind::NotFound)) {
            Error::NotFound { /* TODO hs */ }
        } else {
            Error::SshKeyRead {
                path: path.into(),
                key_type,
                err: e.into(),
            }
        }
    })?;

    // Build the expected key type (i.e. convert ssh_key key types to the key types
    // we're using internally).
    let key = match key.key_data() {
        KeypairData::Ed25519(key) => {
            ed25519::Keypair::from_bytes(&key.to_bytes()).map_err(|_| {
                Error::Bug(tor_error::internal!(
                    "failed to build ed25519 key out of ed25519 OpenSSH key"
                ))
            })?;
        }
        _ => {
            return Err(Error::UnexpectedSshKeyType {
                path: path.into(),
                wanted_key_algo: key_type.ssh_algorithm(),
                found_key_algo: key.algorithm(),
            });
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

    /// Read an OpenSSH key, parse the key material into a known key type, returning the
    /// type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    pub(crate) fn read_ssh_format_erased(&self, path: &Path) -> Result<ErasedKey> {
        match self {
            KeyType::Ed25519Keypair => read_ed25519_keypair(*self, path),
            KeyType::X25519StaticSecret => {
                // TODO hs: implement
                Err(Error::NotFound {})
            }
        }
    }

    /// Encode an OpenSSH-formatted key and write it to the specified file.
    pub(crate) fn write_ssh_format(&self, _key: &dyn EncodableKey, _path: &Path) -> Result<()> {
        todo!() // TODO hs
    }
}
