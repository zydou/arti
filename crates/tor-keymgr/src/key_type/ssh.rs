//! Traits for converting keys to and from OpenSSH format.
//
// TODO hs: OpenSSH keys can have passphrases. While the current implementation isn't able to
// handle such keys, we will eventually need to support them (this will be a breaking API change).

pub(crate) use ssh_key::Algorithm as SshKeyAlgorithm;

use std::path::Path;

use crate::{EncodableKey, ErasedKey, KeyType, Result};

impl KeyType {
    /// Get the algorithm of this key type.
    #[allow(unused)] // TODO hs remove
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
    pub(crate) fn read_ssh_format_erased(&self, _path: &Path) -> Result<ErasedKey> {
        todo!() // TODO hs
    }

    /// Encode an OpenSSH-formatted key and write it to the specified file.
    pub(crate) fn write_ssh_format(&self, _key: &dyn EncodableKey, _path: &Path) -> Result<()> {
        todo!() // TODO hs
    }
}
