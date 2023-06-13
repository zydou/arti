//! This module defines the key types that can be written to a [`KeyStore`](crate::KeyStore).

pub(crate) mod ssh;

/// A type of key stored in the key store.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum KeyType {
    /// An Ed25519 keypair.
    Ed25519Keypair,
    /// A Curve25519 secret key.
    X25519StaticSecret,
    // ...plus all the other key types we're interested in (TODO)
}

impl KeyType {
    /// The file extension for a key of this type.
    //
    // TODO hs: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    pub fn arti_extension(&self) -> &'static str {
        match self {
            KeyType::Ed25519Keypair => "ed25519_private",
            KeyType::X25519StaticSecret => "x25519_private",
        }
    }

    /// The file extension for a key of this type, for use in a C Tor key store.
    //
    // TODO hs: this is subject to change (i.e. we might also need a `KeySpecifier` argument here
    // to decide the file extension should be).
    #[allow(clippy::missing_panics_doc)] // TODO hs: remove
    pub fn ctor_extension(&self) -> &'static str {
        todo!() // TODO hs
    }
}
