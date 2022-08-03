//! Code to abstract over the notion of relays having one or more identities.
//!
//! Currently (2022), every Tor relay has exactly two identities: A legacy
//! identity that is based on the SHA-1 hash of an RSA-1024 public key, and a
//! modern identity that is an Ed25519 public key.  This code lets us abstract
//! over those types, and over other new types that may exist in the future.

use derive_more::{Display, From};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

/// The type of a relay identity.
///
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Display, strum::EnumIter)]
#[non_exhaustive]
pub enum RelayIdType {
    /// An Ed25519 identity.
    ///
    /// Every relay (currently) has one of these identities. It is the same
    /// as the encoding of the relay's public Ed25519 identity key.
    #[display(fmt = "Ed25519")]
    Ed25519,
    /// An RSA identity.
    ///
    /// Every relay (currently) has one of these identities.  It is computed as
    /// a SHA-1 digest of the DER encoding of the relay's public RSA 1024-bit
    /// identity key.  Because of short key length, this type of identity should
    /// not be considered secure on its own.
    #[display(fmt = "RSA (legacy)")]
    Rsa,
}

/// A single relay identity.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, From, Hash)]
#[non_exhaustive]
pub enum RelayId {
    /// An Ed25519 identity.
    #[display(fmt = "{}", _0)]
    Ed25519(Ed25519Identity),
    /// An RSA identity.
    #[display(fmt = "{}", _0)]
    Rsa(RsaIdentity),
}

/// A reference to a single relay identity.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, From, derive_more::TryInto)]
#[non_exhaustive]
pub enum RelayIdRef<'a> {
    /// An Ed25519 identity.
    #[display(fmt = "{}", _0)]
    Ed25519(&'a Ed25519Identity),
    /// An RSA identity.
    #[display(fmt = "{}", _0)]
    Rsa(&'a RsaIdentity),
}

impl RelayIdType {
    /// Return an iterator over all
    pub fn all_types() -> RelayIdTypeIter {
        use strum::IntoEnumIterator;
        Self::iter()
    }
}

impl RelayId {
    /// Return a [`RelayIdRef`] pointing to the contents of this identity.
    pub fn as_ref(&self) -> RelayIdRef<'_> {
        match self {
            RelayId::Ed25519(key) => key.into(),

            RelayId::Rsa(key) => key.into(),
        }
    }
}

impl<'a> RelayIdRef<'a> {
    /// Copy this reference into a new [`RelayId`] object.
    //
    // TODO(nickm): I wish I could make this a proper `ToOwned` implementation,
    // but I see no way to do as long as RelayIdRef<'a> implements Clone too.
    pub fn to_owned(&self) -> RelayId {
        match *self {
            RelayIdRef::Ed25519(key) => (*key).into(),
            RelayIdRef::Rsa(key) => (*key).into(),
        }
    }
}

/// Expand to an implementation for PartialEq for a given key type.
macro_rules! impl_eq_variant {
    { $var:ident($type:ty) } => {
        impl<'a> PartialEq<$type> for RelayIdRef<'a> {
            fn eq(&self, other: &$type) -> bool {
                matches!(self, RelayIdRef::$var(this) if this == &other)
            }
        }
        impl PartialEq<$type> for RelayId {
            fn eq(&self, other: &$type) -> bool {
                matches!(&self, RelayId::$var(this) if this == other)
            }
        }
    }
}

impl_eq_variant! { Rsa(RsaIdentity) }
impl_eq_variant! { Ed25519(Ed25519Identity) }
