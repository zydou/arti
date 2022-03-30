//! Identifier objects used to specify guards and/or fallbacks.

use derive_more::AsRef;
use serde::{Deserialize, Serialize};
use tor_llcrypto::pk;

/// A pair of cryptographic identities used to distinguish a guard or fallback.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub(crate) struct IdPair {
    /// Ed25519 identity key for a guard
    pub(crate) ed25519: pk::ed25519::Ed25519Identity,
    /// RSA identity fingerprint for a guard
    pub(crate) rsa: pk::rsa::RsaIdentity,
}

/// An identifier for a fallback directory cache.
///
/// This is a separate type from GuardId and FirstHopId to avoid confusion
/// about what kind of object we're identifying.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, AsRef)]
pub(crate) struct FallbackId(pub(crate) IdPair);

impl FallbackId {
    /// Return a new, manually constructed `FallbackId`
    pub(crate) fn new(ed25519: pk::ed25519::Ed25519Identity, rsa: pk::rsa::RsaIdentity) -> Self {
        Self(IdPair { ed25519, rsa })
    }
    /// Extract a `FallbackId` from a ChanTarget object.
    pub(crate) fn from_chan_target<T: tor_linkspec::ChanTarget>(target: &T) -> Self {
        Self::new(*target.ed_identity(), *target.rsa_identity())
    }
}

/// An identifier for a sampled guard.
///
/// This is a separate type from GuardId and FirstHopId to avoid confusion
/// about what kind of object we're identifying.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Ord, PartialOrd, AsRef)]
#[serde(transparent)]
pub(crate) struct GuardId(pub(crate) IdPair);

impl GuardId {
    /// Return a new, manually constructed `GuardId`
    pub(crate) fn new(ed25519: pk::ed25519::Ed25519Identity, rsa: pk::rsa::RsaIdentity) -> Self {
        Self(IdPair { ed25519, rsa })
    }
    /// Extract a `GuardId` from a ChanTarget object.
    pub(crate) fn from_chan_target<T: tor_linkspec::ChanTarget>(target: &T) -> Self {
        Self::new(*target.ed_identity(), *target.rsa_identity())
    }
}

/// Implementation type held inside of FirstHopId.
///
/// This exists as a separate type from FirstHopId because Rust requires that a pub enum's variants are all public.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum FirstHopIdInner {
    /// Identifies a guard.
    Guard(GuardId),
    /// Identifies a fallback.
    Fallback(FallbackId),
}

/// A unique cryptographic identifier for a selected guard or fallback
/// directory.
///
/// (This is implemented internally using both of the guard's Ed25519 and RSA
/// identities.)
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FirstHopId(pub(crate) FirstHopIdInner);

impl From<GuardId> for FirstHopId {
    fn from(id: GuardId) -> Self {
        Self(FirstHopIdInner::Guard(id))
    }
}
impl From<FallbackId> for FirstHopId {
    fn from(id: FallbackId) -> Self {
        Self(FirstHopIdInner::Fallback(id))
    }
}
impl AsRef<IdPair> for FirstHopId {
    /// Return the inner IdPair for this object.
    ///
    /// Only use this when it's okay to erase the type information about
    /// whether this identifies a guard or a fallback.
    fn as_ref(&self) -> &IdPair {
        match &self.0 {
            FirstHopIdInner::Guard(id) => id.as_ref(),
            FirstHopIdInner::Fallback(id) => id.as_ref(),
        }
    }
}

impl FirstHopId {
    /// Return the relay in `netdir` that corresponds to this ID, if there
    /// is one.
    //
    // We have to define this function so it'll be public.
    pub fn get_relay<'a>(&self, netdir: &'a tor_netdir::NetDir) -> Option<tor_netdir::Relay<'a>> {
        let id = self.as_ref();
        netdir.by_id_pair(&id.ed25519, &id.rsa)
    }
}
