//! Implement a set of RelayId.

use std::collections::HashSet;

use serde::de::Visitor;
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

use crate::{RelayId, RelayIdRef};

/// A set of relay identities, backed by `HashSet`.
///
/// # Note
///
/// I'd rather use `HashSet` entirely, but that doesn't let us index by
/// RelayIdRef.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RelayIdSet {
    /// The Ed25519 members of this set.
    ed25519: HashSet<Ed25519Identity>,
    /// The RSA members of this set.
    rsa: HashSet<RsaIdentity>,
}

impl RelayIdSet {
    /// Construct a new empty RelayIdSet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `key` into this set.  
    ///
    /// Return true if it was not already there.
    pub fn insert<T: Into<RelayId>>(&mut self, key: T) -> bool {
        let key: RelayId = key.into();
        match key {
            RelayId::Ed25519(key) => self.ed25519.insert(key),
            RelayId::Rsa(key) => self.rsa.insert(key),
        }
    }

    /// Remove `key` from the set.
    ///
    /// Return true if `key` was present.
    pub fn remove<'a, T: Into<RelayIdRef<'a>>>(&mut self, key: T) -> bool {
        let key: RelayIdRef<'a> = key.into();
        match key {
            RelayIdRef::Ed25519(key) => self.ed25519.remove(key),
            RelayIdRef::Rsa(key) => self.rsa.remove(key),
        }
    }

    /// Return true if `key` is a member of this set.
    pub fn contains<'a, T: Into<RelayIdRef<'a>>>(&self, key: T) -> bool {
        let key: RelayIdRef<'a> = key.into();
        match key {
            RelayIdRef::Ed25519(key) => self.ed25519.contains(key),
            RelayIdRef::Rsa(key) => self.rsa.contains(key),
        }
    }

    /// Return an iterator over the members of this set.
    ///
    /// The ordering of the iterator is undefined; do not rely on it.
    pub fn iter(&self) -> impl Iterator<Item = RelayIdRef<'_>> {
        self.ed25519
            .iter()
            .map(|id| id.into())
            .chain(self.rsa.iter().map(|id| id.into()))
    }

    /// Return the number of keys in this set.
    pub fn len(&self) -> usize {
        self.ed25519.len() + self.rsa.len()
    }

    /// Return true if there are not keys in this set.
    pub fn is_empty(&self) -> bool {
        self.ed25519.is_empty() && self.rsa.is_empty()
    }
}

impl<ID: Into<RelayId>> Extend<ID> for RelayIdSet {
    fn extend<T: IntoIterator<Item = ID>>(&mut self, iter: T) {
        for item in iter {
            self.insert(item);
        }
    }
}

impl FromIterator<RelayId> for RelayIdSet {
    fn from_iter<T: IntoIterator<Item = RelayId>>(iter: T) -> Self {
        let mut set = RelayIdSet::new();
        set.extend(iter);
        set
    }
}

impl serde::Serialize for RelayIdSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

impl<'de> serde::Deserialize<'de> for RelayIdSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// A serde visitor to deserialize a sequence of RelayIds into a
        /// RelayIdSet.
        struct IdSetVisitor;
        impl<'de> Visitor<'de> for IdSetVisitor {
            type Value = RelayIdSet;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a list of relay identities")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut set = RelayIdSet::new();
                while let Some(key) = seq.next_element::<RelayId>()? {
                    set.insert(key);
                }
                Ok(set)
            }
        }
        deserializer.deserialize_seq(IdSetVisitor)
    }
}
