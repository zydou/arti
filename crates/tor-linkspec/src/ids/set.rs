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

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use hex_literal::hex;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn basic_usage() {
        #![allow(clippy::cognitive_complexity)]
        let rsa1 = RsaIdentity::from(hex!("42656c6f7665642c207768617420617265206e61"));
        let rsa2 = RsaIdentity::from(hex!("6d657320627574206169723f43686f6f73652074"));
        let rsa3 = RsaIdentity::from(hex!("686f752077686174657665722073756974732074"));

        let ed1 = Ed25519Identity::from(hex!(
            "6865206c696e653a43616c6c206d652053617070686f2c2063616c6c206d6520"
        ));
        let ed2 = Ed25519Identity::from(hex!(
            "43686c6f7269732c2043616c6c206d65204c616c6167652c206f7220446f7269"
        ));
        let ed3 = Ed25519Identity::from(hex!(
            "732c204f6e6c792c206f6e6c792c2063616c6c206d65207468696e652e000000"
        ));

        let mut set = RelayIdSet::new();
        assert_eq!(set.is_empty(), true);
        assert_eq!(set.len(), 0);

        set.insert(rsa1);
        set.insert(rsa2);
        set.insert(ed1);

        assert_eq!(set.is_empty(), false);
        assert_eq!(set.len(), 3);
        assert_eq!(set.contains(&rsa1), true);
        assert_eq!(set.contains(&rsa2), true);
        assert_eq!(set.contains(&rsa3), false);
        assert_eq!(set.contains(&ed1), true);
        assert_eq!(set.contains(&ed2), false);
        assert_eq!(set.contains(&ed3), false);

        let contents: HashSet<_> = set.iter().collect();
        assert_eq!(contents.len(), set.len());
        assert!(contents.contains(&RelayIdRef::from(&rsa1)));
        assert!(contents.contains(&RelayIdRef::from(&rsa2)));
        assert!(contents.contains(&RelayIdRef::from(&ed1)));

        assert_eq!(set.remove(&ed2), false);
        assert_eq!(set.remove(&ed1), true);
        assert_eq!(set.remove(&rsa3), false);
        assert_eq!(set.remove(&rsa1), true);
        assert_eq!(set.is_empty(), false);
        assert_eq!(set.len(), 1);
        assert_eq!(set.contains(&ed1), false);
        assert_eq!(set.contains(&rsa1), false);
        assert_eq!(set.contains(&rsa2), true);

        let contents2: Vec<_> = set.iter().collect();
        assert_eq!(contents2, vec![RelayIdRef::from(&rsa2)]);

        let set2: RelayIdSet = set.iter().map(|id| id.to_owned()).collect();
        assert_eq!(set, set2);

        let mut set3 = RelayIdSet::new();
        set3.extend(set.iter().map(|id| id.to_owned()));
        assert_eq!(set2, set3);
    }

    #[test]
    fn serde_empty() {
        let set = RelayIdSet::new();

        assert_tokens(&set, &[Token::Seq { len: Some(0) }, Token::SeqEnd]);
    }

    #[test]
    fn serde_singleton_rsa() {
        let mut set = RelayIdSet::new();
        set.insert(RsaIdentity::from(hex!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )));

        assert_tokens(
            &set,
            &[
                Token::Seq { len: Some(1) },
                Token::Str("$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                Token::SeqEnd,
            ],
        );
    }

    #[test]
    fn serde_singleton_ed25519() {
        let mut set = RelayIdSet::new();
        set.insert(Ed25519Identity::from(hex!(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )));

        assert_tokens(
            &set,
            &[
                Token::Seq { len: Some(1) },
                Token::String("ed25519:u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s"),
                Token::SeqEnd,
            ],
        );
    }
}
