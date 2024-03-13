//! Implements the relay 'family' type.
//!
//! Families are opt-in lists of relays with the same operators,
//! used to avoid building insecure circuits.

use std::sync::Arc;

use crate::types::misc::LongIdent;
use crate::util::intern::InternCache;
use crate::{Error, Result};
use tor_llcrypto::pk::rsa::RsaIdentity;

/// Information about a relay family.
///
/// Tor relays may declare that they belong to the same family, to
/// indicate that they are controlled by the same party or parties,
/// and as such should not be used in the same circuit. Two relays
/// belong to the same family if and only if each one lists the other
/// as belonging to its family.
///
/// NOTE: when parsing, this type always discards incorrectly-formatted
/// entries, including entries that are only nicknames.
///
/// TODO: This type probably belongs in a different crate.
#[derive(Clone, Debug, Default, Hash, Eq, PartialEq)]
pub struct RelayFamily(Vec<RsaIdentity>);

/// Cache of RelayFamily objects, for saving memory.
//
/// This only holds weak references to the policy objects, so we don't
/// need to worry about running out of space because of stale entries.
static FAMILY_CACHE: InternCache<RelayFamily> = InternCache::new();

impl RelayFamily {
    /// Return a new empty RelayFamily.
    pub fn new() -> Self {
        RelayFamily::default()
    }

    /// Add `rsa_id` to this family.
    pub fn push(&mut self, rsa_id: RsaIdentity) {
        self.0.push(rsa_id);
    }

    /// Convert this family to a standard format (with all IDs sorted and de-duplicated).
    fn normalize(&mut self) {
        self.0.sort();
        self.0.dedup();
    }

    /// Consume this family, and return a new canonical interned representation
    /// of the family.
    pub fn intern(mut self) -> Arc<Self> {
        self.normalize();
        FAMILY_CACHE.intern(self)
    }

    /// Does this family include the given relay?
    pub fn contains(&self, rsa_id: &RsaIdentity) -> bool {
        self.0.contains(rsa_id)
    }

    /// Return an iterator over the RSA identity keys listed in this
    /// family.
    pub fn members(&self) -> impl Iterator<Item = &RsaIdentity> {
        self.0.iter()
    }

    /// Return true if this family has no members.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::str::FromStr for RelayFamily {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let v: Result<Vec<RsaIdentity>> = s
            .split(crate::parse::tokenize::is_sp)
            .map(|e| e.parse::<LongIdent>().map(|v| v.into()))
            .filter(Result::is_ok)
            .collect();
        Ok(RelayFamily(v?))
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
    use crate::Result;
    #[test]
    fn family() -> Result<()> {
        let f = "nickname1 nickname2 $ffffffffffffffffffffffffffffffffffffffff=foo eeeeeeeeeeeeeeeeeeeEEEeeeeeeeeeeeeeeeeee ddddddddddddddddddddddddddddddddd  $cccccccccccccccccccccccccccccccccccccccc~blarg ".parse::<RelayFamily>()?;
        let v = vec![
            RsaIdentity::from_bytes(
                &hex::decode("ffffffffffffffffffffffffffffffffffffffff").unwrap()[..],
            )
            .unwrap(),
            RsaIdentity::from_bytes(
                &hex::decode("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap()[..],
            )
            .unwrap(),
            RsaIdentity::from_bytes(
                &hex::decode("cccccccccccccccccccccccccccccccccccccccc").unwrap()[..],
            )
            .unwrap(),
        ];
        assert_eq!(f.0, v);
        Ok(())
    }

    #[test]
    fn test_contains() -> Result<()> {
        let family =
            "ffffffffffffffffffffffffffffffffffffffff eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .parse::<RelayFamily>()?;
        let in_family = RsaIdentity::from_bytes(
            &hex::decode("ffffffffffffffffffffffffffffffffffffffff").unwrap()[..],
        )
        .unwrap();
        let not_in_family = RsaIdentity::from_bytes(
            &hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()[..],
        )
        .unwrap();
        assert!(family.contains(&in_family), "Relay not found in family");
        assert!(
            !family.contains(&not_in_family),
            "Extra relay found in family"
        );
        Ok(())
    }

    #[test]
    fn mutable() {
        let mut family = RelayFamily::default();
        let key = RsaIdentity::from_hex("ffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(!family.contains(&key));
        family.push(key);
        assert!(family.contains(&key));
    }
}
