//! Implements the relay 'family' type.
//!
//! Families are opt-in lists of relays with the same operators,
//! used to avoid building insecure circuits.

use std::sync::Arc;

use crate::types::misc::LongIdent;
use crate::{Error, NetdocErrorKind, Pos, Result};
use base64ct::Encoding;
use tor_basic_utils::intern::InternCache;
use tor_llcrypto::pk::ed25519::{ED25519_ID_LEN, Ed25519Identity};
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

/// An identifier representing a relay family.
///
/// In the ["happy families"](https://spec.torproject.org/proposals/321) scheme,
/// microdescriptors will no longer have to contain a list of relay members,
/// but will instead contain these identifiers.
///
/// If two relays have a `RelayFamilyId` in common, they belong to the same family.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RelayFamilyId {
    /// An identifier derived from an Ed25519 relay family key. (`KP_familyid_ed`)
    Ed25519(Ed25519Identity),
    /// An unrecognized string.
    Unrecognized(String),
}

/// Prefix for a RelayFamilyId derived from an ed25519 `KP_familyid_ed`.
const ED25519_ID_PREFIX: &str = "ed25519:";

impl std::str::FromStr for RelayFamilyId {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut buf = [0_u8; ED25519_ID_LEN];
        if let Some(s) = s.strip_prefix(ED25519_ID_PREFIX) {
            if let Ok(decoded) = base64ct::Base64Unpadded::decode(s, &mut buf) {
                if let Some(ed_id) = Ed25519Identity::from_bytes(decoded) {
                    return Ok(RelayFamilyId::Ed25519(ed_id));
                }
            }
            return Err(NetdocErrorKind::BadArgument
                .with_msg("Invalid ed25519 family ID")
                .at_pos(Pos::at(s)));
        }
        Ok(RelayFamilyId::Unrecognized(s.to_string()))
    }
}

impl std::fmt::Display for RelayFamilyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayFamilyId::Ed25519(id) => write!(f, "{}{}", ED25519_ID_PREFIX, id),
            RelayFamilyId::Unrecognized(s) => write!(f, "{}", s),
        }
    }
}

impl PartialOrd for RelayFamilyId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Ord::cmp(self, other))
    }
}
impl Ord for RelayFamilyId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // We sort RelayFamilyId values by string representation.
        // This is not super-efficient, but we don't need to do it very often.
        Ord::cmp(&self.to_string(), &other.to_string())
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::str::FromStr;

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

    #[test]
    fn family_ids() {
        let ed_str_rep = "ed25519:7sToQRuge1bU2hS0CG0ViMndc4m82JhO4B4kdrQey80";
        let ed_id = RelayFamilyId::from_str(ed_str_rep).unwrap();
        assert!(matches!(ed_id, RelayFamilyId::Ed25519(_)));
        assert_eq!(ed_id.to_string().as_str(), ed_str_rep);

        let other_str_rep = "hello-world";
        let other_id = RelayFamilyId::from_str(other_str_rep).unwrap();
        assert!(matches!(other_id, RelayFamilyId::Unrecognized(_)));
        assert_eq!(other_id.to_string().as_str(), other_str_rep);

        assert_eq!(ed_id, ed_id);
        assert_ne!(ed_id, other_id);
    }
}
