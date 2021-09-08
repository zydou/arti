//! Implements the relay 'family' type.
//!
//! Families are opt-in lists of relays with the same operators,
//! used to avoid building insecure circuits.

use crate::types::misc::LongIdent;
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
#[derive(Clone, Debug)]
pub struct RelayFamily(Vec<RsaIdentity>);

impl RelayFamily {
    /// Return a new empty RelayFamily.
    pub fn new() -> Self {
        RelayFamily(Vec::new())
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
}

impl Default for RelayFamily {
    fn default() -> Self {
        RelayFamily::new()
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
    #![allow(clippy::unwrap_used)]
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
}
