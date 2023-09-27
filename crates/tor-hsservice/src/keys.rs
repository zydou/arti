//! [`KeySpecifier`] implementations for hidden service keys.

use std::fmt;

use tor_hscrypto::time::TimePeriod;
use tor_keymgr::{ArtiPath, CTorPath, KeySpecifier};

use crate::HsNickname;

/// An identifier for a particular instance of a hidden service key.
#[derive(Clone, Debug, PartialEq)]
pub struct HsSvcKeySpecifier<'a> {
    /// The nickname of the  hidden service.
    nickname: &'a HsNickname,
    /// The role of this key
    role: HsSvcKeyRole,
}

impl<'a> HsSvcKeySpecifier<'a> {
    /// Create a new specifier for service the service with the specified `nickname`.
    pub fn new(nickname: &'a HsNickname, role: HsSvcKeyRole) -> Self {
        Self { nickname, role }
    }
}

/// The role of a hidden service key
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum HsSvcKeyRole {
    /// The public part of the identity key of the service.
    HsIdPublicKey,
    /// The blinded signing keypair.
    BlindIdKeypair(TimePeriod),
    /// The descriptor signing key.
    DescSigningKeypair(TimePeriod),
}

impl fmt::Display for HsSvcKeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use HsSvcKeyRole::*;

        match self {
            BlindIdKeypair(period) => write!(
                f,
                "KS_hs_blind_id_{}_{}",
                period.interval_num(),
                period.length()
            ),
            HsIdPublicKey => write!(f, "KP_hs_id"),
            DescSigningKeypair(period) => write!(
                f,
                "KS_hs_desc_sign_{}_{}",
                period.interval_num(),
                period.length()
            ),
        }
    }
}

impl<'a> KeySpecifier for HsSvcKeySpecifier<'a> {
    fn arti_path(&self) -> tor_keymgr::Result<ArtiPath> {
        ArtiPath::new(format!("hs/{}/{}", self.nickname, self.role))
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        // TODO HSS: the HsSvcKeySpecifier will need to be configured with all the directories used
        // by C tor. The resulting CTorPath will be prefixed with the appropriate C tor directory,
        // based on the HsSvcKeyRole.
        //
        // This function will return `None` for keys that aren't stored on disk by C tor.
        todo!()
    }
}
