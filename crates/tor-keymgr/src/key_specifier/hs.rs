//! Key specifiers for HS client/service keys.

use std::sync::Arc;

use tor_hscrypto::pk::HsId;

use super::{ArtiPath, CTorPath, KeySpecifier};
use crate::Result;

/// The role of an HS client key.
#[derive(Debug, Clone, Copy, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub enum HsClientKeyRole {
    /// A key for deriving keys for decrypting HS descriptors (KP_hsc_desc_enc).
    #[display(fmt = "KP_hsc_desc_enc")]
    DescEnc,
    /// A key for computing INTRODUCE1 signatures (KP_hsc_intro_auth).
    #[display(fmt = "KP_hsc_intro_auth")]
    IntroAuth,
}

/// An HS client identifier.
#[derive(Clone, derive_more::Display)]
pub struct HsClientSpecifier(Arc<str>);

impl HsClientSpecifier {
    /// Create a new [`HsClientSpecifier`].
    // TODO hs: restrict the charset allowed for the name.
    pub fn new(client_name: &str) -> Self {
        Self(client_name.into())
    }
}

impl Default for HsClientSpecifier {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

/// An identifier for a particular instance of an HS client key.
pub struct HsClientSecretKeySpecifier {
    /// The client associated with this key.
    client_id: HsClientSpecifier,
    /// The hidden service this authorization key is for.
    hs_id: HsId,
    /// The role of the key.
    role: HsClientKeyRole,
}

impl HsClientSecretKeySpecifier {
    /// Create a new [`HsClientSecretKeySpecifier`].
    pub fn new(client_id: HsClientSpecifier, hs_id: HsId, role: HsClientKeyRole) -> Self {
        Self {
            client_id,
            hs_id,
            role,
        }
    }
}

impl KeySpecifier for HsClientSecretKeySpecifier {
    fn arti_path(&self) -> Result<ArtiPath> {
        ArtiPath::new(format!(
            "client/{}/{}/{}",
            self.client_id, self.hs_id, self.role
        ))
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        todo!()
    }
}

/// KP_hs_id, KS_hs_id.
#[allow(unused)] // TODO hs: remove
struct HsServiceIdentityKeySpecifier {
    // TODO hs
}

/// KP_hs_blind_id, KS_hs_blind_id.
#[allow(unused)] // TODO hs: remove
struct HsServiceBlindedKeySpecifier {
    // TODO hs
}

/// KP_hs_desc_sign, KS_hs_desc_sign.
#[allow(unused)] // TODO hs: remove
struct HsServiceDescriptorSigningKeySpecifier {
    // TODO hs
}
