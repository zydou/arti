//! This module is where all relay related keys are declared along their key specifier for the
//! KeyMgr so some of them can be stored on disk.

use tor_key_forge::{define_curve25519_keypair, define_ed25519_keypair, define_rsa_keypair};

define_ed25519_keypair!(
    /// [KP_relayid_ed] Long-term identity keypair. Never rotates.
    pub RelayIdentity
);

define_rsa_keypair!(
    /// [KP_relayid_rsa] Legacy RSA long-term identity keypair. Never rotates.
    pub RelayIdentityRsa
);

define_ed25519_keypair!(
    /// [KP_relaysign_ed] Medium-term signing keypair. Rotated periodically.
    pub RelaySigning
);

define_ed25519_keypair!(
    /// [KP_link_ed] Short-term signing keypair for link authentication. Rotated frequently.
    pub RelayLinkSigning
);

define_curve25519_keypair!(
    /// [KP_ntor] Medium-term keypair for the circuit extension handshake. Rotated periodically.
    #[derive(Clone)]
    pub RelayNtor
);

/// The relay’s ntor key set contains both the current key and the previous one, allowing it to
/// handle clients or relays that may be using different consensus views.
#[derive(Clone)]
pub struct RelayNtorKeys {
    /// The latest Ntor key.
    latest: RelayNtorKeypair,
    /// The previous Ntor key. First run, not previous key or if expired.
    previous: Option<RelayNtorKeypair>,
}

impl RelayNtorKeys {
    /// Constructor.
    pub fn new(latest: RelayNtorKeypair) -> Self {
        Self {
            latest,
            previous: None,
        }
    }

    /// Set the previous Ntor key.
    pub fn with_previous(mut self, previous: RelayNtorKeypair) -> Self {
        self.previous = Some(previous);
        self
    }

    /// Return the latest.
    pub fn latest(&self) -> &RelayNtorKeypair {
        &self.latest
    }

    /// Return the previous key, if any.
    pub fn previous(&self) -> Option<&RelayNtorKeypair> {
        self.previous.as_ref()
    }
}
