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
    pub RelayNtor
);
