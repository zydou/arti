//! This module is where all relay related keys are declared along their key specifier for the
//! KeyMgr so some of them can be stored on disk.

use derive_deftly::Deftly;
use derive_more::Constructor;

use tor_key_forge::define_ed25519_keypair;
use tor_keymgr::{derive_deftly_template_KeySpecifier, KeySpecifier};

// TODO: The legacy RSA key is needed. Require support in tor-key-forge and keystore.
// See https://gitlab.torproject.org/tpo/core/arti/-/work_items/1598

define_ed25519_keypair!(
    /// [KP_relayid_ed] Long-term identity keypair. Never rotates.
    pub RelayIdentity
);

#[non_exhaustive]
#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "relay")]
#[deftly(role = "KS_relayid_ed")]
#[deftly(summary = "Relay long-term identity keypair")]
/// The key sepcifier of the relay long-term identity key (RelayIdentityKeypair)
pub struct RelayIdentityKeypairSpecifier;

define_ed25519_keypair!(
    /// [KP_relaysign_ed] Medium-term signing keypair. Rotated periodically.
    pub RelaySigning
);

// TODO(#1692): reinstate this specifier
/*
#[non_exhaustive]
#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "relay")]
#[deftly(role = "KP_relaysign_ed")]
#[deftly(summary = "Relay medium-term signing keypair")]
/// The key sepcifier of the relay medium-term signing key (RelaySigningKeypair)
pub struct RelaySigningKeySpecifier;
*/

define_ed25519_keypair!(
    /// [KP_link_ed] Short-term signing keypair for link authentication. Rotated frequently.
    pub RelayLinkSigning
);
