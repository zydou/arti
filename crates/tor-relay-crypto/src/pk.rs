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
    /// Return the latest.
    pub fn latest(&self) -> &RelayNtorKeypair {
        &self.latest
    }

    /// Return the previous key, if any.
    pub fn previous(&self) -> Option<&RelayNtorKeypair> {
        self.previous.as_ref()
    }
}

/// Error returned when trying to build a [`RelayNtorKeys`] from an empty iterator.
#[derive(Clone, Debug, derive_more::Display, derive_more::Error)]
#[display("Cannot build RelayNtorKeys: iterator was empty")]
#[non_exhaustive]
pub struct NoNtorKeypairError;

impl FromIterator<RelayNtorKeypair> for Result<RelayNtorKeys, NoNtorKeypairError> {
    /// Build a [`RelayNtorKeys`] from an iterator.
    ///
    /// The last item becomes the latest key, the second-to-last (if present)
    /// becomes the previous key. Returns [`NoNtorKeypairError`] if the iterator is empty.
    ///
    /// And so it is primordial that the iterator be sorted in ascending order.
    fn from_iter<I: IntoIterator<Item = RelayNtorKeypair>>(iter: I) -> Self {
        let mut it = iter.into_iter();
        let first = it.next().ok_or(NoNtorKeypairError)?;
        let second = it.next();
        let (latest, previous) = match second {
            Some(s) => (s, Some(first)),
            None => (first, None),
        };
        Ok(RelayNtorKeys { latest, previous })
    }
}
