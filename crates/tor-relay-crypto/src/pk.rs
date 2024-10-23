//! This module is where all relay related keys are declared along their key specifier for the
//! KeyMgr so some of them can be stored on disk.

use std::fmt;
use std::time::SystemTime;

use derive_deftly::Deftly;
use derive_more::derive::{From, Into};
use derive_more::Constructor;

use tor_error::Bug;
use tor_key_forge::define_ed25519_keypair;
use tor_keymgr::{
    derive_deftly_template_KeySpecifier, InvalidKeyPathComponentValue, KeySpecifier,
    KeySpecifierComponent,
};
use tor_persist::slug::{timestamp::Iso8601TimeSlug, Slug};

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
/// The key specifier of the relay long-term identity key (RelayIdentityKeypair)
pub struct RelayIdentityKeypairSpecifier;

#[non_exhaustive]
#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "relay")]
#[deftly(role = "KP_relayid_ed")]
#[deftly(summary = "Public part of the relay long-term identity keypair")]
/// The public part of the long-term identity key of the relay.
pub struct RelayIdentityPublicKeySpecifier;

define_ed25519_keypair!(
    /// [KP_relaysign_ed] Medium-term signing keypair. Rotated periodically.
    pub RelaySigning
);

#[derive(Deftly, PartialEq, Debug, Constructor)]
#[derive_deftly(KeySpecifier)]
#[deftly(prefix = "relay")]
#[deftly(role = "KS_relaysign_ed")]
#[deftly(summary = "Relay medium-term signing keypair")]
/// The key specifier of the relay medium-term signing key.
pub struct RelaySigningKeypairSpecifier {
    /// The approximate time when this key was generated.
    ///
    /// This serves as a unique identifier for this key instance.
    ///
    /// **Important**: this timestamp should not be used for anything other than
    /// distinguishing between different signing keypair instances.
    /// In particular, it should **not** be used for validating the keypair,
    /// or for checking its timeliness.
    #[deftly(denotator)]
    pub(crate) timestamp: Timestamp,
}

/// The approximate time when a [`RelaySigningKeypairSpecifier`] was generated.
///
/// Used as a denotator to distinguish between the different signing keypair instances
/// that might be stored in the keystore.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(Into, From)]
pub struct Timestamp(Iso8601TimeSlug);

impl From<SystemTime> for Timestamp {
    fn from(t: SystemTime) -> Self {
        Self(t.into())
    }
}

impl KeySpecifierComponent for Timestamp {
    fn to_slug(&self) -> Result<Slug, Bug> {
        self.0.try_into()
    }

    fn from_slug(s: &Slug) -> Result<Self, InvalidKeyPathComponentValue>
    where
        Self: Sized,
    {
        use std::str::FromStr as _;

        let timestamp = Iso8601TimeSlug::from_str(s.as_ref())
            .map_err(|e| InvalidKeyPathComponentValue::Slug(e.to_string()))?;

        Ok(Self(timestamp))
    }

    fn fmt_pretty(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

define_ed25519_keypair!(
    /// [KP_link_ed] Short-term signing keypair for link authentication. Rotated frequently.
    pub RelayLinkSigning
);

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

    use tor_keymgr::test_utils::check_key_specifier;

    #[test]
    fn relay_signing_key_specifiers() {
        let ts = SystemTime::UNIX_EPOCH;
        let key_spec = RelaySigningKeypairSpecifier::new(ts.into());

        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "relay/ks_relaysign_ed+19700101000000"
        );

        check_key_specifier(&key_spec, "relay/ks_relaysign_ed+19700101000000");
    }

    #[test]
    fn relay_identity_key_specifiers() {
        let key_spec = RelayIdentityKeypairSpecifier::new();

        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "relay/ks_relayid_ed"
        );

        check_key_specifier(&key_spec, "relay/ks_relayid_ed");

        let key_spec = RelayIdentityPublicKeySpecifier::new();

        assert_eq!(
            key_spec.arti_path().unwrap().as_str(),
            "relay/kp_relayid_ed"
        );

        check_key_specifier(&key_spec, "relay/kp_relayid_ed");
    }
}
