//! Facilities to construct microdescriptor objects.
//!
//! (These are only for testing right now, since we don't yet
//! support encoding.)

use super::Microdesc;

use crate::types::family::RelayFamily;
use crate::types::policy::PortPolicy;
use crate::{BuildError as Error, BuildResult as Result, Error as ParseError};
use tor_llcrypto::pk::{curve25519, ed25519};

use rand::Rng;

/// A builder object used to construct a microdescriptor.
///
/// Create one of these with the [`Microdesc::builder`] method.
///
/// This facility is only enabled when the crate is built with
/// the `build_docs` feature.
#[cfg_attr(docsrs, doc(cfg(feature = "build_docs")))]
#[derive(Debug, Clone)]
pub struct MicrodescBuilder {
    /// The ntor onion key we'll be using.
    ///
    /// See [`Microdesc::ntor_onion_key`].
    ntor_onion_key: Option<curve25519::PublicKey>,
    /// The relay family we'll be using.
    ///
    /// See [`Microdesc::family`].
    family: RelayFamily,
    /// See [`Microdesc::ipv4_policy`]
    ipv4_policy: PortPolicy,
    /// See [`Microdesc::ipv6_policy`]
    ipv6_policy: PortPolicy,
    /// See [`Microdesc::ed25519_id`]
    ed25519_id: Option<ed25519::Ed25519Identity>,
}

impl MicrodescBuilder {
    /// Create a new MicrodescBuilder.
    pub(crate) fn new() -> Self {
        MicrodescBuilder {
            ntor_onion_key: None,
            family: RelayFamily::new(),
            ipv4_policy: PortPolicy::new_reject_all(),
            ipv6_policy: PortPolicy::new_reject_all(),
            ed25519_id: None,
        }
    }

    /// Set the ntor onion key.
    ///
    /// This key is required for a well-formed microdescriptor.
    pub fn ntor_key(&mut self, key: curve25519::PublicKey) -> &mut Self {
        self.ntor_onion_key = Some(key);
        self
    }

    /// Set the ed25519 identity key.
    ///
    /// This key is required for a well-formed microdescriptor.
    pub fn ed25519_id(&mut self, key: ed25519::Ed25519Identity) -> &mut Self {
        self.ed25519_id = Some(key);
        self
    }

    /// Set the family of this relay.
    ///
    /// By default, this family is empty.
    pub fn family(&mut self, family: RelayFamily) -> &mut Self {
        self.family = family;
        self
    }

    /// Set the ipv4 exit policy of this relay.
    ///
    /// By default, this policy is `reject 1-65535`.
    pub fn ipv4_policy(&mut self, policy: PortPolicy) -> &mut Self {
        self.ipv4_policy = policy;
        self
    }

    /// Set the ipv6 exit policy of this relay.
    ///
    /// By default, this policy is `reject 1-65535`.
    pub fn ipv6_policy(&mut self, policy: PortPolicy) -> &mut Self {
        self.ipv6_policy = policy;
        self
    }

    /// Set the family of this relay based on parsing a string.
    pub fn parse_family(&mut self, family: &str) -> Result<&mut Self> {
        Ok(self.family(family.parse()?))
    }

    /// Set the ipv4 exit policy of this relay based on parsing
    /// a string.
    ///
    /// By default, this policy is `reject 1-65535`.
    pub fn parse_ipv4_policy(&mut self, policy: &str) -> Result<&mut Self> {
        Ok(self.ipv4_policy(policy.parse().map_err(ParseError::from)?))
    }

    /// Set the ipv6 exit policy of this relay based on parsing
    /// a string.
    ///
    /// By default, this policy is `reject 1-65535`.
    pub fn parse_ipv6_policy(&mut self, policy: &str) -> Result<&mut Self> {
        Ok(self.ipv6_policy(policy.parse().map_err(ParseError::from)?))
    }

    /// Try to build a microdescriptor from the settings on this builder.
    ///
    /// Give an error if any required fields are not set.
    ///
    /// # Limitations
    ///
    /// This is only for testing, since it does actually encode the
    /// information in a string, and since it sets the sha256 digest
    /// field at random.
    ///
    /// In the future, when we have authority support, we'll need an
    /// encoder function instead.
    pub fn testing_md(&self) -> Result<Microdesc> {
        let ntor_onion_key = self
            .ntor_onion_key
            .ok_or(Error::CannotBuild("Missing ntor_key"))?;
        let ed25519_id = self
            .ed25519_id
            .ok_or(Error::CannotBuild("Missing ed25519_id"))?;

        // We generate a random sha256 value here, since this is only
        // for testing.
        let sha256 = rand::thread_rng().gen();

        Ok(Microdesc {
            sha256,
            ntor_onion_key,
            family: self.family.clone().intern(),
            ipv4_policy: self.ipv4_policy.clone().intern(),
            ipv6_policy: self.ipv6_policy.clone().intern(),
            ed25519_id,
        })
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

    #[test]
    fn minimal() {
        let ed: ed25519::Ed25519Identity = (*b"this is not much of a public key").into();
        let ntor: curve25519::PublicKey = (*b"but fortunately nothing cares...").into();

        let md = MicrodescBuilder::new()
            .ed25519_id(ed)
            .ntor_key(ntor)
            .testing_md()
            .unwrap();

        assert_eq!(md.ed25519_id(), &ed);
        assert_eq!(md.ntor_key(), &ntor);

        assert_eq!(md.family().members().count(), 0);
    }

    #[test]
    fn maximal() -> Result<()> {
        let ed: ed25519::Ed25519Identity = (*b"this is not much of a public key").into();
        let ntor: curve25519::PublicKey = (*b"but fortunately nothing cares...").into();

        let md = Microdesc::builder()
            .ed25519_id(ed)
            .ntor_key(ntor)
            .parse_ipv4_policy("accept 80,443")?
            .parse_ipv6_policy("accept 22-80")?
            .parse_family("$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa $bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?
            .testing_md()
            .unwrap();

        assert_eq!(md.family().members().count(), 2);
        assert!(md.family().contains(&[0xaa; 20].into()));

        assert!(md.ipv4_policy().allows_port(443));
        assert!(md.ipv4_policy().allows_port(80));
        assert!(!md.ipv4_policy().allows_port(55));

        assert!(!md.ipv6_policy().allows_port(443));
        assert!(md.ipv6_policy().allows_port(80));
        assert!(md.ipv6_policy().allows_port(55));

        Ok(())
    }

    #[test]
    fn failing() {
        let ed: ed25519::Ed25519Identity = (*b"this is not much of a public key").into();
        let ntor: curve25519::PublicKey = (*b"but fortunately nothing cares...").into();

        {
            let mut builder = Microdesc::builder();
            builder.ed25519_id(ed);
            assert!(builder.testing_md().is_err()); // no ntor
        }

        {
            let mut builder = Microdesc::builder();
            builder.ntor_key(ntor);
            assert!(builder.testing_md().is_err()); // no ed id.
        }
    }
}
