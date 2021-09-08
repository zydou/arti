//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to to sign the
//! consensus directory.

use crate::{Error, Result};
use serde::Deserialize;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};

/// A single authority that signs a consensus directory.
//
// Note that we do *not* set serde(deny_unknown_fields)] on this structure:
// we want our authorities format to be future-proof against adding new info
// about each authority.
#[derive(Deserialize, Debug, Clone)]
pub struct Authority {
    /// A memorable nickname for this authority.
    name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    v3ident: RsaIdentity,
}

impl Authority {
    /// Return a new builder for constructing an [`Authority`].
    ///
    /// You only need this if you're using a non-default Tor network
    /// with its own set of directory authorities.
    pub fn builder() -> AuthorityBuilder {
        AuthorityBuilder::new()
    }
    /// Return the v3 identity key of this certificate.
    ///
    /// This is the identity of the >=2048-bit RSA key that the
    /// authority uses to sign documents; it is distinct from its
    /// identity keys that it uses when operating as a relay.
    pub fn v3ident(&self) -> &RsaIdentity {
        &self.v3ident
    }
    /// Return true if this authority matches a given certificate.
    pub fn matches_cert(&self, cert: &AuthCert) -> bool {
        &self.v3ident == cert.id_fingerprint()
    }

    /// Return true if this authority matches a given key ID.
    pub fn matches_keyid(&self, id: &AuthCertKeyIds) -> bool {
        self.v3ident == id.id_fingerprint
    }
}

/// Return a vector of the default directory authorities.
pub(crate) fn default_authorities() -> Vec<Authority> {
    /// Build an authority; panic if input is bad.
    fn auth(name: &str, key: &str) -> Authority {
        let v3ident = hex::decode(key).expect("Built-in authority identity had bad hex!?");
        let v3ident = RsaIdentity::from_bytes(&v3ident)
            .expect("Built-in authority identity had wrong length!?");
        AuthorityBuilder::new()
            .name(name)
            .v3ident(v3ident)
            .build()
            .expect("unable to construct built-in authority!?")
    }

    // (List generated August 2020.)
    vec![
        auth("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21"),
        auth("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
        auth("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
        auth("Faravahar", "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97"),
        auth("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
        auth("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66"),
        auth("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B"),
        auth("moria1", "D586D18309DED4CD6D57C18FDB97EFA96D330566"),
        auth("tor26", "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4"),
    ]
}

/// A Builder object for constructing an [`Authority`] entry.
#[derive(Debug, Clone, Default)]
pub struct AuthorityBuilder {
    /// See [`Authority::name`]
    name: Option<String>,
    /// See [`Authority::v3ident`]
    v3ident: Option<RsaIdentity>,
}

impl AuthorityBuilder {
    /// Make a new AuthorityBuilder with no fields set.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the name on this AuthorityBuilder.
    ///
    /// This field is required.
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.to_owned());
        self
    }
    /// Set the v3 RSA identity of this AuthorityBuilder.
    ///
    /// This field is required.
    pub fn v3ident(&mut self, key: RsaIdentity) -> &mut Self {
        self.v3ident = Some(key);
        self
    }
    /// Try to build an [`Authority`].
    pub fn build(&self) -> Result<Authority> {
        let name = self
            .name
            .as_ref()
            .ok_or(Error::BadNetworkConfig("Missing authority name"))?
            .clone();
        let v3ident = self
            .v3ident
            .ok_or(Error::BadNetworkConfig("Missing v3 identity key."))?;
        Ok(Authority { name, v3ident })
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn authority() {
        let key1: RsaIdentity = [9_u8; 20].into();
        let key2: RsaIdentity = [10_u8; 20].into();
        let auth = Authority::builder()
            .name("example")
            .v3ident(key1)
            .build()
            .unwrap();

        assert_eq!(auth.v3ident(), &key1);

        let keyids1 = AuthCertKeyIds {
            id_fingerprint: key1,
            sk_fingerprint: key2,
        };
        assert!(auth.matches_keyid(&keyids1));

        let keyids2 = AuthCertKeyIds {
            id_fingerprint: key2,
            sk_fingerprint: key2,
        };
        assert!(!auth.matches_keyid(&keyids2));
    }

    #[test]
    fn auth() {
        let dflt = default_authorities();
        assert_eq!(&dflt[0].name[..], "bastet");
        assert_eq!(
            &dflt[0].v3ident.to_string()[..],
            "$27102bc123e7af1d4741ae047e160c91adc76b21"
        );
    }
}
