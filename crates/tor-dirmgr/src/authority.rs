//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to sign the
//! consensus directory.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{define_list_builder_helper, impl_standard_builder, ConfigBuildError};
use tor_llcrypto::pk::rsa::RsaIdentity;

/// A single authority that signs a consensus directory.
//
// Note that we do *not* set serde(deny_unknown_fields)] on this structure:
// we want our authorities format to be future-proof against adding new info
// about each authority.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct Authority {
    /// A memorable nickname for this authority.
    #[builder(setter(into))]
    name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    #[cfg(not(feature = "experimental-api"))]
    pub(crate) v3ident: RsaIdentity,
    #[cfg(feature = "experimental-api")]
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    pub v3ident: RsaIdentity,
}

impl_standard_builder! { Authority: !Default }

/// Authority list, built
pub(crate) type AuthorityList = Vec<Authority>;

define_list_builder_helper! {
    pub(crate) struct AuthorityListBuilder {
        authorities: [AuthorityBuilder],
    }
    built: AuthorityList = authorities;
    default = default_authorities();
}

/// Return a vector of the default directory authorities.
pub(crate) fn default_authorities() -> Vec<AuthorityBuilder> {
    /// Build an authority; panic if input is bad.
    fn auth(name: &str, key: &str) -> AuthorityBuilder {
        let v3ident =
            RsaIdentity::from_hex(key).expect("Built-in authority identity had bad hex!?");
        let mut auth = AuthorityBuilder::new();
        auth.name(name).v3ident(v3ident);
        auth
    }

    // (List generated August 2020.)
    vec![
        auth("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21"),
        auth("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
        auth("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
        auth("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
        auth("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66"),
        auth("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B"),
        auth("moria1", "F533C81CEF0BC0267857C99B2F471ADF249FA232"),
        auth("tor26", "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C"),
    ]
}

impl AuthorityBuilder {
    /// Make a new AuthorityBuilder with no fields set.
    pub fn new() -> Self {
        Self::default()
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
    use tor_netdoc::doc::authcert::AuthCertKeyIds;

    impl Authority {
        /// Return true if this authority matches a given key ID.
        fn matches_keyid(&self, id: &AuthCertKeyIds) -> bool {
            self.v3ident == id.id_fingerprint
        }
    }

    #[test]
    fn authority() {
        let key1: RsaIdentity = [9_u8; 20].into();
        let key2: RsaIdentity = [10_u8; 20].into();
        let auth = Authority::builder()
            .name("example")
            .v3ident(key1)
            .build()
            .unwrap();

        assert_eq!(&auth.v3ident, &key1);

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
        let dflt = AuthorityListBuilder::default().build().unwrap();
        assert_eq!(&dflt[0].name[..], "bastet");
        assert_eq!(
            &dflt[0].v3ident.to_string()[..],
            "$27102bc123e7af1d4741ae047e160c91adc76b21"
        );
    }
}
