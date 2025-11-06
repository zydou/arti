//! Information about directory authorities
//!
//! From a client's point of view, an authority's role is to sign the
//! consensus directory.

use std::net::SocketAddr;

use derive_builder::Builder;
use getset::Getters;
use serde::{Deserialize, Serialize};
use tor_config::{ConfigBuildError, define_list_builder_accessors, impl_standard_builder};
use tor_llcrypto::pk::rsa::RsaIdentity;

/// The contact information for all directory authorities this implementation is
/// aware of.
///
/// This data structure makes use of proposal 330 in order to distinguish
/// authorities by their responsibilities, hence why the fields are divided.
#[derive(Debug, Clone, Builder, Eq, PartialEq, Getters)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct AuthorityContacts {
    /// The [`RsaIdentity`] keys that may be used to sign valid consensus documents.
    #[builder(setter(custom), default = "default_v3idents()")]
    #[getset(get = "pub")]
    v3idents: Vec<RsaIdentity>,
    /// The endpoints of authorities where upload of router descriptors and other
    /// documents is possible.
    ///
    /// This section is primarily of interest for relays.
    ///
    /// The use of nested a [`Vec`] serves the purpose to assign multiple IPs to
    /// a single logical authority, such as having an IPv4 and IPv6 address.
    #[builder(setter(custom), default = "default_uploads()")]
    #[getset(get = "pub")]
    uploads: Vec<Vec<SocketAddr>>,
    #[builder(setter(custom), default = "default_downloads()")]
    /// The endpoints of authorities where download of network documents is possible.
    ///
    /// This section is primarily of interest for directory mirrors.
    ///
    /// The use of nested a [`Vec`] serves the purpose to assign multiple IPs to
    /// a single logical authority, such as having an IPv4 and IPv6 address.
    #[getset(get = "pub")]
    downloads: Vec<Vec<SocketAddr>>,
    #[builder(setter(custom), default = "default_votes()")]
    #[getset(get = "pub")]
    /// The endpoints of authorities where voting for consensus documents is possible.
    ///
    /// This section is primarily of interest for other directory authorities.
    ///
    /// The use of nested a [`Vec`] serves the purpose to assign multiple IPs to
    /// a single logical authority, such as having an IPv4 and IPv6 address.
    votes: Vec<Vec<SocketAddr>>,
}

/// The legacy way of storing an authority before Arti 1.6.0.
///
/// Only for compatibility, see `crate::config::authority_compat`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LegacyAuthority {
    /// A memorable nickname for this authority.
    pub(crate) name: String,
    /// A SHA1 digest of the DER-encoded long-term v3 RSA identity key for
    /// this authority.
    // TODO: It would be lovely to use a better hash for these identities.
    pub(crate) v3ident: RsaIdentity,
}

impl_standard_builder! { AuthorityContacts }

define_list_builder_accessors! {
    struct AuthorityContactsBuilder {
        pub v3idents: [RsaIdentity],
        pub uploads: [Vec<SocketAddr>],
        pub downloads: [Vec<SocketAddr>],
        pub votes: [Vec<SocketAddr>],
    }
}

/// Returns a list of the default [`RsaIdentity`]s for the directory authorities.
fn default_v3idents() -> Vec<RsaIdentity> {
    fn rsa(hex: &str) -> RsaIdentity {
        RsaIdentity::from_hex(hex).expect("invalid hex?!?")
    }

    vec![
        rsa("27102BC123E7AF1D4741AE047E160C91ADC76B21"), // bastet
        rsa("0232AF901C31A04EE9848595AF9BB7620D4C5B2E"), // dannenberg
        rsa("E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"), // dizum
        rsa("70849B868D606BAECFB6128C5E3D782029AA394F"), // faravahar
        rsa("ED03BB616EB2F60BEC80151114BB25CEF515B226"), // gabelmoo
        rsa("23D15D965BC35114467363C165C4F724B64B4F66"), // longclaw
        rsa("49015F787433103580E3B66A1707A00E60F2D15B"), // maatuska
        rsa("F533C81CEF0BC0267857C99B2F471ADF249FA232"), // moria1
        rsa("2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C"), // tor26
    ]
}

/// Returns a list of the [`SocketAddr`] for the directory authorities.
///
/// The nested [`Vec`] serves dual-stack purposes
/// (i.e. many IPs mapping to one logical authority).
fn default_uploads() -> Vec<Vec<SocketAddr>> {
    /// Converts a [`str`] to a [`SocketAddr`].
    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("invalid socket address?!?")
    }

    vec![
        // bastet
        vec![
            sa("204.13.164.118:80"),
            sa("[2620:13:4000:6000::1000:118]:80"),
        ],
        // dannenberg
        vec![sa("193.23.244.244:80"), sa("[2001:678:558:1000::244]:80")],
        // dizum
        vec![sa("45.66.35.11:80"), sa("[2a09:61c0::1337]:80")],
        // faravahar
        vec![sa("216.218.219.41:80"), sa("[2001:470:164:2::2]:80")],
        // gabelmoo
        vec![
            sa("131.188.40.189:80"),
            sa("[2001:638:a000:4140::ffff:189]:80"),
        ],
        // longclaw
        vec![sa("199.58.81.140:80")],
        // maatuska
        vec![sa("171.25.193.9:443"), sa("[2001:67c:289c::9]:443")],
        // moria1
        vec![sa("128.31.0.39:9231")],
        // tor26
        vec![sa("217.196.147.77:80"), sa("[2a02:16a8:662:2203::1]:80")],
    ]
}

/// For now, an alias to [`default_uploads()`].
fn default_downloads() -> Vec<Vec<SocketAddr>> {
    default_uploads()
}

/// For now, an alias to [`default_uploads()`].
fn default_votes() -> Vec<Vec<SocketAddr>> {
    default_uploads()
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::unnecessary_wraps)]

    use super::*;

    #[test]
    fn default_auths() {
        let dflt = AuthorityContacts::builder().build().unwrap();
        assert_eq!(dflt.v3idents, default_v3idents());
        assert_eq!(dflt.uploads, default_uploads());
        assert_eq!(dflt.downloads, default_downloads());
        assert_eq!(dflt.votes, default_votes());

        assert_eq!(
            dflt.v3idents[8],
            RsaIdentity::from_hex("2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C").unwrap()
        );
        assert_eq!(
            dflt.uploads[8],
            vec![
                "217.196.147.77:80".parse().unwrap(),
                "[2a02:16a8:662:2203::1]:80".parse().unwrap()
            ]
        );
        assert_eq!(dflt.uploads[8], dflt.downloads[8]);
        assert_eq!(dflt.uploads[8], dflt.votes[8]);
    }
}
