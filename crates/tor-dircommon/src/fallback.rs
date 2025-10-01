//! List of directories that ships with Tor, for initial directory
//! operations.
//!
//! When a client doesn't have directory information yet, it uses a
//! "Fallback Directory" to retrieve its initial information about the
//! network.
//!
//! # Semver note
//!
//! The types in this module are re-exported from `arti-client` and
//! `tor-dirmgr`: any changes here must be reflected there.

use base64ct::{Base64Unpadded, Encoding as _};
use derive_builder::Builder;
use tor_config::{ConfigBuildError, define_list_builder_helper};
use tor_config::{define_list_builder_accessors, impl_standard_builder, list_builder::VecBuilder};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A directory whose location ships with Tor (or arti), and which we
/// can use for bootstrapping when we don't know anything else about
/// the network.
//
// Note that we do *not* set serde(deny_unknown_fields) on this
// structure: we want our fallback directory configuration format to
// be future-proof against adding new info about each fallback.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(private, name = "build_unvalidated", error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct FallbackDir {
    /// RSA identity for the directory relay
    rsa_identity: RsaIdentity,
    /// Ed25519 identity for the directory relay
    ed_identity: Ed25519Identity,
    /// List of ORPorts for the directory relay
    #[builder(sub_builder(fn_name = "build"), setter(custom))]
    orports: Vec<SocketAddr>,
}

impl_standard_builder! { FallbackDir: !Default }

define_list_builder_accessors! {
    struct FallbackDirBuilder {
        pub orports: [SocketAddr],
    }
}

impl FallbackDirBuilder {
    /// Make a new FallbackDirBuilder.
    ///
    /// You only need to use this if you're using a non-default set of
    /// fallback directories.
    pub fn new() -> Self {
        Self::default()
    }
    /// Builds a new `FallbackDir`.
    ///
    /// ### Errors
    ///
    /// Errors unless both of `rsa_identity`, `ed_identity`, and at least one `orport`,
    /// have been provided.
    pub fn build(&self) -> std::result::Result<FallbackDir, ConfigBuildError> {
        let built = self.build_unvalidated()?;
        if built.orports.is_empty() {
            return Err(ConfigBuildError::Invalid {
                field: "orport".to_string(),
                problem: "list was empty".to_string(),
            });
        }
        Ok(built)
    }
}

/// A list of fallback directories.
///
/// Fallback directories (represented by [`FallbackDir`]) are used by Tor
/// clients when they don't already have enough other directory information to
/// contact the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FallbackList {
    /// The underlying fallbacks in this set.
    fallbacks: Vec<FallbackDir>,
}

impl<T: IntoIterator<Item = FallbackDir>> From<T> for FallbackList {
    fn from(fallbacks: T) -> Self {
        FallbackList {
            fallbacks: fallbacks.into_iter().collect(),
        }
    }
}

define_list_builder_helper! {
    // pub because tor-dirmgr needs it for NetworkConfig.fallback_caches
    pub struct FallbackListBuilder {
        pub(crate) fallbacks: [FallbackDirBuilder],
    }
    built: FallbackList = FallbackList { fallbacks };
    default = default_fallbacks();
}

impl FallbackList {
    /// Return the number of fallbacks in this list.
    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }
    /// Return true if there are no fallbacks in this list.
    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }
    /// Returns an iterator over the [`FallbackDir`] items.
    pub fn iter(&self) -> std::slice::Iter<'_, FallbackDir> {
        self.fallbacks.iter()
    }
}

/// Return a list of the default fallback directories shipped with
/// arti.
pub(crate) fn default_fallbacks() -> Vec<FallbackDirBuilder> {
    /// Build a fallback directory; panic if input is bad.
    fn fallback(rsa: &str, ed: &str, ports: &[&str]) -> FallbackDirBuilder {
        let rsa = RsaIdentity::from_hex(rsa).expect("Bad hex in built-in fallback list");
        let ed = Base64Unpadded::decode_vec(ed).expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        let mut bld = FallbackDir::builder();
        bld.rsa_identity(rsa).ed_identity(ed);

        ports
            .iter()
            .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
            .for_each(|p| {
                bld.orports().push(p);
            });

        bld
    }
    include!("../data/fallback_dirs.rs")
}

impl tor_linkspec::HasAddrs for FallbackDir {
    fn addrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.orports.iter().copied()
    }
}
impl tor_linkspec::HasRelayIdsLegacy for FallbackDir {
    fn ed_identity(&self) -> &Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rsa_identity
    }
}

impl tor_linkspec::DirectChanMethodsHelper for FallbackDir {}

impl tor_linkspec::ChanTarget for FallbackDir {}
