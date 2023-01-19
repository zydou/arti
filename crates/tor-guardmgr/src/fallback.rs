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

mod set;

use base64ct::{Base64Unpadded, Encoding as _};
use derive_builder::Builder;
use tor_config::ConfigBuildError;
use tor_config::{define_list_builder_accessors, impl_standard_builder, list_builder::VecBuilder};
use tor_linkspec::{DirectChanMethodsHelper, OwnedChanTarget};
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::dirstatus::DirStatus;
pub(crate) use set::FallbackState;
pub use set::{FallbackList, FallbackListBuilder};

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

impl FallbackDir {
    /// Return a copy of this FallbackDir as a [`FirstHop`](crate::FirstHop)
    pub fn as_guard(&self) -> crate::FirstHop {
        crate::FirstHop {
            sample: None,
            inner: crate::FirstHopInner::Chan(OwnedChanTarget::from_chan_target(self)),
        }
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
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
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

impl DirectChanMethodsHelper for FallbackDir {}

impl tor_linkspec::ChanTarget for FallbackDir {}
