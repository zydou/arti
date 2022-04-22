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

use crate::ids::FallbackId;
use derive_builder::Builder;
use tor_config::ConfigBuildError;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use serde::Deserialize;
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
#[derive(Debug, Clone, Deserialize, Builder, Eq, PartialEq)]
#[builder(build_fn(validate = "FallbackDirBuilder::validate", error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct FallbackDir {
    /// RSA identity for the directory relay
    rsa_identity: RsaIdentity,
    /// Ed25519 identity for the directory relay
    ed_identity: Ed25519Identity,
    /// List of ORPorts for the directory relay
    orports: Vec<SocketAddr>,
}

impl FallbackDir {
    /// Return a builder that can be used to make a `FallbackDir`.
    pub fn builder() -> FallbackDirBuilder {
        FallbackDirBuilder::default()
    }

    /// Return a copy of this FallbackDir as a [`FirstHop`](crate::FirstHop)
    pub fn as_guard(&self) -> crate::FirstHop {
        crate::FirstHop {
            id: FallbackId::from_chan_target(self).into(),
            orports: self.orports.clone(),
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
    /// Add a single OR port for this fallback directory.
    ///
    /// This field is required, and may be called more than once.
    pub fn orport(&mut self, orport: SocketAddr) -> &mut Self {
        self.orports.get_or_insert_with(Vec::new).push(orport);
        self
    }
    /// Check whether this builder is ready to make a FallbackDir.
    fn validate(&self) -> std::result::Result<(), ConfigBuildError> {
        if let Some(orports) = &self.orports {
            if orports.is_empty() {
                return Err(ConfigBuildError::Invalid {
                    field: "orport".to_string(),
                    problem: "list was empty".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Return a list of the default fallback directories shipped with
/// arti.
pub(crate) fn default_fallbacks() -> Vec<FallbackDirBuilder> {
    /// Build a fallback directory; panic if input is bad.
    fn fallback(rsa: &str, ed: &str, ports: &[&str]) -> FallbackDirBuilder {
        let rsa = RsaIdentity::from_hex(rsa).expect("Bad hex in built-in fallback list");
        let ed = base64::decode_config(ed, base64::STANDARD_NO_PAD)
            .expect("Bad hex in built-in fallback list");
        let ed = Ed25519Identity::from_bytes(&ed).expect("Wrong length in built-in fallback list");
        let mut bld = FallbackDir::builder();
        bld.rsa_identity(rsa).ed_identity(ed);

        ports
            .iter()
            .map(|s| s.parse().expect("Bad socket address in fallbacklist"))
            .for_each(|p| {
                bld.orport(p);
            });

        bld
    }
    include!("fallback_dirs.inc")
}

impl tor_linkspec::ChanTarget for FallbackDir {
    fn addrs(&self) -> &[SocketAddr] {
        &self.orports[..]
    }
    fn ed_identity(&self) -> &Ed25519Identity {
        &self.ed_identity
    }
    fn rsa_identity(&self) -> &RsaIdentity {
        &self.rsa_identity
    }
}
