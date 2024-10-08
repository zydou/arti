//! Types and functions to configure a Tor Relay.
//!
//! NOTE: At the moment, only StorageConfig is implemented but as we ramp up arti relay
//! implementation, more configurations will show up.

use std::path::Path;
use std::{collections::HashMap, path::PathBuf};

use derive_builder::Builder;
use derive_more::AsRef;

use fs_mistrust::{Mistrust, MistrustBuilder};
use serde::{Deserialize, Serialize};
use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
use tor_config::{impl_standard_builder, mistrust::BuilderExt, CfgPath};
use tor_keymgr::config::{ArtiKeystoreConfig, ArtiKeystoreConfigBuilder};

pub use tor_config::ConfigBuildError;

/// A configuration used by a [`TorRelay`](crate::TorRelay).
///
/// Most users will create a TorRelayConfig by running
/// [`TorRelayConfig::default`].
///
/// If you need to override the locations where Arti stores its
/// information, you can make a TorRelayConfig with
/// [`TorRelayConfigBuilder::from_directories`].
///
/// Finally, you can get fine-grained control over the members of a
/// TorRelayConfig using [`TorRelayConfigBuilder`].
#[derive(Clone, Builder, Debug, Eq, PartialEq, AsRef)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug))]
#[non_exhaustive]
pub struct TorRelayConfig {
    /// Directories for storing information on disk
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) storage: StorageConfig,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[builder(
        sub_builder,
        field(
            type = "HashMap<String, i32>",
            build = "default_extend(self.override_net_params.clone())"
        )
    )]
    #[builder_field_attr(serde(default))]
    pub(crate) override_net_params: tor_netdoc::doc::netstatus::NetParams<i32>,

    /// Information about how to build paths through the network.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) channel: ChannelConfig,
}
impl_standard_builder! { TorRelayConfig }

impl TorRelayConfigBuilder {
    /// Returns a `TorRelayConfigBuilder` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults, except `storage.keystore.path`,
    /// which is derived from the specified state directory.
    #[allow(unused)] // TODO RELAY remove
    pub fn from_directories<P, Q>(state_dir: P, cache_dir: Q) -> Self
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let mut builder = Self::default();

        builder
            .storage()
            .cache_dir(CfgPath::new_literal(cache_dir.as_ref()))
            .state_dir(CfgPath::new_literal(state_dir.as_ref()));

        builder
    }
}

/// Helper to add overrides to a default collection.
fn default_extend<T: Default + Extend<X>, X>(to_add: impl IntoIterator<Item = X>) -> T {
    let mut collection = T::default();
    collection.extend(to_add);
    collection
}

/// Configuration for where information should be stored on disk.
///
/// By default, cache information will be stored in `${ARTI_RELAY_CACHE}`, and
/// persistent state will be stored in `${ARTI_RELAY_LOCAL_DATA}`. That means that
/// _all_ programs using these defaults will share their cache and state data.
/// If that isn't what you want, you'll need to override these directories.
///
/// On unix, the default directories will typically expand to `~/.cache/arti`
/// and `~/.local/share/arti/` respectively, depending on the user's
/// environment. Other platforms will also use suitable defaults. For more
/// information, see the documentation for [`CfgPath`].
///
/// This section is for read/write storage.
///
/// You cannot change this section on a running relay.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct StorageConfig {
    /// Location on disk for cached information.
    ///
    /// This follows the rules for `/var/cache`: "sufficiently old" filesystem objects
    /// in it may be deleted outside of the control of Arti,
    /// and Arti will continue to function properly.
    /// It is also fine to delete the directory as a whole, while Arti is not running.
    //
    // Usage note, for implementations of Arti components:
    //
    // When files in this directory are to be used by a component, the cache_dir
    // value should be passed through to the component as-is, and the component is
    // then responsible for constructing an appropriate sub-path (for example,
    // tor-dirmgr receives cache_dir, and appends components such as "dir_blobs".
    //
    // (This consistency rule is not current always followed by every component.)
    #[builder(setter(into), default = "default_cache_dir()")]
    cache_dir: CfgPath,

    /// Location on disk for less-sensitive persistent state information.
    // Usage note: see the note for `cache_dir`, above.
    #[builder(setter(into), default = "default_state_dir()")]
    state_dir: CfgPath,

    /// Location on disk for the Arti keystore.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    keystore: ArtiKeystoreConfig,

    /// Configuration about which permissions we want to enforce on our files.
    #[builder(sub_builder(fn_name = "build_for_arti"))]
    #[builder_field_attr(serde(default))]
    permissions: Mistrust,
}
impl_standard_builder! { StorageConfig }

impl StorageConfig {
    /// Return the FS permissions to use for state and cache directories.
    pub(crate) fn permissions(&self) -> &Mistrust {
        &self.permissions
    }

    /// Return the fully expanded path of the keystore directory.
    pub(crate) fn keystore_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        Ok(self
            .state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "state_dir".to_owned(),
                problem: e.to_string(),
            })?
            .join("keystore"))
    }
}

/// Return the default cache directory.
fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_RELAY_CACHE}".to_owned())
}

/// Return the default state directory.
fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_RELAY_LOCAL_DATA}".to_owned())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn defaults() {
        let dflt = TorRelayConfig::default();
        let b2 = TorRelayConfigBuilder::default();
        let dflt2 = b2.build().unwrap();
        assert_eq!(&dflt, &dflt2);
    }

    #[test]
    fn builder() {
        let mut bld = TorRelayConfigBuilder::default();
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));

        let val = bld.build().unwrap();

        assert_ne!(val, TorRelayConfig::default());
    }
}
