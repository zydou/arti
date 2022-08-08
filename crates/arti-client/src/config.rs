//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.
//!
//! # ⚠ Stability Warning ⚠
//!
//! The design of this structure, and of the configuration system for
//! Arti, is likely to change significantly before the release of Arti
//! 1.0.0. The layout of options within this structure is also likely
//! to change. For more information see ticket [#285].
//!
//! [#285]: https://gitlab.torproject.org/tpo/core/arti/-/issues/285

use derive_builder::Builder;
use derive_more::AsRef;
use fs_mistrust::{Mistrust, MistrustBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
pub use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
pub use tor_config::impl_standard_builder;
pub use tor_config::{CfgPath, CfgPathError, ConfigBuildError, Reconfigure};

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircuitTiming, CircuitTimingBuilder, PathConfig, PathConfigBuilder,
        PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
    };
}

/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dirmgr::{
        Authority, AuthorityBuilder, DirMgrConfig, DirTolerance, DirToleranceBuilder,
        DownloadSchedule, DownloadScheduleConfig, DownloadScheduleConfigBuilder, FallbackDir,
        FallbackDirBuilder, NetworkConfig, NetworkConfigBuilder,
    };
}

/// Configuration for client behavior relating to addresses.
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`ClientAddrConfigBuilder`].
///
/// You can replace this configuration on a running Arti client.  Doing so will
/// affect new streams and requests, but will have no effect on existing streams
/// and requests.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ClientAddrConfig {
    /// Should we allow attempts to make Tor connections to local addresses?
    ///
    /// This option is off by default, since (by default) Tor exits will
    /// always reject connections to such addresses.
    #[builder(default)]
    pub(crate) allow_local_addrs: bool,
}
impl_standard_builder! { ClientAddrConfig }

/// Configuration for client behavior relating to stream connection timeouts
///
/// This type is immutable once constructed. To create an object of this type,
/// use [`StreamTimeoutConfigBuilder`].
///
/// You can replace this configuration on a running Arti client.  Doing so will
/// affect new streams and requests, but will have no effect on existing streams
/// and requests—even those that are currently waiting.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct StreamTimeoutConfig {
    /// How long should we wait before timing out a stream when connecting
    /// to a host?
    #[builder(default = "default_connect_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) connect_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS record?
    #[builder(default = "default_dns_resolve_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) resolve_timeout: Duration,

    /// How long should we wait before timing out when resolving a DNS
    /// PTR record?
    #[builder(default = "default_dns_resolve_ptr_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) resolve_ptr_timeout: Duration,
}
impl_standard_builder! { StreamTimeoutConfig }

/// Return the default stream timeout
fn default_connect_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default resolve timeout
fn default_dns_resolve_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Return the default PTR resolve timeout
fn default_dns_resolve_ptr_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Extension trait for `MistrustBuilder` to convert the error type on
/// build.
trait BuilderExt {
    /// Type that this builder provides.
    type Built;
    /// Run this builder and convert its error type (if any)
    fn build_for_arti(&self) -> Result<Self::Built, ConfigBuildError>;
}

impl BuilderExt for MistrustBuilder {
    type Built = Mistrust;

    fn build_for_arti(&self) -> Result<Self::Built, ConfigBuildError> {
        self.clone()
            .controlled_by_env_var_if_not_set(FS_PERMISSIONS_CHECKS_DISABLE_VAR)
            .build()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "permissions".to_string(),
                problem: e.to_string(),
            })
    }
}

/// Configuration for where information should be stored on disk.
///
/// By default, cache information will be stored in `${ARTI_CACHE}`, and
/// persistent state will be stored in `${ARTI_LOCAL_DATA}`.  That means that
/// _all_ programs using these defaults will share their cache and state data.
/// If that isn't what you want,  you'll need to override these directories.
///
/// On unix, the default directories will typically expand to `~/.cache/arti`
/// and `~/.local/share/arti/` respectively, depending on the user's
/// environment. Other platforms will also use suitable defaults. For more
/// information, see the documentation for [`CfgPath`].
///
/// This section is for read/write storage.
///
/// You cannot change this section on a running Arti client.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct StorageConfig {
    /// Location on disk for cached directory information.
    #[builder(setter(into), default = "default_cache_dir()")]
    cache_dir: CfgPath,
    /// Location on disk for less-sensitive persistent state information.
    #[builder(setter(into), default = "default_state_dir()")]
    state_dir: CfgPath,
    /// Filesystem state to
    #[builder(sub_builder(fn_name = "build_for_arti"))]
    #[builder_field_attr(serde(default))]
    permissions: Mistrust,
}
impl_standard_builder! { StorageConfig }

/// Return the default cache directory.
fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_CACHE}".to_owned())
}

/// Return the default state directory.
fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}".to_owned())
}

impl StorageConfig {
    /// Try to expand `state_dir` to be a path buffer.
    pub(crate) fn expand_state_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.state_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "state_dir".to_owned(),
                problem: e.to_string(),
            })
    }
    /// Try to expand `cache_dir` to be a path buffer.
    pub(crate) fn expand_cache_dir(&self) -> Result<PathBuf, ConfigBuildError> {
        self.cache_dir
            .path()
            .map_err(|e| ConfigBuildError::Invalid {
                field: "cache_dir".to_owned(),
                problem: e.to_string(),
            })
    }
    /// Return the FS permissions to use for state and cache directories.
    pub(crate) fn permissions(&self) -> &Mistrust {
        &self.permissions
    }
}

/// A configuration used to bootstrap a [`TorClient`](crate::TorClient).
///
/// In order to connect to the Tor network, Arti needs to know a few
/// well-known directory caches on the network, and the public keys of the
/// network's directory authorities.  It also needs a place on disk to
/// store persistent state and cached directory information. (See [`StorageConfig`]
/// for default directories.)
///
/// Most users will create a TorClientConfig by running
/// [`TorClientConfig::default`].
///
/// If you need to override the locations where Arti stores its
/// information, you can make a TorClientConfig with
/// [`TorClientConfigBuilder::from_directories`].
///
/// Finally, you can get fine-grained control over the members of a a
/// TorClientConfig using [`TorClientConfigBuilder`].
///
/// # ⚠ Stability Warning ⚠
///
/// The design of this structure, and of the configuration system for
/// Arti, is likely to change significantly before the release of Arti
/// 1.0.0. The layout of options within this structure is also likely
/// to change. For more information see ticket [#285].
///
/// [#285]: https://gitlab.torproject.org/tpo/core/arti/-/issues/285
#[derive(Clone, Builder, Debug, Eq, PartialEq, AsRef)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug))]
#[non_exhaustive]
pub struct TorClientConfig {
    /// Information about the Tor network we want to connect to.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    tor_network: dir::NetworkConfig,

    /// Directories for storing information on disk
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) storage: StorageConfig,

    /// Information about when and how often to download directory information
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    download_schedule: dir::DownloadScheduleConfig,

    /// Information about how premature or expired our directories are allowed
    /// to be.
    ///
    /// These options help us tolerate clock skew, and help survive the case
    /// where the directory authorities are unable to reach consensus for a
    /// while.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    directory_tolerance: dir::DirTolerance,

    /// Facility to override network parameters from the values set in the
    /// consensus.
    #[builder(
        sub_builder,
        field(
            type = "HashMap<String, i32>",
            build = "convert_override_net_params(&self.override_net_params)"
        )
    )]
    #[builder_field_attr(serde(default))]
    pub(crate) override_net_params: tor_netdoc::doc::netstatus::NetParams<i32>,

    /// Information about how to build paths through the network.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) channel: ChannelConfig,

    /// Information about how to build paths through the network.
    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    path_rules: circ::PathConfig,

    /// Information about preemptive circuits.
    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    preemptive_circuits: circ::PreemptiveCircuitConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    circuit_timing: circ::CircuitTiming,

    /// Rules about which addresses the client is willing to connect to.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) address_filter: ClientAddrConfig,

    /// Information about timing out client requests.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) stream_timeouts: StreamTimeoutConfig,
}
impl_standard_builder! { TorClientConfig }

impl tor_config::load::TopLevel for TorClientConfig {
    type Builder = TorClientConfigBuilder;
}

/// Helper to convert convert_override_net_params
fn convert_override_net_params(
    builder: &HashMap<String, i32>,
) -> tor_netdoc::doc::netstatus::NetParams<i32> {
    let mut override_net_params = tor_netdoc::doc::netstatus::NetParams::new();
    for (k, v) in builder {
        override_net_params.set(k.clone(), *v);
    }
    override_net_params
}

impl tor_circmgr::CircMgrConfig for TorClientConfig {}

impl AsRef<tor_guardmgr::fallback::FallbackList> for TorClientConfig {
    fn as_ref(&self) -> &tor_guardmgr::fallback::FallbackList {
        self.tor_network.fallback_caches()
    }
}

impl TorClientConfig {
    /// Try to create a DirMgrConfig corresponding to this object.
    #[rustfmt::skip]
    pub(crate) fn dir_mgr_config(&self) -> Result<dir::DirMgrConfig, ConfigBuildError> {
        Ok(dir::DirMgrConfig {
            network:             self.tor_network        .clone(),
            schedule:            self.download_schedule  .clone(),
            tolerance:           self.directory_tolerance.clone(),
            cache_path:          self.storage.expand_cache_dir()?,
            cache_trust:         self.storage.permissions.clone(),
            override_net_params: self.override_net_params.clone(),
            extensions:          Default::default(),
        })
    }

    /// Return a reference to the [`fs_mistrust::Mistrust`] object that we'll
    /// use to check permissions on files and directories by default.
    ///
    /// # Usage notes
    ///
    /// In the future, specific files or directories may have stricter or looser
    /// permissions checks applied to them than this default.  Callers shouldn't
    /// use this [`Mistrust`] to predict what Arti will accept for a specific
    /// file or directory.  Rather, you should use this if you have some file or
    /// directory of your own on which you'd like to enforce the same rules as
    /// Arti uses.
    //
    // NOTE: The presence of this accessor is _NOT_ in any form a commitment to
    // expose every field from the configuration as an accessor.  We explicitly
    // reject that slippery slope argument.
    pub fn fs_mistrust(&self) -> &Mistrust {
        self.storage.permissions()
    }
}

impl TorClientConfigBuilder {
    /// Returns a `TorClientConfigBuilder` using the specified state and cache directories.
    ///
    /// All other configuration options are set to their defaults.
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

/// Return a filename for the default user configuration file.
pub fn default_config_file() -> Result<PathBuf, CfgPathError> {
    CfgPath::new("${ARTI_CONFIG}/arti.toml".into()).path()
}

/// The environment variable we look at when deciding whether to disable FS permissions checking.
pub const FS_PERMISSIONS_CHECKS_DISABLE_VAR: &str = "ARTI_FS_DISABLE_PERMISSION_CHECKS";

/// Return true if the environment has been set up to disable FS permissions
/// checking.
///
/// This function is exposed so that other tools can use the same checking rules
/// as `arti-client`.  For more information, see
/// [`TorClientBuilder`](crate::TorClientBuilder).
#[deprecated(since = "0.5.0")]
pub fn fs_permissions_checks_disabled_via_env() -> bool {
    std::env::var_os(FS_PERMISSIONS_CHECKS_DISABLE_VAR).is_some()
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn defaults() {
        let dflt = TorClientConfig::default();
        let b2 = TorClientConfigBuilder::default();
        let dflt2 = b2.build().unwrap();
        assert_eq!(&dflt, &dflt2);
    }

    #[test]
    fn builder() {
        let sec = std::time::Duration::from_secs(1);

        let auth = dir::Authority::builder()
            .name("Fred")
            .v3ident([22; 20].into())
            .clone();
        let mut fallback = dir::FallbackDir::builder();
        fallback
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports()
            .push("127.0.0.7:7".parse().unwrap());

        let mut bld = TorClientConfig::builder();
        bld.tor_network().set_authorities(vec![auth]);
        bld.tor_network().set_fallback_caches(vec![fallback]);
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.download_schedule().retry_certs().attempts(10);
        bld.download_schedule().retry_certs().initial_delay(sec);
        bld.download_schedule().retry_certs().parallelism(3);
        bld.download_schedule().retry_microdescs().attempts(30);
        bld.download_schedule()
            .retry_microdescs()
            .initial_delay(10 * sec);
        bld.download_schedule().retry_microdescs().parallelism(9);
        bld.override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        assert_ne!(val, TorClientConfig::default());
    }

    #[test]
    fn check_default() {
        // We don't want to second-guess the directories crate too much
        // here, so we'll just make sure it does _something_ plausible.

        let dflt = default_config_file().unwrap();
        assert!(dflt.ends_with("arti.toml"));
    }
}
