//! Types and functions to configure a Tor Relay.

// TODO: It would be nice to remove the builder aspect of these config objects, as we don't need
// them for arti-relay. But I don't think we can do so while still using tor-config. See:
// https://gitlab.torproject.org/tpo/core/arti/-/issues/2253

mod listen;

use std::borrow::Cow;
use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;

use derive_builder::Builder;
use derive_more::AsRef;
use directories::ProjectDirs;
use fs_mistrust::{Mistrust, MistrustBuilder};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
use tor_circmgr::{CircuitTiming, PathConfig, PreemptiveCircuitConfig};
use tor_config::{ConfigBuildError, ExplicitOrAuto, impl_standard_builder, mistrust::BuilderExt};
use tor_config_path::{CfgPath, CfgPathError, CfgPathResolver};
use tor_dircommon::config::{NetworkConfig, NetworkConfigBuilder};
use tor_dircommon::fallback::FallbackList;
use tor_guardmgr::bridge::BridgeConfig;
use tor_guardmgr::{VanguardConfig, VanguardConfigBuilder, VanguardMode};
use tor_keymgr::config::{ArtiKeystoreConfig, ArtiKeystoreConfigBuilder};
use tracing::metadata::Level;
use tracing_subscriber::filter::EnvFilter;

use crate::util::NonEmptyList;

use self::listen::Listen;

/// Paths used for default configuration files.
pub(crate) fn default_config_paths() -> Result<Vec<PathBuf>, CfgPathError> {
    // the base path resolver includes the 'ARTI_RELAY_CONFIG' variable
    let resolver = base_resolver();
    [
        "${ARTI_RELAY_CONFIG}/arti-relay.toml",
        "${ARTI_RELAY_CONFIG}/arti-relay.d/",
    ]
    .into_iter()
    .map(|f| CfgPath::new(f.into()).path(&resolver))
    .collect()
}

/// A [`CfgPathResolver`] with the base variables configured for a Tor relay.
///
/// A relay should have a single `CfgPathResolver` that is passed around where needed to ensure that
/// all parts of the relay are resolving paths consistently using the same variables.
/// If you need to resolve a path,
/// you likely want a reference to the existing resolver,
/// and not to create a new one here.
///
/// The supported variables are:
///   - `ARTI_RELAY_CACHE`:
///     An arti-specific cache directory.
///   - `ARTI_RELAY_CONFIG`:
///     An arti-specific configuration directory.
///   - `ARTI_RELAY_LOCAL_DATA`:
///     An arti-specific directory in the user's "local data" space.
///   - `PROGRAM_DIR`:
///     The directory of the currently executing binary.
///     See documentation for [`std::env::current_exe`] for security notes.
///   - `USER_HOME`:
///     The user's home directory.
///
/// These variables are implemented using the [`directories`] crate,
/// and so should use appropriate system-specific overrides under the hood.
/// (Some of those overrides are based on environment variables.)
/// For more information, see that crate's documentation.
//
// NOTE: We intentionally don't expose an `ARTI_RELAY_SHARED_DATA`
// (analogous to `ARTI_SHARED_DATA` in arti).
// This is almost certainly never intended over `ARTI_RELAY_LOCAL_DATA`,
// so by removing it we don't need to worry about bugs from mixing them up.
// We can introduce it later if really needed.
pub(crate) fn base_resolver() -> CfgPathResolver {
    let arti_relay_cache = project_dirs().map(|x| Cow::Owned(x.cache_dir().to_owned()));
    let arti_relay_config = project_dirs().map(|x| Cow::Owned(x.config_dir().to_owned()));
    let arti_relay_local_data = project_dirs().map(|x| Cow::Owned(x.data_local_dir().to_owned()));
    let program_dir = get_program_dir().map(Cow::Owned);
    let user_home = tor_config_path::home().map(Cow::Borrowed);

    let mut resolver = CfgPathResolver::default();

    resolver.set_var("ARTI_RELAY_CACHE", arti_relay_cache);
    resolver.set_var("ARTI_RELAY_CONFIG", arti_relay_config);
    resolver.set_var("ARTI_RELAY_LOCAL_DATA", arti_relay_local_data);
    resolver.set_var("PROGRAM_DIR", program_dir);
    resolver.set_var("USER_HOME", user_home);

    resolver
}

/// The directory holding the currently executing program.
fn get_program_dir() -> Result<PathBuf, CfgPathError> {
    let binary = std::env::current_exe().map_err(|_| CfgPathError::NoProgramPath)?;
    let directory = binary.parent().ok_or(CfgPathError::NoProgramDir)?;
    Ok(directory.to_owned())
}

/// A `ProjectDirs` object for Arti relays.
fn project_dirs() -> Result<&'static ProjectDirs, CfgPathError> {
    /// lazy lock holding the ProjectDirs object.
    static PROJECT_DIRS: LazyLock<Option<ProjectDirs>> =
        LazyLock::new(|| ProjectDirs::from("org", "torproject", "Arti-Relay"));

    PROJECT_DIRS.as_ref().ok_or(CfgPathError::NoProjectDirs)
}

/// A configuration used by a TorRelay.
///
/// This is a builder so that it works with tor-config.
/// We don't expect to ever use it as a builder since we don't provide this as a public rust API.
#[derive(Clone, Builder, Debug, Eq, PartialEq, AsRef)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug))]
#[non_exhaustive]
pub(crate) struct TorRelayConfig {
    /// Configuration for the "relay" part of the relay.
    // TODO: Add a better doc comment here once we figure out exactly how we want the config to be
    // structured.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) relay: RelayConfig,

    /// Information about the Tor network we want to connect to.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) tor_network: NetworkConfig,

    /// Logging configuration
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) logging: LoggingConfig,

    /// Directories for storing information on disk
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) storage: StorageConfig,

    /// Information about how to build paths through the network.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) channel: ChannelConfig,

    /// Configuration for system resources
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) system: SystemConfig,

    /// Information about how to build paths through the network.
    // We don't expose this field in the config.
    #[builder(setter(skip))]
    #[builder_field_attr(serde(skip))]
    #[builder(default)]
    // Needed to implement `CircMgrConfig`.
    #[as_ref]
    pub(crate) path_rules: PathConfig,

    /// Information about vanguards.
    // We don't expose this field in the config.
    #[builder(setter(skip))]
    #[builder_field_attr(serde(skip))]
    #[builder(default = r#"
        VanguardConfigBuilder::default()
            .mode(ExplicitOrAuto::Explicit(VanguardMode::Disabled))
            .build()
            .expect("Could not build a disabled `VanguardConfig`")"#)]
    // Needed to implement `CircMgrConfig`.
    #[as_ref]
    pub(crate) vanguards: VanguardConfig,

    /// Information about how to retry and expire circuits and request for circuits.
    // We don't expose this field in the config.
    #[builder(setter(skip))]
    #[builder_field_attr(serde(skip))]
    #[builder(default)]
    // Needed to implement `CircMgrConfig`.
    #[as_ref]
    pub(crate) circuit_timing: CircuitTiming,

    /// Information about preemptive circuits.
    // We don't expose this field in the config.
    #[builder(setter(skip))]
    #[builder_field_attr(serde(skip))]
    #[builder(default)]
    // Needed to implement `CircMgrConfig`.
    #[as_ref]
    pub(crate) preemptive_circuits: PreemptiveCircuitConfig,
}
impl_standard_builder! { TorRelayConfig: !Default }

impl tor_config::load::TopLevel for TorRelayConfig {
    type Builder = TorRelayConfigBuilder;
}

impl tor_circmgr::CircMgrConfig for TorRelayConfig {}

// Needed to implement `GuardMgrConfig`.
impl AsRef<FallbackList> for TorRelayConfig {
    fn as_ref(&self) -> &FallbackList {
        self.tor_network.fallback_caches()
    }
}

// Needed to implement `GuardMgrConfig`.
impl AsRef<[BridgeConfig]> for TorRelayConfig {
    fn as_ref(&self) -> &[BridgeConfig] {
        // Relays don't use bridges.
        &[]
    }
}

impl tor_guardmgr::GuardMgrConfig for TorRelayConfig {
    fn bridges_enabled(&self) -> bool {
        // Relays don't use bridges.
        false
    }
}

/// Configuration for the "relay" part of the relay.
///
/// TODO: I'm not really sure what to call this yet. I'm expecting that we'll rename and reorganize
/// things as we add more options. But we should come back to this and update the name and/or doc
/// comment.
///
/// TODO: There's a high-level issue for discussing these options:
/// <https://gitlab.torproject.org/tpo/core/arti/-/issues/2252>
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub(crate) struct RelayConfig {
    /// Addresses to listen on for incoming OR connections.
    pub(crate) listen: Listen,

    /// Addresses to advertise on the network for receiving OR connections.
    // For now, we've decided that we don't want to include any IP address auto-detection in
    // arti-relay, so we require users to provide the addresses to advertise. (So no `Option` and
    // `builder(default)` here).
    pub(crate) advertise: Advertise,
}
impl_standard_builder! { RelayConfig: !Default }

/// The address(es) to advertise on the network.
// TODO: We'll want to make sure we check that the addresses are valid before uploading them in a
// server descriptor (for example no `INADDR_ANY`, multicast, etc). We can't do that validation here
// during parsing, since we don't know exactly which addresses are valid or not. For example we
// don't know if local addresses are allowed as we don't know here whether the user plans to run a
// testing tor network. We also don't want to do the validation too late (for example when uploading
// the server descriptor) as it's better to validate at startup. A better place might be to perform
// the validation in the `RelayConfig` builder validate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Advertise {
    /// All relays must advertise an IPv4 address.
    ipv4: NonEmptyList<SocketAddrV4>,
    /// Relays may optionally advertise an IPv6 address.
    ipv6: Vec<SocketAddrV6>,
}

/// Default log level.
pub(crate) const DEFAULT_LOG_LEVEL: Level = Level::INFO;

/// Logging configuration options.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError", validate = "Self::validate"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub(crate) struct LoggingConfig {
    /// Filtering directives that determine tracing levels as described at
    /// <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/targets/struct.Targets.html#impl-FromStr-for-Targets>
    ///
    /// You can override this setting with the `-l`, `--log-level` command line parameter.
    ///
    /// Example: "info,tor_proto::channel=trace"
    #[builder(default = "DEFAULT_LOG_LEVEL.to_string()", setter(into))]
    pub(crate) console: String,
}

impl LoggingConfigBuilder {
    /// Validate the options provided to the builder.
    fn validate(&self) -> Result<(), ConfigBuildError> {
        if let Some(console) = &self.console {
            EnvFilter::builder()
                .parse(console)
                .map_err(|e| ConfigBuildError::Invalid {
                    field: "console".to_string(),
                    problem: e.to_string(),
                })?;
        }
        Ok(())
    }
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
pub(crate) struct StorageConfig {
    /// Location on disk for cached information.
    ///
    /// This follows the rules for `/var/cache`: "sufficiently old" filesystem objects
    /// in it may be deleted outside of the control of Arti,
    /// and Arti will continue to function properly.
    /// It is also fine to delete the directory as a whole, while Arti is not running.
    ///
    /// Should be accessed through the `cache_dir()` getter to provide better error messages when
    /// resolving the path.
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
    ///
    /// Should be accessed through the `state_dir()` getter to provide better error messages when
    /// resolving the path.
    // Usage note: see the note for `cache_dir`, above.
    #[builder(setter(into), default = "default_state_dir()")]
    state_dir: CfgPath,

    /// Location on disk for the Arti keystore.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    keystore: ArtiKeystoreConfig,

    /// Configuration about which permissions we want to enforce on our files.
    // NOTE: This 'build_for_arti()' hard-codes the config field name as `permissions` and the
    // environment variable as `ARTI_FS_DISABLE_PERMISSION_CHECKS`. These things should be
    // configured by the application, not lower-level libraries, but some other lower-level
    // libraries like `tor-hsservice` also use 'build_for_arti()'. So we're stuck with it for now.
    // It might be confusing in the future if relays use some environment variables prefixed with
    // "ARTI_" and others with "ARTI_RELAY_", so we should probably stick to just "ARTI_".
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

    /// Return the fully expanded path of the state directory.
    pub(crate) fn state_dir(
        &self,
        resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        resolve_cfg_path(&self.state_dir, "state_dir", resolver)
    }

    /// Return the fully expanded path of the cache directory.
    pub(crate) fn cache_dir(
        &self,
        resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        resolve_cfg_path(&self.cache_dir, "cache_dir", resolver)
    }
}

/// Configuration for system resources used by the relay.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub(crate) struct SystemConfig {
    /// Memory limits (approximate)
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) memory: tor_memquota::Config,
}
impl_standard_builder! { SystemConfig }

/// Return the default cache directory.
fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_RELAY_CACHE}".to_owned())
}

/// Return the default state directory.
fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_RELAY_LOCAL_DATA}".to_owned())
}

/// Helper to return a `ConfigBuildError` if the path could not be resolved.
fn resolve_cfg_path(
    path: &CfgPath,
    name: &str,
    resolver: &CfgPathResolver,
) -> Result<PathBuf, ConfigBuildError> {
    path.path(resolver).map_err(|e| ConfigBuildError::Invalid {
        field: name.to_owned(),
        problem: e.to_string(),
    })
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

    use super::*;

    fn cfg_variables() -> impl IntoIterator<Item = (&'static str, PathBuf)> {
        let project_dirs = project_dirs().unwrap();
        let list = [
            ("ARTI_RELAY_CACHE", project_dirs.cache_dir()),
            ("ARTI_RELAY_CONFIG", project_dirs.config_dir()),
            ("ARTI_RELAY_LOCAL_DATA", project_dirs.data_local_dir()),
            ("PROGRAM_DIR", &get_program_dir().unwrap()),
            ("USER_HOME", tor_config_path::home().unwrap()),
        ];

        list.into_iter()
            .map(|(a, b)| (a, b.to_owned()))
            .collect::<Vec<_>>()
    }

    #[cfg(not(target_family = "windows"))]
    #[test]
    fn expand_variables() {
        let path_resolver = base_resolver();

        for (var, val) in cfg_variables() {
            let p = CfgPath::new(format!("${{{var}}}/example"));
            assert_eq!(p.to_string(), format!("${{{var}}}/example"));

            let expected = val.join("example");
            assert_eq!(p.path(&path_resolver).unwrap().to_str(), expected.to_str());
        }

        let p = CfgPath::new("${NOT_A_REAL_VAR}/example".to_string());
        assert!(p.path(&path_resolver).is_err());
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn expand_variables() {
        let path_resolver = base_resolver();

        for (var, val) in cfg_variables() {
            let p = CfgPath::new(format!("${{{var}}}\\example"));
            assert_eq!(p.to_string(), format!("${{{var}}}\\example"));

            let expected = val.join("example");
            assert_eq!(p.path(&path_resolver).unwrap().to_str(), expected.to_str());
        }

        let p = CfgPath::new("${NOT_A_REAL_VAR}\\example".to_string());
        assert!(p.path(&path_resolver).is_err());
    }
}
