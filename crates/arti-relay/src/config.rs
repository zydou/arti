//! Types and functions to configure a Tor Relay.
//!
//! NOTE: At the moment, only StorageConfig is implemented but as we ramp up arti relay
//! implementation, more configurations will show up.

use std::borrow::Cow;
use std::path::PathBuf;

use derive_builder::Builder;
use derive_more::AsRef;

use directories::ProjectDirs;
use fs_mistrust::{Mistrust, MistrustBuilder};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
use tor_config::{ConfigBuildError, impl_standard_builder, mistrust::BuilderExt};
use tor_config_path::{CfgPath, CfgPathError, CfgPathResolver};
use tor_keymgr::config::{ArtiKeystoreConfig, ArtiKeystoreConfigBuilder};
use tracing::metadata::Level;
use tracing_subscriber::filter::EnvFilter;

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
///   - `ARTI_RELAY_SHARED_DATA`:
///     An arti-specific directory in the user's "shared data" space.
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
pub(crate) fn base_resolver() -> CfgPathResolver {
    let arti_relay_cache = project_dirs().map(|x| Cow::Owned(x.cache_dir().to_owned()));
    let arti_relay_config = project_dirs().map(|x| Cow::Owned(x.config_dir().to_owned()));
    let arti_relay_shared_data = project_dirs().map(|x| Cow::Owned(x.data_dir().to_owned()));
    let arti_relay_local_data = project_dirs().map(|x| Cow::Owned(x.data_local_dir().to_owned()));
    let program_dir = get_program_dir().map(Cow::Owned);
    let user_home = tor_config_path::home().map(Cow::Borrowed);

    let mut resolver = CfgPathResolver::default();

    resolver.set_var("ARTI_RELAY_CACHE", arti_relay_cache);
    resolver.set_var("ARTI_RELAY_CONFIG", arti_relay_config);
    resolver.set_var("ARTI_RELAY_SHARED_DATA", arti_relay_shared_data);
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
/// Most users will create a TorRelayConfig by running
/// [`TorRelayConfig::default`].
///
/// Finally, you can get fine-grained control over the members of a
/// TorRelayConfig using [`TorRelayConfigBuilder`].
#[derive(Clone, Builder, Debug, Eq, PartialEq, AsRef)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug))]
#[non_exhaustive]
pub(crate) struct TorRelayConfig {
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
}
impl_standard_builder! { TorRelayConfig }

impl tor_config::load::TopLevel for TorRelayConfig {
    type Builder = TorRelayConfigBuilder;
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
    pub(crate) fn keystore_dir(
        &self,
        resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        Ok(self
            .state_dir
            .path(resolver)
            .map_err(|e| ConfigBuildError::Invalid {
                field: "state_dir".to_owned(),
                problem: e.to_string(),
            })?
            .join("keystore"))
    }

    /// Return the fully expanded path of the cache directory.
    pub(crate) fn state_dir(
        &self,
        resolver: &CfgPathResolver,
    ) -> Result<PathBuf, ConfigBuildError> {
        resolve_cfg_path(&self.state_dir, "state_dir", resolver)
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

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

    fn cfg_variables() -> impl IntoIterator<Item = (&'static str, PathBuf)> {
        let project_dirs = project_dirs().unwrap();
        let list = [
            ("ARTI_RELAY_CACHE", project_dirs.cache_dir()),
            ("ARTI_RELAY_CONFIG", project_dirs.config_dir()),
            ("ARTI_RELAY_SHARED_DATA", project_dirs.data_dir()),
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
