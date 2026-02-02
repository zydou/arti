//! Configuration for the Arti command line application
//
// (This module is called `cfg` to avoid name clash with the `config` crate, which we use.)

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config_path::CfgPath;

#[cfg(feature = "onion-service-service")]
use crate::onion_proxy::{
    OnionServiceProxyConfigBuilder, OnionServiceProxyConfigMap, OnionServiceProxyConfigMapBuilder,
};
#[cfg(not(feature = "onion-service-service"))]
use crate::onion_proxy_disabled::{OnionServiceProxyConfigMap, OnionServiceProxyConfigMapBuilder};
#[cfg(feature = "rpc")]
pub use crate::rpc::{RpcConfig, RpcConfigBuilder};
use arti_client::TorClientConfig;
#[cfg(feature = "onion-service-service")]
use tor_config::define_list_builder_accessors;
pub(crate) use tor_config::{ConfigBuildError, Listen, impl_standard_builder};

use crate::{LoggingConfig, LoggingConfigBuilder};

/// Example file demonstrating our configuration and the default options.
///
/// The options in this example file are all commented out;
/// the actual defaults are done via builder attributes in all the Rust config structs.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) const ARTI_EXAMPLE_CONFIG: &str = concat!(include_str!("./arti-example-config.toml"));

/// Test case file for the oldest version of the config we still support.
///
/// (When updating, copy `arti-example-config.toml` from the earliest version we want to
/// be compatible with.)
//
// Probably, in the long run, we will want to make this architecture more general: we'll want
// to have a larger number of examples to test, and we won't want to write a separate constant
// for each. Probably in that case, we'll want a directory of test examples, and we'll want to
// traverse the whole directory.
//
// Compare C tor, look at conf_examples and conf_failures - each of the subdirectories there is
// an example configuration situation that we wanted to validate.
//
// NB here in Arti the OLDEST_SUPPORTED_CONFIG and the ARTI_EXAMPLE_CONFIG are tested
// somewhat differently: we test that the current example is *exhaustive*, not just
// parsable.
#[cfg(test)]
const OLDEST_SUPPORTED_CONFIG: &str = concat!(include_str!("./oldest-supported-config.toml"),);

/// Structure to hold our application configuration options
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct ApplicationConfig {
    /// If true, we should watch our configuration files for changes, and reload
    /// our configuration when they change.
    ///
    /// Note that this feature may behave in unexpected ways if the path to the
    /// directory holding our configuration files changes its identity (because
    /// an intermediate symlink is changed, because the directory is removed and
    /// recreated, or for some other reason).
    #[builder(default)]
    pub(crate) watch_configuration: bool,

    /// If true, we should allow other applications not owned by the system
    /// administrator to monitor the Arti application and inspect its memory.
    ///
    /// Otherwise, we take various steps (including disabling core dumps) to
    /// make it harder for other programs to view our internal state.
    ///
    /// This option has no effect when arti is built without the `harden`
    /// feature.  When `harden` is not enabled, debugger attachment is permitted
    /// whether this option is set or not.
    #[builder(default)]
    pub(crate) permit_debugging: bool,

    /// If true, then we do not exit when we are running as `root`.
    ///
    /// This has no effect on Windows.
    #[builder(default)]
    pub(crate) allow_running_as_root: bool,
}
impl_standard_builder! { ApplicationConfig }

/// Configuration for one or more proxy listeners.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[allow(clippy::option_option)] // Builder port fields: Some(None) = specified to disable
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct ProxyConfig {
    /// Addresses to listen on for incoming SOCKS connections.
    //
    // TODO: Once http-connect is non-experimental, we should rename this option in a backward-compatible way.
    #[builder(default = "Listen::new_localhost(9150)")]
    pub(crate) socks_listen: Listen,

    /// Addresses to listen on for incoming DNS connections.
    #[builder(default = "Listen::new_none()")]
    pub(crate) dns_listen: Listen,
}
impl_standard_builder! { ProxyConfig }

/// Configuration for arti-specific storage locations.
///
/// See also [`arti_client::config::StorageConfig`].
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct ArtiStorageConfig {
    /// A file in which to write information about the ports we're listening on.
    #[builder(setter(into), default = "default_port_info_file()")]
    pub(crate) port_info_file: CfgPath,
}
impl_standard_builder! { ArtiStorageConfig }

/// Return the default ports_info_file location.
fn default_port_info_file() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}/public/port_info.json".to_owned())
}

/// Configuration for system resources used by Tor.
///
/// You cannot change *these variables* in this section on a running Arti client.
///
/// Note that there are other settings in this section,
/// in [`arti_client::config::SystemConfig`].
//
// These two structs exist because:
//
//  1. Our doctrine is that configuration structs live with the code that uses the info.
//  2. tor-memquota's configuration is used by the MemoryQuotaTracker in TorClient
//  3. File descriptor limits are enforced here in arti because it's done process-global
//  4. Nevertheless, logically, these things want to be in the same section of the file.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct SystemConfig {
    /// Maximum number of file descriptors we should launch with
    #[builder(setter(into), default = "default_max_files()")]
    pub(crate) max_files: u64,
}
impl_standard_builder! { SystemConfig }

/// Return the default maximum number of file descriptors to launch with.
fn default_max_files() -> u64 {
    16384
}

/// Structure to hold Arti's configuration options, whether from a
/// configuration file or the command line.
//
/// These options are declared in a public crate outside of `arti` so that other
/// applications can parse and use them, if desired.  If you're only embedding
/// arti via `arti-client`, and you don't want to use Arti's configuration
/// format, use [`arti_client::TorClientConfig`] instead.
///
/// By default, Arti will run using the default Tor network, store state and
/// cache information to a per-user set of directories shared by all
/// that user's applications, and run a SOCKS client on a local port.
///
/// NOTE: These are NOT the final options or their final layout. Expect NO
/// stability here.
#[derive(Debug, Builder, Clone, Eq, PartialEq)]
#[builder(derive(Serialize, Deserialize, Debug))]
#[builder(build_fn(private, name = "build_unvalidated", error = "ConfigBuildError"))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct ArtiConfig {
    /// Configuration for application behavior.
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    application: ApplicationConfig,

    /// Configuration for proxy listeners
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    proxy: ProxyConfig,

    /// Logging configuration
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    logging: LoggingConfig,

    /// Metrics configuration
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) metrics: MetricsConfig,

    /// Configuration for RPC subsystem
    #[cfg(feature = "rpc")]
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) rpc: RpcConfig,

    /// Configuration for the RPC subsystem (disabled)
    //
    // This set of options allows us to detect and warn
    // when anything is set under "rpc" in the config.
    //
    // The incantations are a bit subtle: we use an Option<toml::Value> in the builder,
    // to ensure that our configuration will continue to round-trip thorough serde.
    // We use () in the configuration type, since toml::Value isn't Eq,
    // and since we don't want to expose whatever spurious options were in the config.
    // We use builder(private), since using builder(setter(skip))
    // would (apparently) override the type of the field in builder and make it a PhantomData.
    #[cfg(not(feature = "rpc"))]
    #[builder_field_attr(serde(default))]
    #[builder(field(type = "Option<toml::Value>", build = "()"), private)]
    rpc: (),

    /// Information on system resources used by Arti.
    ///
    /// Note that there are other settings in this section,
    /// in [`arti_client::config::SystemConfig`] -
    /// these two structs overlay here.
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) system: SystemConfig,

    /// Information on where things are stored by Arti.
    ///
    /// Note that [`TorClientConfig`] also has a storage configuration;
    /// our configuration logic should merge them correctly.
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) storage: ArtiStorageConfig,

    /// Configured list of proxied onion services.
    ///
    /// Note that this field is present unconditionally, but when onion service
    /// support is disabled, it is replaced with a stub type from
    /// `onion_proxy_disabled`, and its setter functions are not implemented.
    /// The purpose of this stub type is to give an error if somebody tries to
    /// configure onion services when the `onion-service-service` feature is
    /// disabled.
    #[builder(sub_builder(fn_name = "build"), setter(custom))]
    #[builder_field_attr(serde(default))]
    pub(crate) onion_services: OnionServiceProxyConfigMap,
}

impl_standard_builder! { ArtiConfig }

impl ArtiConfigBuilder {
    /// Build the [`ArtiConfig`].
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn build(&self) -> Result<ArtiConfig, ConfigBuildError> {
        #[cfg_attr(not(feature = "onion-service-service"), allow(unused_mut))]
        let mut config = self.build_unvalidated()?;
        #[cfg(feature = "onion-service-service")]
        for svc in config.onion_services.values_mut() {
            // Pass the application-level watch_configuration to each restricted discovery config.
            *svc.svc_cfg
                .restricted_discovery_mut()
                .watch_configuration_mut() = config.application.watch_configuration;
        }

        #[cfg(not(feature = "rpc"))]
        if self.rpc.is_some() {
            tracing::warn!("rpc options were set, but Arti was built without support for rpc.");
        }

        Ok(config)
    }
}

impl tor_config::load::TopLevel for ArtiConfig {
    type Builder = ArtiConfigBuilder;
    // Some config options such as "proxy.socks_port" are no longer
    // just "deprecated" and have since been completely removed from Arti,
    // but there's no harm in informing the user that the options are still deprecated.
    // For these removed options, Arti will ignore them like it does for all unknown options.
    const DEPRECATED_KEYS: &'static [&'static str] = &["proxy.socks_port", "proxy.dns_port"];
}

#[cfg(feature = "onion-service-service")]
define_list_builder_accessors! {
    struct ArtiConfigBuilder {
        pub(crate) onion_services: [OnionServiceProxyConfigBuilder],
    }
}

/// Convenience alias for the config for a whole `arti` program
///
/// Used primarily as a type parameter on calls to [`tor_config::resolve`]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) type ArtiCombinedConfig = (ArtiConfig, TorClientConfig);

/// Configuration for exporting metrics (eg, perf data)
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct MetricsConfig {
    /// Where to listen for incoming HTTP connections.
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) prometheus: PrometheusConfig,
}
impl_standard_builder! { MetricsConfig }

/// Configuration for one or more proxy listeners.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[allow(clippy::option_option)] // Builder port fields: Some(None) = specified to disable
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
#[cfg_attr(feature = "experimental-api", builder(public))]
pub(crate) struct PrometheusConfig {
    /// Port on which to establish a Prometheus scrape endpoint
    ///
    /// We listen here for incoming HTTP connections.
    ///
    /// If just a port is provided, we don't support IPv6.
    /// Alternatively, (only) a single address and port can be specified.
    /// These restrictions are due to upstream limitations:
    /// <https://github.com/metrics-rs/metrics/issues/567>.
    #[builder(default)]
    #[builder_field_attr(serde(default))]
    pub(crate) listen: Listen,
}
impl_standard_builder! { PrometheusConfig }

impl ArtiConfig {
    /// Return the [`ApplicationConfig`] for this configuration.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn application(&self) -> &ApplicationConfig {
        &self.application
    }

    /// Return the [`LoggingConfig`] for this configuration.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn logging(&self) -> &LoggingConfig {
        &self.logging
    }

    /// Return the [`ProxyConfig`] for this configuration.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn proxy(&self) -> &ProxyConfig {
        &self.proxy
    }

    /// Return the [`ArtiStorageConfig`] for this configuration.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    ///
    pub(crate) fn storage(&self) -> &ArtiStorageConfig {
        &self.storage
    }

    /// Return the [`RpcConfig`] for this configuration.
    #[cfg(feature = "rpc")]
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn rpc(&self) -> &RpcConfig {
        &self.rpc
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    // TODO add this next lint to maint/add_warning, for all tests
    #![allow(clippy::iter_overeager_cloned)]
    // Saves adding many individual #[cfg], or a sub-module
    #![cfg_attr(not(feature = "pt-client"), allow(dead_code))]

    use arti_client::config::TorClientConfigBuilder;
    use arti_client::config::dir;
    use itertools::{EitherOrBoth, Itertools, chain};
    use regex::Regex;
    use std::collections::HashSet;
    use std::fmt::Write as _;
    use std::iter;
    use std::time::Duration;
    use tor_config::load::{ConfigResolveError, ResolutionResults};
    use tor_config_path::CfgPath;

    #[allow(unused_imports)] // depends on features
    use tor_error::ErrorReport as _;

    #[cfg(feature = "restricted-discovery")]
    use {
        arti_client::HsClientDescEncKey,
        std::str::FromStr as _,
        tor_hsservice::config::restricted_discovery::{
            DirectoryKeyProviderBuilder, HsClientNickname,
        },
    };

    use super::*;

    //---------- tests that rely on the provided example config file ----------
    //
    // These are quite complex.  They uncomment the file, parse bits of it,
    // and do tests via serde and via the normal config machinery,
    // to see that everything is documented as expected.

    fn uncomment_example_settings(template: &str) -> String {
        let re = Regex::new(r#"(?m)^\#([^ \n])"#).unwrap();
        re.replace_all(template, |cap: &regex::Captures<'_>| -> _ {
            cap.get(1).unwrap().as_str().to_string()
        })
        .into()
    }

    /// Is this key present or absent in the examples in one of the example files ?
    ///
    /// Depending on which variable this is in, it refers to presence in other the
    /// old or the new example file.
    ///
    /// This type is *not* used in declarations in `declared_config_exceptions`;
    /// it is used by the actual checking code.
    /// The declarations use types in that function.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    enum InExample {
        Absent,
        Present,
    }
    /// Which of the two example files?
    ///
    /// This type is *not* used in declarations in `declared_config_exceptions`;
    /// it is used by the actual checking code.
    /// The declarations use types in that function.
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
    enum WhichExample {
        Old,
        New,
    }
    /// An exception to the usual expectations about configuration example files
    ///
    /// This type is *not* used in declarations in `declared_config_exceptions`;
    /// it is used by the actual checking code.
    /// The declarations use types in that function.
    #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
    struct ConfigException {
        /// The actual config key
        key: String,
        /// Does it appear in the oldest supported example file?
        in_old_example: InExample,
        /// Does it appear in the current example file?
        in_new_example: InExample,
        /// Does our code recognise it ?  `None` means "don't know"
        in_code: Option<bool>,
    }
    impl ConfigException {
        fn in_example(&self, which: WhichExample) -> InExample {
            use WhichExample::*;
            match which {
                Old => self.in_old_example,
                New => self.in_new_example,
            }
        }
    }

    /// *every* feature that's listed as `InCode::FeatureDependent`
    const ALL_RELEVANT_FEATURES_ENABLED: bool = cfg!(all(
        feature = "bridge-client",
        feature = "pt-client",
        feature = "onion-service-client",
        feature = "rpc",
    ));

    /// Return the expected exceptions to the usual expectations about config and examples
    fn declared_config_exceptions() -> Vec<ConfigException> {
        /// Is this key recognised by the parsing code ?
        ///
        /// (This can be feature-dependent, so literal values of this type
        /// are often feature-qualified.)
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
        enum InCode {
            /// No configuration of this codebase knows about this option
            Ignored,
            /// *Some* configuration of this codebase know about this option
            ///
            /// This means:
            ///   - If *every* feature in `ALL_RELEVANT_FEATURES_ENABLED` is enabled,
            ///     the config key is expected to be `Recognised`
            ///   - Otherwise we're not sure (because cargo features are additive,
            ///     dependency crates' features might be *en*abled willy-nilly).
            FeatureDependent,
            /// All configurations of this codebase know about this option
            Recognized,
        }
        use InCode::*;

        /// Marker.  `Some(InOld)` means presence of this config key in the oldest-supported file
        struct InOld;
        /// Marker.  `Some(InNew)` means presence of this config key in the current example file
        struct InNew;

        let mut out = vec![];

        // Declare some keys which aren't "normal", eg they aren't documented in the usual
        // way, are configurable, aren't in the oldest supported file, etc.
        //
        // `in_old_example` and `in_new_example` are whether the key appears in
        // `arti-example-config.toml` and `oldest-supported-config.toml` respectively.
        // (in each case, only a line like `#example.key = ...` counts.)
        //
        // `whether_supported` tells is if the key is supposed to be
        // recognised by the code.
        //
        // `keys` is the list of keys.  Add a // comment at the start of the list
        // so that rustfmt retains the consistent formatting.
        let mut declare_exceptions = |in_old_example: Option<InOld>,
                                      in_new_example: Option<InNew>,
                                      in_code: InCode,
                                      keys: &[&str]| {
            let in_code = match in_code {
                Ignored => Some(false),
                Recognized => Some(true),
                FeatureDependent if ALL_RELEVANT_FEATURES_ENABLED => Some(true),
                FeatureDependent => None,
            };
            #[allow(clippy::needless_pass_by_value)] // pass by value defends against a->a b->a
            fn in_example<T>(spec: Option<T>) -> InExample {
                match spec {
                    None => InExample::Absent,
                    Some(_) => InExample::Present,
                }
            }
            let in_old_example = in_example(in_old_example);
            let in_new_example = in_example(in_new_example);
            out.extend(keys.iter().cloned().map(|key| ConfigException {
                key: key.to_owned(),
                in_old_example,
                in_new_example,
                in_code,
            }));
        };

        declare_exceptions(
            None,
            Some(InNew),
            Recognized,
            &[
                // Keys that are newer than the oldest-supported example, but otherwise normal.
                "application.allow_running_as_root",
                "bridges",
                "logging.time_granularity",
                "path_rules.long_lived_ports",
                "use_obsolete_software",
                "circuit_timing.disused_circuit_timeout",
                "storage.port_info_file",
            ],
        );

        declare_exceptions(
            None,
            None,
            Recognized,
            &[
                // Examples exist but are not auto-testable
                "tor_network.authorities",
                "tor_network.fallback_caches",
            ],
        );

        declare_exceptions(
            None,
            None,
            Recognized,
            &[
                // Examples exist but are not auto-testable
                "logging.opentelemetry",
            ],
        );

        declare_exceptions(
            Some(InOld),
            Some(InNew),
            if cfg!(target_family = "windows") {
                Ignored
            } else {
                Recognized
            },
            &[
                // Unix-only mistrust settings
                "storage.permissions.trust_group",
                "storage.permissions.trust_user",
            ],
        );

        declare_exceptions(
            None,
            None, // TODO: Make examples for bridges settings!
            FeatureDependent,
            &[
                // Settings only available with bridge support
                "bridges.transports", // we recognise this so we can reject it
            ],
        );

        declare_exceptions(
            None,
            Some(InNew),
            FeatureDependent,
            &[
                // Settings only available with experimental-api support
                "storage.keystore",
            ],
        );

        declare_exceptions(
            None,
            None, // it's there, but not formatted for auto-testing
            FeatureDependent,
            &[
                // Settings only available with tokio-console support
                "logging.tokio_console",
                "logging.tokio_console.enabled",
            ],
        );

        declare_exceptions(
            None,
            None, // it's there, but not formatted for auto-testing
            Recognized,
            &[
                // Memory quota, tested by fn memquota (below)
                "system.memory",
                "system.memory.max",
                "system.memory.low_water",
            ],
        );

        declare_exceptions(
            None,
            Some(InNew), // The top-level section is in the new file (only).
            Recognized,
            &["metrics"],
        );

        declare_exceptions(
            None,
            None, // The inner information is not formatted for auto-testing
            Recognized,
            &[
                // Prometheus metrics exporter, tested by fn metrics (below)
                "metrics.prometheus",
                "metrics.prometheus.listen",
            ],
        );

        declare_exceptions(
            None,
            Some(InNew),
            FeatureDependent,
            &[
                // PT-only settings
            ],
        );

        declare_exceptions(
            None,
            Some(InNew),
            FeatureDependent,
            &[
                // HS client settings
                "address_filter.allow_onion_addrs",
                "circuit_timing.hs_desc_fetch_attempts",
                "circuit_timing.hs_intro_rend_attempts",
            ],
        );

        declare_exceptions(
            None,
            None, // TODO RPC, these should actually appear in the example config
            FeatureDependent,
            &[
                // RPC-only settings
                "rpc",
                "rpc.rpc_listen",
            ],
        );

        // These are commented-out by default, and tested with test::onion_services().
        declare_exceptions(
            None,
            None,
            FeatureDependent,
            &[
                // onion-service only settings.
                "onion_services",
            ],
        );

        declare_exceptions(
            None,
            Some(InNew),
            FeatureDependent,
            &[
                // Vanguards-specific settings
                "vanguards",
                "vanguards.mode",
            ],
        );

        // These are commented-out by default
        declare_exceptions(
            None,
            None,
            FeatureDependent,
            &[
                "storage.keystore.ctor",
                "storage.keystore.ctor.services",
                "storage.keystore.ctor.clients",
            ],
        );

        out.sort();

        let dupes = out.iter().map(|exc| &exc.key).duplicates().collect_vec();
        assert!(
            dupes.is_empty(),
            "duplicate exceptions in configuration {dupes:?}"
        );

        eprintln!(
            "declared config exceptions for this configuration:\n{:#?}",
            &out
        );
        out
    }

    #[test]
    fn default_config() {
        use InExample::*;

        let empty_config = tor_config::ConfigurationSources::new_empty()
            .load()
            .unwrap();
        let empty_config: ArtiCombinedConfig = tor_config::resolve(empty_config).unwrap();

        let default = (ArtiConfig::default(), TorClientConfig::default());
        let exceptions = declared_config_exceptions();

        /// Helper to decide what to do about a possible discrepancy
        ///
        /// Provided with `EitherOrBoth` of:
        ///   - the config key that the config parser reported it found, but didn't recognise
        ///   - the declared exception entry
        ///     (for the same config key)
        ///
        /// Decides whether this is something that should fail the test.
        /// If so it returns `Err((key, error_message))`, otherwise `Ok`.
        #[allow(clippy::needless_pass_by_value)] // clippy is IMO wrong about eob
        fn analyse_joined_info(
            which: WhichExample,
            uncommented: bool,
            eob: EitherOrBoth<&String, &ConfigException>,
        ) -> Result<(), (String, String)> {
            use EitherOrBoth::*;
            let (key, err) = match eob {
                // Unrecognised entry, no exception
                Left(found) => (found, "found in example but not processed".into()),
                Both(found, exc) => {
                    let but = match (exc.in_example(which), exc.in_code, uncommented) {
                        (Absent, _, _) => "but exception entry expected key to be absent",
                        (_, _, false) => "when processing still-commented-out file!",
                        (_, Some(true), _) => {
                            "but an exception entry says it should have been recognised"
                        }
                        (Present, Some(false), true) => return Ok(()), // that's as expected
                        (Present, None, true) => return Ok(()), // that's could be as expected
                    };
                    (
                        found,
                        format!("parser reported unrecognised config key, {but}"),
                    )
                }
                Right(exc) => {
                    // An exception entry exists.  The actual situation is either
                    //   - not found in file (so no "unrecognised" report)
                    //   - processed successfully (found in file and in code)
                    // but we don't know which.
                    let trouble = match (exc.in_example(which), exc.in_code, uncommented) {
                        (Absent, _, _) => return Ok(()), // not in file, no report expected
                        (_, _, false) => return Ok(()),  // not uncommented, no report expected
                        (_, Some(true), _) => return Ok(()), // code likes it, no report expected
                        (Present, Some(false), true) => {
                            "expected an 'unknown config key' report but didn't see one"
                        }
                        (Present, None, true) => return Ok(()), // not sure, have to just allow it
                    };
                    (&exc.key, trouble.into())
                }
            };
            Err((key.clone(), err))
        }

        let parses_to_defaults = |example: &str, which: WhichExample, uncommented: bool| {
            let cfg = {
                let mut sources = tor_config::ConfigurationSources::new_empty();
                sources.push_source(
                    tor_config::ConfigurationSource::from_verbatim(example.to_string()),
                    tor_config::sources::MustRead::MustRead,
                );
                sources.load().unwrap()
            };

            // This tests that the example settings do not *contradict* the defaults.
            let results: ResolutionResults<ArtiCombinedConfig> =
                tor_config::resolve_return_results(cfg).unwrap();

            assert_eq!(&results.value, &default, "{which:?} {uncommented:?}");
            assert_eq!(&results.value, &empty_config, "{which:?} {uncommented:?}");

            // We serialize the DisfavouredKey entries to strings to compare them against
            // `known_unrecognized_options`.
            let unrecognized = results
                .unrecognized
                .iter()
                .map(|k| k.to_string())
                .collect_vec();

            eprintln!(
                "parsing of {which:?} uncommented={uncommented:?}, unrecognized={unrecognized:#?}"
            );

            let reports =
                Itertools::merge_join_by(unrecognized.iter(), exceptions.iter(), |u, e| {
                    u.as_str().cmp(&e.key)
                })
                .filter_map(|eob| analyse_joined_info(which, uncommented, eob).err())
                .collect_vec();

            if !reports.is_empty() {
                let reports = reports.iter().fold(String::new(), |mut out, (k, s)| {
                    writeln!(out, "  {}: {}", s, k).unwrap();
                    out
                });

                panic!(
                    r"
mismatch: results of parsing example files (& vs declared exceptions):
example config file {which:?}, uncommented={uncommented:?}
{reports}
"
                );
            }

            results.value
        };

        let _ = parses_to_defaults(ARTI_EXAMPLE_CONFIG, WhichExample::New, false);
        let _ = parses_to_defaults(OLDEST_SUPPORTED_CONFIG, WhichExample::Old, false);

        let built_default = (
            ArtiConfigBuilder::default().build().unwrap(),
            TorClientConfigBuilder::default().build().unwrap(),
        );

        let parsed = parses_to_defaults(
            &uncomment_example_settings(ARTI_EXAMPLE_CONFIG),
            WhichExample::New,
            true,
        );
        let parsed_old = parses_to_defaults(
            &uncomment_example_settings(OLDEST_SUPPORTED_CONFIG),
            WhichExample::Old,
            true,
        );

        assert_eq!(&parsed, &built_default);
        assert_eq!(&parsed_old, &built_default);

        assert_eq!(&default, &built_default);
    }

    /// Config file exhaustiveness and default checking
    ///
    /// `example_file` is a putative configuration file text.
    /// It is expected to contain "example lines",
    /// which are lines in start with `#` *not followed by whitespace*.
    ///
    /// This function checks that:
    ///
    /// Positive check on the example lines that are present.
    ///  * `example_file`, when example lines are uncommented, can be parsed.
    ///  * The example values are the same as the default values.
    ///
    /// Check for missing examples:
    ///  * Every key `in `TorClientConfig` or `ArtiConfig` has a corresponding example value.
    ///  * Except as declared in [`declared_config_exceptions`]
    ///  * And also, tolerating absence in the example files of `deprecated` keys
    ///
    /// It handles straightforward cases, where the example line is in a `[section]`
    /// and is something like `#key = value`.
    ///
    /// More complex keys, eg those which don't appear in "example lines" starting with just `#`,
    /// must be dealt with ad-hoc and mentioned in `declared_config_exceptions`.
    ///
    /// For complex config keys, it may not be sufficient to simply write the default value in
    /// the example files (along with perhaps some other information).  In that case,
    ///   1. Write a bespoke example (with lines starting `# `) in the config file.
    ///   2. Write a bespoke test, to test the parsing of the bespoke example.
    ///      This will probably involve using `ExampleSectionLines` and may be quite ad-hoc.
    ///      The test function bridges(), below, is a complex worked example.
    ///   3. Either add a trivial example for the affected key(s) (starting with just `#`)
    ///      or add the affected key(s) to `declared_config_exceptions`
    fn exhaustive_1(example_file: &str, which: WhichExample, deprecated: &[String]) {
        use InExample::*;
        use serde_json::Value as JsValue;
        use std::collections::BTreeSet;

        let example = uncomment_example_settings(example_file);
        let example: toml::Value = toml::from_str(&example).unwrap();
        // dbg!(&example);
        let example = serde_json::to_value(example).unwrap();
        // dbg!(&example);

        // "Exhaustive" taxonomy of the recognized configuration keys
        //
        // We use the JSON serialization of the default builders, because Rust's toml
        // implementation likes to omit more things, that we want to see.
        //
        // I'm not sure this is quite perfect but it is pretty good,
        // and has found a number of un-exampled config keys.
        let exhausts = [
            serde_json::to_value(TorClientConfig::builder()).unwrap(),
            serde_json::to_value(ArtiConfig::builder()).unwrap(),
        ];

        /// This code does *not* record a problem for keys *in* the example file
        /// that are unrecognized.  That is handled by the `default_config` test.
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, derive_more::Display)]
        enum ProblemKind {
            #[display("recognised by serialisation, but missing from example config file")]
            MissingFromExample,
            #[display("expected that example config file should contain have this as a table")]
            ExpectedTableInExample,
            #[display(
                "declared exception says this key should be recognised but not in file, but that doesn't seem to be the case"
            )]
            UnusedException,
        }

        #[derive(Default, Debug)]
        struct Walk {
            current_path: Vec<String>,
            problems: Vec<(String, ProblemKind)>,
        }

        impl Walk {
            /// Records a problem
            fn bad(&mut self, kind: ProblemKind) {
                self.problems.push((self.current_path.join("."), kind));
            }

            /// Recurses, looking for problems
            ///
            /// Visited for every node in either or both of the starting `exhausts`.
            ///
            /// `E` is the number of elements in `exhausts`, ie the number of different
            /// top-level config types that Arti uses.  Ie, 2.
            fn walk<const E: usize>(
                &mut self,
                example: Option<&JsValue>,
                exhausts: [Option<&JsValue>; E],
            ) {
                assert! { exhausts.into_iter().any(|e| e.is_some()) }

                let example = if let Some(e) = example {
                    e
                } else {
                    self.bad(ProblemKind::MissingFromExample);
                    return;
                };

                let tables = exhausts.map(|e| e?.as_object());

                // Union of the keys of both exhausts' tables (insofar as they *are* tables)
                let table_keys = tables
                    .iter()
                    .flat_map(|t| t.map(|t| t.keys().cloned()).into_iter().flatten())
                    .collect::<BTreeSet<String>>();

                for key in table_keys {
                    let example = if let Some(e) = example.as_object() {
                        e
                    } else {
                        // At least one of the exhausts was a nonempty table,
                        // but the corresponding example node isn't a table.
                        self.bad(ProblemKind::ExpectedTableInExample);
                        continue;
                    };

                    // Descend the same key in all the places.
                    self.current_path.push(key.clone());
                    self.walk(example.get(&key), tables.map(|t| t?.get(&key)));
                    self.current_path.pop().unwrap();
                }
            }
        }

        let exhausts = exhausts.iter().map(Some).collect_vec().try_into().unwrap();

        let mut walk = Walk::default();
        walk.walk::<2>(Some(&example), exhausts);
        let mut problems = walk.problems;

        /// Marker present in `expect_missing` to say we *definitely* expect it
        #[derive(Debug, Copy, Clone)]
        struct DefinitelyRecognized;

        let expect_missing = declared_config_exceptions()
            .iter()
            .filter_map(|exc| {
                let definitely = match (exc.in_example(which), exc.in_code) {
                    (Present, _) => return None, // in file, don't expect "non-exhaustive" notice
                    (_, Some(false)) => return None, // code hasn't heard of it, likewise
                    (Absent, Some(true)) => Some(DefinitelyRecognized),
                    (Absent, None) => None, // allow this exception but don't mind if not known
                };
                Some((exc.key.clone(), definitely))
            })
            .collect_vec();
        dbg!(&expect_missing);

        // Things might appear in expect_missing for different reasons, and sometimes
        // at different levels.  For example, `bridges.transports` is expected to be
        // missing because we document that a different way in the example; but
        // `bridges` is expected to be missing from the OLDEST_SUPPORTED_CONFIG,
        // because that config predates bridge support.
        //
        // When this happens, we need to remove `bridges.transports` in favour of
        // the over-arching `bridges`.
        let expect_missing: Vec<(String, Option<DefinitelyRecognized>)> = expect_missing
            .iter()
            .cloned()
            .filter({
                let original: HashSet<_> = expect_missing.iter().map(|(k, _)| k.clone()).collect();
                move |(found, _)| {
                    !found
                        .match_indices('.')
                        .any(|(doti, _)| original.contains(&found[0..doti]))
                }
            })
            .collect_vec();
        dbg!(&expect_missing);

        for (exp, definitely) in expect_missing {
            let was = problems.len();
            problems.retain(|(path, _)| path != &exp);
            if problems.len() == was && definitely.is_some() {
                problems.push((exp, ProblemKind::UnusedException));
            }
        }

        let problems = problems
            .into_iter()
            .filter(|(key, _kind)| !deprecated.iter().any(|dep| key == dep))
            .map(|(path, m)| format!("    config key {:?}: {}", path, m))
            .collect_vec();

        // If this assert fails, it might be because in `fn exhaustive`, below,
        // a newly-defined config item has not been added to the list for OLDEST_SUPPORTED_CONFIG.
        assert!(
            problems.is_empty(),
            "example config {which:?} exhaustiveness check failed: {}\n-----8<-----\n{}\n-----8<-----\n",
            problems.join("\n"),
            example_file,
        );
    }

    #[test]
    fn exhaustive() {
        let mut deprecated = vec![];
        <(ArtiConfig, TorClientConfig) as tor_config::load::Resolvable>::enumerate_deprecated_keys(
            &mut |l| {
                for k in l {
                    deprecated.push(k.to_string());
                }
            },
        );
        let deprecated = deprecated.iter().cloned().collect_vec();

        // Check that:
        //  - The primary example config file has good examples for everything
        //  - Except for deprecated config keys
        //  - (And, except for those that we never expect: CONFIG_KEYS_EXPECT_NO_EXAMPLE.)
        exhaustive_1(ARTI_EXAMPLE_CONFIG, WhichExample::New, &deprecated);

        // Check that:
        //  - That oldest supported example config file has good examples for everything
        //  - Except for keys that we have introduced since that file was written
        //  - (And, except for those that we never expect: CONFIG_KEYS_EXPECT_NO_EXAMPLE.)
        // We *tolerate* entries in this table that don't actually occur in the oldest-supported
        // example.  This avoids having to feature-annotate them.
        exhaustive_1(OLDEST_SUPPORTED_CONFIG, WhichExample::Old, &deprecated);
    }

    /// Check that the `Report` of `err` contains the string `exp`, and otherwise panic
    #[cfg_attr(feature = "pt-client", allow(dead_code))]
    fn expect_err_contains(err: ConfigResolveError, exp: &str) {
        use std::error::Error as StdError;
        let err: Box<dyn StdError> = Box::new(err);
        let err = tor_error::Report(err).to_string();
        assert!(
            err.contains(exp),
            "wrong message, got {:?}, exp {:?}",
            err,
            exp,
        );
    }

    #[test]
    fn bridges() {
        // We make assumptions about the contents of `arti-example-config.toml` !
        //
        // 1. There are nontrivial, non-default examples of `bridges.bridges`.
        // 2. These are in the `[bridges]` section, after a line `# For example:`
        // 3. There's precisely one ``` example, with conventional TOML formatting.
        // 4. There's precisely one [ ] example, with conventional TOML formatting.
        // 5. Both these examples specify the same set of bridges.
        // 6. There are three bridges.
        // 7. Lines starting with a digit or `[` are direct bridges; others are PT.
        //
        // Below, we annotate with `[1]` etc. where these assumptions are made.

        // Filter examples that we don't want to test in this configuration
        let filter_examples = |#[allow(unused_mut)] mut examples: ExampleSectionLines| -> _ {
            // [7], filter out the PTs
            if cfg!(all(feature = "bridge-client", not(feature = "pt-client"))) {
                let looks_like_addr =
                    |l: &str| l.starts_with(|c: char| c.is_ascii_digit() || c == '[');
                examples.lines.retain(|l| looks_like_addr(l));
            }

            examples
        };

        // Tests that one example parses, and returns what it parsed.
        // If bridge support is completely disabled, checks that this configuration
        // is rejected, as it should be, and returns a dummy value `((),)`
        // (so that the rest of the test has something to "compare that we parsed it the same").
        let resolve_examples = |examples: &ExampleSectionLines| {
            // [7], check that the PT bridge is properly rejected
            #[cfg(all(feature = "bridge-client", not(feature = "pt-client")))]
            {
                let err = examples.resolve::<TorClientConfig>().unwrap_err();
                expect_err_contains(err, "support disabled in cargo features");
            }

            let examples = filter_examples(examples.clone());

            #[cfg(feature = "bridge-client")]
            {
                examples.resolve::<TorClientConfig>().unwrap()
            }

            #[cfg(not(feature = "bridge-client"))]
            {
                let err = examples.resolve::<TorClientConfig>().unwrap_err();
                expect_err_contains(err, "support disabled in cargo features");
                // Use ((),) as the dummy unit value because () gives clippy conniptions
                ((),)
            }
        };

        // [1], [2], narrow to just the nontrivial, non-default, examples
        let mut examples = ExampleSectionLines::from_section("bridges");
        examples.narrow((r#"^# For example:"#, true), NARROW_NONE);

        let compare = {
            // [3], narrow to the multi-line string
            let mut examples = examples.clone();
            examples.narrow((r#"^#  bridges = '''"#, true), (r#"^#  '''"#, true));
            examples.uncomment();

            let parsed = resolve_examples(&examples);

            // Now we fish out the lines ourselves as a double-check
            // We must strip off the bridges = ''' and ''' lines.
            examples.lines.remove(0);
            examples.lines.remove(examples.lines.len() - 1);
            // [6], check we got the number of examples we expected
            examples.expect_lines(3);

            // If we have the bridge API, try parsing each line and using the API to insert it
            #[cfg(feature = "bridge-client")]
            {
                let examples = filter_examples(examples);
                let mut built = TorClientConfig::builder();
                for l in &examples.lines {
                    built.bridges().bridges().push(l.trim().parse().expect(l));
                }
                let built = built.build().unwrap();

                assert_eq!(&parsed, &built);
            }

            parsed
        };

        // [4], [5], narrow to the [ ] section, parse again, and compare
        {
            examples.narrow((r#"^#  bridges = \["#, true), (r#"^#  \]"#, true));
            examples.uncomment();
            let parsed = resolve_examples(&examples);
            assert_eq!(&parsed, &compare);
        }
    }

    #[test]
    fn transports() {
        // Extract and uncomment our transports lines.
        //
        // (They're everything from  `# An example managed pluggable transport`
        // through the start of the next
        // section.  They start with "#    ".)
        let mut file =
            ExampleSectionLines::from_markers("# An example managed pluggable transport", "[");
        file.lines.retain(|line| line.starts_with("#    "));
        file.uncomment();

        let result = file.resolve::<(TorClientConfig, ArtiConfig)>();
        let cfg_got = result.unwrap();

        #[cfg(feature = "pt-client")]
        {
            use arti_client::config::{BridgesConfig, pt::TransportConfig};
            use tor_config_path::CfgPath;

            let bridges_got: &BridgesConfig = cfg_got.0.as_ref();

            // Build the expected configuration.
            let mut bld = BridgesConfig::builder();
            {
                let mut b = TransportConfig::builder();
                b.protocols(vec!["obfs4".parse().unwrap(), "obfs5".parse().unwrap()]);
                b.path(CfgPath::new("/usr/bin/obfsproxy".to_string()));
                b.arguments(vec!["-obfs4".to_string(), "-obfs5".to_string()]);
                b.run_on_startup(true);
                bld.transports().push(b);
            }
            {
                let mut b = TransportConfig::builder();
                b.protocols(vec!["obfs4".parse().unwrap()]);
                b.proxy_addr("127.0.0.1:31337".parse().unwrap());
                bld.transports().push(b);
            }

            let bridges_expected = bld.build().unwrap();
            assert_eq!(&bridges_expected, bridges_got);
        }
    }

    #[test]
    fn memquota() {
        // Test that uncommenting the example generates a config
        // with tracking enabled, iff support is compiled in.
        let mut file = ExampleSectionLines::from_section("system");
        file.lines.retain(|line| line.starts_with("#    memory."));
        file.uncomment();

        let result = file.resolve_return_results::<(TorClientConfig, ArtiConfig)>();

        let result = result.unwrap();

        // Test that the example config doesn't have any unrecognised keys
        assert_eq!(result.unrecognized, []);
        assert_eq!(result.deprecated, []);

        let inner: &tor_memquota::testing::ConfigInner =
            result.value.0.system_memory().inner().unwrap();

        // Test that the example low_water is the default
        // value for the example max.
        let defaulted_low = tor_memquota::Config::builder()
            .max(*inner.max)
            .build()
            .unwrap();
        let inner_defaulted_low = defaulted_low.inner().unwrap();
        assert_eq!(inner, inner_defaulted_low);
    }

    #[test]
    fn metrics() {
        // Test that uncommenting the example generates a config with prometheus enabled.
        let mut file = ExampleSectionLines::from_section("metrics");
        file.lines
            .retain(|line| line.starts_with("#    prometheus."));
        file.uncomment();

        let result = file
            .resolve_return_results::<(TorClientConfig, ArtiConfig)>()
            .unwrap();

        // Test that the example config doesn't have any unrecognised keys
        assert_eq!(result.unrecognized, []);
        assert_eq!(result.deprecated, []);

        // Check that the example is as we expected
        assert_eq!(
            result
                .value
                .1
                .metrics
                .prometheus
                .listen
                .single_address_legacy()
                .unwrap(),
            Some("127.0.0.1:9035".parse().unwrap()),
        );

        // We don't test "compiled out but not used" here.
        // That case is handled in proxy.rs at startup time.
    }

    #[test]
    fn onion_services() {
        // Here we require that the onion services configuration is between a line labeled
        // with `##### ONION SERVICES` and a line labeled with `##### RPC`, and that each
        // line of _real_ configuration in that section begins with `#    `.
        let mut file = ExampleSectionLines::from_markers("##### ONION SERVICES", "##### RPC");
        file.lines.retain(|line| line.starts_with("#    "));
        file.uncomment();

        let result = file.resolve::<(TorClientConfig, ArtiConfig)>();
        #[cfg(feature = "onion-service-service")]
        {
            let svc_expected = {
                use tor_hsrproxy::config::*;
                let mut b = OnionServiceProxyConfigBuilder::default();
                b.service().nickname("allium-cepa".parse().unwrap());
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::one_port(80).unwrap(),
                    ProxyAction::Forward(
                        Encapsulation::Simple,
                        TargetAddr::Inet("127.0.0.1:10080".parse().unwrap()),
                    ),
                ));
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::one_port(22).unwrap(),
                    ProxyAction::DestroyCircuit,
                ));
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::one_port(265).unwrap(),
                    ProxyAction::IgnoreStream,
                ));
                /* TODO (#1246)
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::port_range(1, 1024).unwrap(),
                    ProxyAction::Forward(
                        Encapsulation::Simple,
                        TargetAddr::Unix("/var/run/allium-cepa/socket".into()),
                    ),
                ));
                */
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::one_port(443).unwrap(),
                    ProxyAction::RejectStream,
                ));
                b.proxy().proxy_ports().push(ProxyRule::new(
                    ProxyPattern::all_ports(),
                    ProxyAction::DestroyCircuit,
                ));

                #[cfg(feature = "restricted-discovery")]
                {
                    const ALICE_KEY: &str =
                        "descriptor:x25519:PU63REQUH4PP464E2Y7AVQ35HBB5DXDH5XEUVUNP3KCPNOXZGIBA";
                    const BOB_KEY: &str =
                        "descriptor:x25519:b5zqgtpermmuda6vc63lhjuf5ihpokjmuk26ly2xksf7vg52aesq";
                    for (nickname, key) in [("alice", ALICE_KEY), ("bob", BOB_KEY)] {
                        b.service()
                            .restricted_discovery()
                            .enabled(true)
                            .static_keys()
                            .access()
                            .push((
                                HsClientNickname::from_str(nickname).unwrap(),
                                HsClientDescEncKey::from_str(key).unwrap(),
                            ));
                    }
                    let mut dir = DirectoryKeyProviderBuilder::default();
                    dir.path(CfgPath::new(
                        "/var/lib/tor/hidden_service/authorized_clients".to_string(),
                    ));

                    b.service()
                        .restricted_discovery()
                        .key_dirs()
                        .access()
                        .push(dir);
                }

                b.build().unwrap()
            };

            cfg_if::cfg_if! {
                if #[cfg(feature = "restricted-discovery")] {
                    let cfg = result.unwrap();
                    let services = cfg.1.onion_services;
                    assert_eq!(services.len(), 1);
                    let svc = services.values().next().unwrap();
                    assert_eq!(svc, &svc_expected);
                } else {
                    expect_err_contains(
                        result.unwrap_err(),
                        "restricted_discovery.enabled=true, but restricted-discovery feature not enabled"
                    );
                }
            }
        }
        #[cfg(not(feature = "onion-service-service"))]
        {
            expect_err_contains(result.unwrap_err(), "no support for running onion services");
        }
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn rpc_defaults() {
        let mut file = ExampleSectionLines::from_markers("##### RPC", "[");
        // This will get us all the RPC entries that correspond to our defaults.
        //
        // The examples that _aren't_ in our defaults have '#      ' at the start.
        file.lines
            .retain(|line| line.starts_with("#    ") && !line.starts_with("#      "));
        file.uncomment();

        let parsed = file
            .resolve_return_results::<(TorClientConfig, ArtiConfig)>()
            .unwrap();
        assert!(parsed.unrecognized.is_empty());
        assert!(parsed.deprecated.is_empty());
        let rpc_parsed: &RpcConfig = parsed.value.1.rpc();
        let rpc_default = RpcConfig::default();
        assert_eq!(rpc_parsed, &rpc_default);
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn rpc_full() {
        use crate::rpc::listener::{ConnectPointOptionsBuilder, RpcListenerSetConfigBuilder};

        // This will get us all the RPC entries, including those that _don't_ correspond to our defaults.
        let mut file = ExampleSectionLines::from_markers("##### RPC", "[");
        // We skip the "file" item because it conflicts with "dir" and "file_options"
        file.lines
            .retain(|line| line.starts_with("#    ") && !line.contains("file ="));
        file.uncomment();

        let parsed = file
            .resolve_return_results::<(TorClientConfig, ArtiConfig)>()
            .unwrap();
        let rpc_parsed: &RpcConfig = parsed.value.1.rpc();

        let expected = {
            let mut bld_opts = ConnectPointOptionsBuilder::default();
            bld_opts.enable(false);

            let mut bld_set = RpcListenerSetConfigBuilder::default();
            bld_set.dir(CfgPath::new("${HOME}/.my_connect_files/".to_string()));
            bld_set.listener_options().enable(true);
            bld_set
                .file_options()
                .insert("bad_file.json".to_string(), bld_opts);

            let mut bld = RpcConfigBuilder::default();
            bld.listen().insert("label".to_string(), bld_set);
            bld.build().unwrap()
        };

        assert_eq!(&expected, rpc_parsed);
    }

    /// Helper for fishing out parts of the config file and uncommenting them.
    ///
    /// It represents a part of a configuration file.
    ///
    /// This can be used to find part of the config file by ad-hoc regexp matching,
    /// uncomment it, and parse it.  This is useful as part of a test to check
    /// that we can parse more complex config.
    #[derive(Debug, Clone)]
    struct ExampleSectionLines {
        /// The header for the section that we are parsing.  It is
        /// prepended to the lines before parsing them.
        section: String,
        /// The lines in the section.
        lines: Vec<String>,
    }

    /// A 2-tuple of a regular expression and a flag describing whether the line
    /// containing the expression should be included in the result of `narrow()`.
    type NarrowInstruction<'s> = (&'s str, bool);
    /// A NarrowInstruction that does not match anything.
    const NARROW_NONE: NarrowInstruction<'static> = ("?<none>", false);

    impl ExampleSectionLines {
        /// Construct a new `ExampleSectionLines` from `ARTI_EXAMPLE_CONFIG`, containing
        /// everything that starts with `[section]`, up to but not including the
        /// next line that begins with a `[`.
        fn from_section(section: &str) -> Self {
            Self::from_markers(format!("[{section}]"), "[")
        }

        /// Construct a new `ExampleSectionLines` from `ARTI_EXAMPLE_CONFIG`,
        /// containing everything that starts with `start`, up to but not
        /// including the next line that begins with `end`.
        ///
        /// If `start` is a configuration section header it will be put in the
        /// `section` field of the returned `ExampleSectionLines`, otherwise
        /// at the beginning of the `lines` field.
        ///
        /// `start` will be perceived as a configuration section header if it
        /// starts with `[` and ends with `]`.
        fn from_markers<S, E>(start: S, end: E) -> Self
        where
            S: AsRef<str>,
            E: AsRef<str>,
        {
            let (start, end) = (start.as_ref(), end.as_ref());
            let mut lines = ARTI_EXAMPLE_CONFIG
                .lines()
                .skip_while(|line| !line.starts_with(start))
                .peekable();
            let section = lines
                .next_if(|l0| l0.starts_with('['))
                .map(|section| section.to_owned())
                .unwrap_or_default();
            let lines = lines
                .take_while(|line| !line.starts_with(end))
                .map(|l| l.to_owned())
                .collect_vec();

            Self { section, lines }
        }

        /// Remove all lines from this section, except those between the (unique) line matching
        /// "start" and the next line matching "end" (or the end of the file).
        fn narrow(&mut self, start: NarrowInstruction, end: NarrowInstruction) {
            let find_index = |(re, include), start_pos, exactly_one: bool, adjust: [isize; 2]| {
                if (re, include) == NARROW_NONE {
                    return None;
                }

                let re = Regex::new(re).expect(re);
                let i = self
                    .lines
                    .iter()
                    .enumerate()
                    .skip(start_pos)
                    .filter(|(_, l)| re.is_match(l))
                    .map(|(i, _)| i);
                let i = if exactly_one {
                    i.clone().exactly_one().unwrap_or_else(|_| {
                        panic!("RE={:?} I={:#?} L={:#?}", re, i.collect_vec(), &self.lines)
                    })
                } else {
                    i.clone().next()?
                };

                let adjust = adjust[usize::from(include)];
                let i = (i as isize + adjust) as usize;
                Some(i)
            };

            eprint!("narrow {:?} {:?}: ", start, end);
            let start = find_index(start, 0, true, [1, 0]).unwrap_or(0);
            let end = find_index(end, start + 1, false, [0, 1]).unwrap_or(self.lines.len());
            eprintln!("{:?} {:?}", start, end);
            // don't tolerate empty
            assert!(start < end, "empty, from {:#?}", &self.lines);
            self.lines = self.lines.drain(..).take(end).skip(start).collect_vec();
        }

        /// Assert that this section contains exactly `n` lines.
        fn expect_lines(&self, n: usize) {
            assert_eq!(self.lines.len(), n);
        }

        /// Remove `#` from the start of every line that begins with it.
        fn uncomment(&mut self) {
            self.strip_prefix("#");
        }

        /// Remove `prefix` from the start of every line.
        ///
        /// If there are lines that *don't* start with `prefix`, crash.
        ///
        /// But, lines starting with `[` are left unchanged, in any case.
        /// (These are TOML section markers; changing them would change the TOML structure.)
        fn strip_prefix(&mut self, prefix: &str) {
            for l in &mut self.lines {
                if !l.starts_with('[') {
                    *l = l.strip_prefix(prefix).expect(l).to_string();
                }
            }
        }

        /// Join the parts of this object together into a single string.
        fn build_string(&self) -> String {
            chain!(iter::once(&self.section), self.lines.iter(),).join("\n")
        }

        /// Make a TOML document of this section and parse it as a complete configuration.
        /// Panic if the section cannot be parsed.
        fn parse(&self) -> tor_config::ConfigurationTree {
            let s = self.build_string();
            eprintln!("parsing\n  --\n{}\n  --", &s);
            let mut sources = tor_config::ConfigurationSources::new_empty();
            sources.push_source(
                tor_config::ConfigurationSource::from_verbatim(s.clone()),
                tor_config::sources::MustRead::MustRead,
            );
            sources.load().expect(&s)
        }

        fn resolve<R: tor_config::load::Resolvable>(&self) -> Result<R, ConfigResolveError> {
            tor_config::load::resolve(self.parse())
        }

        fn resolve_return_results<R: tor_config::load::Resolvable>(
            &self,
        ) -> Result<ResolutionResults<R>, ConfigResolveError> {
            tor_config::load::resolve_return_results(self.parse())
        }
    }

    // More normal config tests

    #[test]
    fn builder() {
        use tor_config_path::CfgPath;
        let sec = std::time::Duration::from_secs(1);

        let mut authorities = dir::AuthorityContacts::builder();
        authorities.v3idents().push([22; 20].into());

        let mut fallback = dir::FallbackDir::builder();
        fallback
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports()
            .push("127.0.0.7:7".parse().unwrap());

        let mut bld = ArtiConfig::builder();
        let mut bld_tor = TorClientConfig::builder();

        bld.proxy().socks_listen(Listen::new_localhost(9999));
        bld.logging().console("warn");

        *bld_tor.tor_network().authorities() = authorities;
        bld_tor.tor_network().set_fallback_caches(vec![fallback]);
        bld_tor
            .storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld_tor.download_schedule().retry_certs().attempts(10);
        bld_tor.download_schedule().retry_certs().initial_delay(sec);
        bld_tor.download_schedule().retry_certs().parallelism(3);
        bld_tor.download_schedule().retry_microdescs().attempts(30);
        bld_tor
            .download_schedule()
            .retry_microdescs()
            .initial_delay(10 * sec);
        bld_tor
            .download_schedule()
            .retry_microdescs()
            .parallelism(9);
        bld_tor
            .override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld_tor
            .path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld_tor.preemptive_circuits().disable_at_threshold(12);
        bld_tor
            .preemptive_circuits()
            .set_initial_predicted_ports(vec![80, 443]);
        bld_tor
            .preemptive_circuits()
            .prediction_lifetime(Duration::from_secs(3600))
            .min_exit_circs_for_port(2);
        bld_tor
            .circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld_tor.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        assert_ne!(val, ArtiConfig::default());
    }

    #[test]
    fn articonfig_application() {
        let config = ArtiConfig::default();

        let application = config.application();
        assert_eq!(&config.application, application);
    }

    #[test]
    fn articonfig_logging() {
        let config = ArtiConfig::default();

        let logging = config.logging();
        assert_eq!(&config.logging, logging);
    }

    #[test]
    fn articonfig_proxy() {
        let config = ArtiConfig::default();

        let proxy = config.proxy();
        assert_eq!(&config.proxy, proxy);
    }

    /// Comprehensive tests for `proxy.socks_listen` and `proxy.dns_listen`.
    ///
    /// The "this isn't set at all, just use the default" cases are tested elsewhere.
    fn ports_listen(
        f: &str,
        get_listen: &dyn Fn(&ArtiConfig) -> &Listen,
        bld_get_listen: &dyn Fn(&ArtiConfigBuilder) -> &Option<Listen>,
        setter_listen: &dyn Fn(&mut ArtiConfigBuilder, Listen) -> &mut ProxyConfigBuilder,
    ) {
        let from_toml = |s: &str| -> ArtiConfigBuilder {
            let cfg: toml::Value = toml::from_str(dbg!(s)).unwrap();
            let cfg: ArtiConfigBuilder = cfg.try_into().unwrap();
            cfg
        };

        let chk = |cfg: &ArtiConfigBuilder, expected: &Listen| {
            dbg!(bld_get_listen(cfg));
            let cfg = cfg.build().unwrap();
            assert_eq!(get_listen(&cfg), expected);
        };

        let check_setters = |port, expected: &_| {
            let cfg = ArtiConfig::builder();
            for listen in match port {
                None => vec![Listen::new_none(), Listen::new_localhost(0)],
                Some(port) => vec![Listen::new_localhost(port)],
            } {
                let mut cfg = cfg.clone();
                setter_listen(&mut cfg, dbg!(listen));
                chk(&cfg, expected);
            }
        };

        {
            let expected = Listen::new_localhost(100);

            let cfg = from_toml(&format!("proxy.{}_listen = 100", f));
            assert_eq!(bld_get_listen(&cfg), &Some(Listen::new_localhost(100)));
            chk(&cfg, &expected);

            check_setters(Some(100), &expected);
        }

        {
            let expected = Listen::new_none();

            let cfg = from_toml(&format!("proxy.{}_listen = 0", f));
            chk(&cfg, &expected);

            check_setters(None, &expected);
        }
    }

    #[test]
    fn ports_listen_socks() {
        ports_listen(
            "socks",
            &|cfg| &cfg.proxy.socks_listen,
            &|bld| &bld.proxy.socks_listen,
            &|bld, arg| bld.proxy.socks_listen(arg),
        );
    }

    #[test]
    fn ports_listen_dns() {
        ports_listen(
            "dns",
            &|cfg| &cfg.proxy.dns_listen,
            &|bld| &bld.proxy.dns_listen,
            &|bld, arg| bld.proxy.dns_listen(arg),
        );
    }
}
