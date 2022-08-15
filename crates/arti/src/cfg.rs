//! Configuration for the Arti command line application
//
// (Thia module is called `cfg` to avoid name clash with the `config` crate, which we use.)

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use arti_client::TorClientConfig;
use tor_config::{impl_standard_builder, ConfigBuildError};

use crate::{LoggingConfig, LoggingConfigBuilder};

/// Default options to use for our configuration.
pub const ARTI_EXAMPLE_CONFIG: &str = concat!(include_str!("./arti-example-config.toml"),);

/// Structure to hold our application configuration options
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ApplicationConfig {
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
}
impl_standard_builder! { ApplicationConfig }

/// Configuration for one or more proxy listeners.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ProxyConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    #[builder(field(build = r#"tor_config::resolve_option(&self.socks_port, || Some(9150))"#))]
    pub(crate) socks_port: Option<u16>,
    /// Port to lisen on (at localhost) for incoming DNS connections.
    #[builder(field(build = r#"tor_config::resolve_option(&self.dns_port, || None)"#))]
    pub(crate) dns_port: Option<u16>,
}
impl_standard_builder! { ProxyConfig }

/// Configuration for system resources used by Tor.
///
/// You cannot change this section on a running Arti client.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct SystemConfig {
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
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct ArtiConfig {
    /// Configuration for application behavior.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    application: ApplicationConfig,

    /// Configuration for proxy listeners
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    proxy: ProxyConfig,

    /// Logging configuration
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    logging: LoggingConfig,

    /// Information on system resources used by Arti.
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) system: SystemConfig,
}
impl_standard_builder! { ArtiConfig }

impl tor_config::load::TopLevel for ArtiConfig {
    type Builder = ArtiConfigBuilder;
}

/// Convenience alias for the config for a whole `arti` program
///
/// Used primarily as a type parameter on calls to [`tor_config::resolve`]
pub type ArtiCombinedConfig = (ArtiConfig, TorClientConfig);

impl ArtiConfig {
    /// Return the [`ApplicationConfig`] for this configuration.
    pub fn application(&self) -> &ApplicationConfig {
        &self.application
    }

    /// Return the [`LoggingConfig`] for this configuration.
    pub fn logging(&self) -> &LoggingConfig {
        &self.logging
    }

    /// Return the [`ProxyConfig`] for this configuration.
    pub fn proxy(&self) -> &ProxyConfig {
        &self.proxy
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use arti_client::config::dir;
    use arti_client::config::TorClientConfigBuilder;
    use regex::Regex;
    use std::time::Duration;

    use super::*;

    fn uncomment_example_settings(template: &str) -> String {
        let re = Regex::new(r#"(?m)^\#([^ \n])"#).unwrap();
        re.replace_all(template, |cap: &regex::Captures<'_>| -> _ {
            cap.get(1).unwrap().as_str().to_string()
        })
        .into()
    }

    #[test]
    fn default_config() {
        let empty_config = config::Config::builder().build().unwrap();
        let empty_config: ArtiCombinedConfig = tor_config::resolve(empty_config).unwrap();

        let default = (ArtiConfig::default(), TorClientConfig::default());

        let parses_to_defaults = |example: &str| {
            let cfg = config::Config::builder()
                .add_source(config::File::from_str(example, config::FileFormat::Toml))
                .build()
                .unwrap();

            // This tests that the example settings do not *contradict* the defaults.
            //
            // Also we should ideally test that every setting from the config appears here in
            // the file.  Possibly that could be done with some kind of stunt Deserializer,
            // but it's not trivial.
            let (parsed, unrecognized): (ArtiCombinedConfig, _) =
                tor_config::resolve_return_unrecognized(cfg).unwrap();

            assert_eq!(&parsed, &default);
            assert_eq!(&parsed, &empty_config);

            assert_eq!(unrecognized, &[]);
            parsed
        };

        let _ = parses_to_defaults(ARTI_EXAMPLE_CONFIG);

        let example = uncomment_example_settings(ARTI_EXAMPLE_CONFIG);
        let parsed = parses_to_defaults(&example);

        let built_default = (
            ArtiConfigBuilder::default().build().unwrap(),
            TorClientConfigBuilder::default().build().unwrap(),
        );
        assert_eq!(&parsed, &built_default);
        assert_eq!(&default, &built_default);
    }

    #[test]
    fn builder() {
        use tor_config::CfgPath;
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

        let mut bld = ArtiConfig::builder();
        let mut bld_tor = TorClientConfig::builder();

        bld.proxy().socks_port(Some(9999));
        bld.logging().console("warn");

        bld_tor.tor_network().set_authorities(vec![auth]);
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

    #[test]
    fn exhaustive() {
        use itertools::Itertools;
        use serde_json::Value as JsValue;
        use std::collections::BTreeSet;

        let example = uncomment_example_settings(ARTI_EXAMPLE_CONFIG);
        let example: toml::Value = toml::from_str(&example).unwrap();
        // dbg!(&example);
        let example = serde_json::to_value(&example).unwrap();
        // dbg!(&example);

        // "Exhaustive" taxonomy of the recognised configuration keys
        //
        // We use the JSON serialization of the default builders, because Rust's toml
        // implementation likes to omit more things, that we want to see.
        //
        // I'm not sure this is quite perfect but it is pretty good,
        // and has found a number of un-exampled config keys.
        let exhausts = [
            serde_json::to_value(&TorClientConfig::builder()).unwrap(),
            serde_json::to_value(&ArtiConfig::builder()).unwrap(),
        ];

        #[derive(Default, Debug)]
        struct Walk {
            current_path: Vec<String>,
            problems: Vec<(String, String)>,
        }

        impl Walk {
            /// Records a problem
            fn bad(&mut self, m: &str) {
                self.problems
                    .push((self.current_path.join("."), m.to_string()));
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
                    self.bad("missing from example");
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
                        self.bad("expected table in example");
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

        // When adding things here, check that `arti-example-config.toml`
        // actually has something about these particular config keys.
        let expect_missing = ["tor_network.authorities", "tor_network.fallback_caches"];

        for exp in expect_missing {
            let was = problems.len();
            problems.retain(|(path, _)| path != exp);
            if problems.len() == was {
                problems.push((
                    exp.into(),
                    "expected to be missing but found in default".into(),
                ));
            }
        }

        let problems = problems
            .into_iter()
            .map(|(path, m)| format!("    config key {:?}: {}", path, m))
            .collect_vec();

        assert! { problems.is_empty(),
        "example config exhaustiveness check failed:\n{}\n",
        problems.join("\n")}
    }
}
