//! Configuration for the Arti command line application
//
// (Thia module is called `cfg` to avoid name clash with the `config` crate, which we use.)

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use arti_client::config::TorClientConfigBuilder;
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
}
impl_standard_builder! { ApplicationConfig }

/// Configuration for one or more proxy listeners.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ProxyConfig {
    /// Port to listen on (at localhost) for incoming SOCKS
    /// connections.
    #[serde(default = "default_socks_port")]
    #[builder(default = "default_socks_port()")]
    pub(crate) socks_port: Option<u16>,
    /// Port to lisen on (at localhost) for incoming DNS connections.
    #[serde(default)]
    #[builder(default)]
    pub(crate) dns_port: Option<u16>,
}
impl_standard_builder! { ProxyConfig }

/// Return the default value for `socks_port`
#[allow(clippy::unnecessary_wraps)]
fn default_socks_port() -> Option<u16> {
    Some(9150)
}

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

    /// Configuration of the actual Tor client
    #[builder(sub_builder)]
    #[builder_field_attr(serde(flatten))]
    pub(crate) tor: TorClientConfig,
}
impl_standard_builder! { ArtiConfig }

impl TryFrom<config::Config> for ArtiConfig {
    type Error = config::ConfigError;
    fn try_from(cfg: config::Config) -> Result<ArtiConfig, Self::Error> {
        let builder: ArtiConfigBuilder = cfg.try_deserialize()?;
        builder
            .build()
            .map_err(|e| config::ConfigError::Foreign(Box::new(e)))
    }
}

// This handwritten impl ought not to exist, but it is needed until #374 is done.
impl From<ArtiConfigBuilder> for TorClientConfigBuilder {
    fn from(cfg: ArtiConfigBuilder) -> TorClientConfigBuilder {
        cfg.tor
    }
}

impl ArtiConfig {
    /// Construct a [`TorClientConfig`] based on this configuration.
    pub fn tor_client_config(&self) -> Result<TorClientConfig, ConfigBuildError> {
        Ok(self.tor.clone())
    }

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
    use regex::Regex;
    use std::time::Duration;

    use super::*;

    fn uncomment_example_settings(template: &str) -> String {
        let re = Regex::new(r#"(?m)^\#([^ \n])"#).unwrap();
        re.replace(template, |cap: &regex::Captures<'_>| -> _ {
            cap.get(1).unwrap().as_str().to_string()
        })
        .into()
    }

    #[test]
    fn default_config() {
        let empty_config = config::Config::builder().build().unwrap();
        let empty_config: ArtiConfig = empty_config.try_into().unwrap();

        let example = uncomment_example_settings(ARTI_EXAMPLE_CONFIG);
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(&example, config::FileFormat::Toml))
            .build()
            .unwrap();

        // This tests that the example settings do not *contradict* the defaults.
        // But it does not prove that the example template file does not contain misspelled
        // (and therefore ignored) items - which might even contradict the defaults if
        // their spelling was changed.
        //
        // Really we should test that too, but that's dependent on a fix for
        //  https://gitlab.torproject.org/tpo/core/arti/-/issues/417
        // which is blocked on serde-ignored not handling serde(flatten).
        //
        // Also we should ideally test that every setting from the config appears here in
        // the file.  Possibly that could be done with some kind of stunt Deserializer,
        // but it's not trivial.
        let parsed: ArtiConfig = cfg.try_into().unwrap();
        let default = ArtiConfig::default();
        assert_eq!(&parsed, &default);
        assert_eq!(&parsed, &empty_config);

        let built_default = ArtiConfigBuilder::default().build().unwrap();
        assert_eq!(&parsed, &built_default);
        assert_eq!(&default, &built_default);

        // Make sure that the client configuration this gives us is the default one.
        let client_config = parsed.tor_client_config().unwrap();
        let dflt_client_config = TorClientConfig::default();
        assert_eq!(&client_config, &dflt_client_config);
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
        bld.proxy().socks_port(Some(9999));
        bld.logging().console("warn");
        bld.tor().tor_network().set_authorities(vec![auth]);
        bld.tor().tor_network().set_fallback_caches(vec![fallback]);
        bld.tor()
            .storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.tor().download_schedule().retry_certs().attempts(10);
        bld.tor()
            .download_schedule()
            .retry_certs()
            .initial_delay(sec);
        bld.tor().download_schedule().retry_certs().parallelism(3);
        bld.tor()
            .download_schedule()
            .retry_microdescs()
            .attempts(30);
        bld.tor()
            .download_schedule()
            .retry_microdescs()
            .initial_delay(10 * sec);
        bld.tor()
            .download_schedule()
            .retry_microdescs()
            .parallelism(9);
        bld.tor()
            .override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.tor()
            .path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.tor().preemptive_circuits().disable_at_threshold(12);
        bld.tor()
            .preemptive_circuits()
            .set_initial_predicted_ports(vec![80, 443]);
        bld.tor()
            .preemptive_circuits()
            .prediction_lifetime(Duration::from_secs(3600))
            .min_exit_circs_for_port(2);
        bld.tor()
            .circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.tor().address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        assert_ne!(val, ArtiConfig::default());
    }
}
