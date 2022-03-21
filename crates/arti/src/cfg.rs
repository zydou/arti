//! Configuration for the Arti command line application
//
// (Thia module is called `cfg` to avoid name clash with the `config` crate, which we use.)

use std::convert::TryFrom;

use derive_builder::Builder;
use serde::Deserialize;

use arti_client::config::{SystemConfig, SystemConfigBuilder, TorClientConfigBuilder};
use arti_client::TorClientConfig;
use tor_config::ConfigBuildError;

use crate::{LoggingConfig, LoggingConfigBuilder};

/// Structure to hold our application configuration options
#[derive(Deserialize, Debug, Default, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
pub struct ApplicationConfig {
    /// If true, we should watch our configuration files for changes, and reload
    /// our configuration when they change.
    ///
    /// Note that this feature may behave in unexpected ways if the path to the
    /// directory holding our configuration files changes its identity (because
    /// an intermediate symlink is changed, because the directory is removed and
    /// recreated, or for some other reason).
    #[serde(default)]
    #[builder(default)]
    pub(crate) watch_configuration: bool,
}

/// Configuration for one or more proxy listeners.
#[derive(Deserialize, Debug, Clone, Builder, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Deserialize))]
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

/// Return the default value for `socks_port`
#[allow(clippy::unnecessary_wraps)]
fn default_socks_port() -> Option<u16> {
    Some(9150)
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::builder().build().expect("Default builder failed")
    }
}

impl ProxyConfig {
    /// Return a new [`ProxyConfigBuilder`].
    pub fn builder() -> ProxyConfigBuilder {
        ProxyConfigBuilder::default()
    }
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
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ArtiConfig {
    /// Configuration for application behavior.
    application: ApplicationConfig,

    /// Configuration for proxy listeners
    proxy: ProxyConfig,

    /// Logging configuration
    logging: LoggingConfig,

    /// Information on system resources used by Arti.
    system: SystemConfig,

    /// Configuration of the actual Tor client
    tor: TorClientConfig,
}

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

    /// Return a new ArtiConfigBuilder.
    pub fn builder() -> ArtiConfigBuilder {
        ArtiConfigBuilder::default()
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

/// Builder object used to construct an ArtiConfig.
///
/// Most code won't need this, and should use [`TorClientConfigBuilder`] instead.
///
/// Unlike other builder types in Arti, this builder works by exposing an
/// inner builder for each section in the [`TorClientConfig`].
#[derive(Default, Clone, Deserialize)]
// This ought to be replaced by a derive-builder generated struct (probably as part of #374),
// but currently derive-builder can't do this.
pub struct ArtiConfigBuilder {
    /// Builder for the actual Tor client.
    #[serde(flatten)]
    tor: TorClientConfigBuilder,

    /// Builder for the application section
    #[serde(default)]
    application: ApplicationConfigBuilder,
    /// Builder for the proxy section.
    #[serde(default)]
    proxy: ProxyConfigBuilder,
    /// Builder for the logging section.
    #[serde(default)]
    logging: LoggingConfigBuilder,
    /// Builder for system resource configuration.
    #[serde(default)]
    system: SystemConfigBuilder,
}

impl ArtiConfigBuilder {
    /// Try to construct a new [`ArtiConfig`] from this builder.
    pub fn build(&self) -> Result<ArtiConfig, ConfigBuildError> {
        let application = self
            .application
            .build()
            .map_err(|e| e.within("application"))?;
        let proxy = self.proxy.build().map_err(|e| e.within("proxy"))?;
        let logging = self.logging.build().map_err(|e| e.within("logging"))?;
        let system = self.system.build().map_err(|e| e.within("system"))?;
        let tor = TorClientConfigBuilder::from(self.clone());
        let tor = tor.build()?;
        Ok(ArtiConfig {
            application,
            proxy,
            logging,
            system,
            tor,
        })
    }

    /// Return a mutable reference to an [`ApplicationConfigBuilder`] to use in
    /// configuring the Arti process.
    pub fn application(&mut self) -> &mut ApplicationConfigBuilder {
        &mut self.application
    }

    /// Return a mutable reference to a [`ProxyConfig`] to use in
    /// configuring the Arti process.
    pub fn proxy(&mut self) -> &mut ProxyConfigBuilder {
        &mut self.proxy
    }

    /// Return a mutable reference to a
    /// [`LoggingConfigBuilder`]
    /// to use in configuring the Arti process.
    pub fn logging(&mut self) -> &mut LoggingConfigBuilder {
        &mut self.logging
    }

    /// Return a mutable reference to a `TorClientConfigBuilder`.
    /// to use in configuring the underlying Tor network.
    ///
    /// Most programs shouldn't need to alter this configuration: it's only for
    /// cases when you need to use a nonstandard set of Tor directory authorities
    /// and fallback caches.
    pub fn tor(&mut self) -> &mut TorClientConfigBuilder {
        &mut self.tor
    }

    /// Return a mutable reference to a [`SystemConfigBuilder`].
    ///
    /// This section controls the system parameters used by Arti.
    pub fn system(&mut self) -> &mut SystemConfigBuilder {
        &mut self.system
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use arti_client::config::dir;
    use arti_config::ARTI_DEFAULTS;
    use std::convert::TryInto;
    use std::time::Duration;

    use super::*;

    #[test]
    fn default_config() {
        // TODO: this is duplicate code.
        let cfg = config::Config::builder()
            .add_source(config::File::from_str(
                ARTI_DEFAULTS,
                config::FileFormat::Toml,
            ))
            .build()
            .unwrap();

        let parsed: ArtiConfig = cfg.try_into().unwrap();
        let default = ArtiConfig::default();
        assert_eq!(&parsed, &default);

        // Make sure that the client configuration this gives us is the default one.
        let client_config = parsed.tor_client_config().unwrap();
        let dflt_client_config = TorClientConfig::default();
        assert_eq!(&client_config, &dflt_client_config);
    }

    #[test]
    fn builder() {
        use arti_client::config::dir::DownloadSchedule;
        use tor_config::CfgPath;
        let sec = std::time::Duration::from_secs(1);

        let auth = dir::Authority::builder()
            .name("Fred")
            .v3ident([22; 20].into())
            .build()
            .unwrap();
        let fallback = dir::FallbackDir::builder()
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports(vec!["127.0.0.7:7".parse().unwrap()])
            .build()
            .unwrap();

        let mut bld = ArtiConfig::builder();
        bld.proxy().socks_port(Some(9999));
        bld.logging().console("warn");
        bld.tor()
            .tor_network()
            .authorities(vec![auth])
            .fallback_caches(vec![fallback]);
        bld.tor()
            .storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.tor()
            .download_schedule()
            .retry_certs(DownloadSchedule::new(10, sec, 3))
            .retry_microdescs(DownloadSchedule::new(30, 10 * sec, 9));
        bld.tor()
            .override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.tor()
            .path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.tor()
            .preemptive_circuits()
            .disable_at_threshold(12)
            .initial_predicted_ports(vec![80, 443])
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
