//! Configure and implement onion service reverse-proxy feature.

use std::{collections::HashMap, sync::Arc};

use arti_client::config::onion_service::{OnionServiceConfig, OnionServiceConfigBuilder};
use futures::task::SpawnExt;
use tor_config::{define_list_builder_helper, impl_standard_builder, ConfigBuildError, Flatten};
use tor_error::warn_report;
use tor_hsrproxy::{config::ProxyConfigBuilder, OnionServiceReverseProxy, ProxyConfig};
use tor_hsservice::{HsNickname, OnionService};
use tor_rtcompat::Runtime;
use tracing::debug;

/// Configuration for running an onion service from `arti`.
///
/// This onion service will forward incoming connections to one or more local
/// ports, depending on its configuration.  If you need it to do something else
/// with incoming connections, or if you need finer-grained control over its
/// behavior, consider using
/// [`TorClient::launch_onion_service`](arti_client::TorClient::launch_onion_service).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnionServiceProxyConfig {
    /// Configuration for the onion service itself.
    svc_cfg: OnionServiceConfig,
    /// Configuration for the reverse proxy that handles incoming connections
    /// from the onion service.
    proxy_cfg: ProxyConfig,
}

/// Builder object to construct an [`OnionServiceProxyConfig`].
//
// We cannot easily use derive_builder on this builder type, since we want it to be a
// "Flatten<>" internally.  Fortunately, it's easy enough to implement the
// pieces that we need.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default, Eq, PartialEq)]
#[serde(transparent)]
pub struct OnionServiceProxyConfigBuilder(Flatten<OnionServiceConfigBuilder, ProxyConfigBuilder>);

impl OnionServiceProxyConfigBuilder {
    /// Try to construct an [`OnionServiceProxyConfig`].
    ///
    /// Returns an error if any part of this builder is invalid.
    pub fn build(&self) -> Result<OnionServiceProxyConfig, ConfigBuildError> {
        let svc_cfg = self.0 .0.build()?;
        let proxy_cfg = self.0 .1.build()?;
        Ok(OnionServiceProxyConfig { svc_cfg, proxy_cfg })
    }

    /// Return a mutable reference to an onion-service configuration sub-builder.
    pub fn service(&mut self) -> &mut OnionServiceConfigBuilder {
        &mut self.0 .0
    }

    /// Return a mutable reference to a proxy configuration sub-builder.
    pub fn proxy(&mut self) -> &mut ProxyConfigBuilder {
        &mut self.0 .1
    }
}

impl_standard_builder! { OnionServiceProxyConfig: !Default }

/// Alias for a `Vec` of `OnionServiceProxyConfig`; used to make derive_builder
/// happy.
#[cfg(feature = "onion-service-service")]
pub(crate) type OnionServiceProxyConfigList = Vec<OnionServiceProxyConfig>;

/// The serialized format of an OnionServiceProxyConfigListBuilder:
/// a map from nickname to `OnionServiceConfigBuilder`
type NamedProxyMap = HashMap<HsNickname, OnionServiceProxyConfigBuilder>;

#[cfg(feature = "onion-service-service")]
define_list_builder_helper! {
    pub struct OnionServiceProxyConfigListBuilder {
        services: [OnionServiceProxyConfigBuilder],
    }
    built: OnionServiceProxyConfigList = services;
    default = vec![];
    #[serde(try_from="NamedProxyMap", into="NamedProxyMap")]
}

impl TryFrom<NamedProxyMap> for OnionServiceProxyConfigListBuilder {
    type Error = ConfigBuildError;

    fn try_from(value: NamedProxyMap) -> Result<Self, Self::Error> {
        let mut list_builder = OnionServiceProxyConfigListBuilder::default();
        for (nickname, mut cfg) in value {
            match cfg.0 .0.peek_nickname() {
                Some(n) if n == &nickname => (),
                None => (),
                Some(other) => {
                    return Err(ConfigBuildError::Inconsistent {
                        fields: vec![nickname.to_string(), format!("{nickname}.{other}")],
                        problem: "mismatched nicknames on onion service.".into(),
                    });
                }
            }
            cfg.0 .0.nickname(nickname);
            list_builder.access().push(cfg);
        }
        Ok(list_builder)
    }
}

impl From<OnionServiceProxyConfigListBuilder> for NamedProxyMap {
    fn from(value: OnionServiceProxyConfigListBuilder) -> Self {
        let mut map = HashMap::new();
        for cfg in value.services.into_iter().flatten() {
            // TODO HSS: Validate that nicknames are unique, somehow.
            let nickname = cfg.0 .0.peek_nickname().cloned().unwrap_or_else(|| {
                "Unnamed"
                    .to_string()
                    .try_into()
                    .expect("'Unnamed' was not a valid nickname")
            });
            map.insert(nickname, cfg);
        }
        map
    }
}

/// A running onion service and an associated reverse proxy.
///
/// This is what a user configures when they add an onion service to their
/// configuration.
#[allow(dead_code)] //TODO HSS remove once reconfigure is written.
struct Proxy {
    /// The onion service.
    ///
    /// This is launched and running.
    svc: Arc<OnionService>,
    /// The reverse proxy that accepts connections from the onion service.
    ///
    /// This is also launched and running.
    proxy: Arc<OnionServiceReverseProxy>,
}

impl Proxy {
    /// Create and launch a new onion service proxy, using a given `client`,
    /// to handle connections according to `config`.
    pub(crate) fn launch_new<R: Runtime>(
        client: &arti_client::TorClient<R>,
        config: OnionServiceProxyConfig,
    ) -> anyhow::Result<Self> {
        let OnionServiceProxyConfig { svc_cfg, proxy_cfg } = config;
        let nickname = svc_cfg.nickname().clone();
        let (svc, request_stream) = client.launch_onion_service(svc_cfg)?;
        let proxy = OnionServiceReverseProxy::new(proxy_cfg);

        {
            let proxy = proxy.clone();
            let runtime_clone = client.runtime().clone();
            client.runtime().spawn(async move {
                match proxy.handle_requests(runtime_clone, request_stream).await {
                    Ok(()) => {
                        debug!("Onion service {} exited cleanly.", nickname);
                    }
                    Err(e) => {
                        warn_report!(e, "Onion service {} exited with an error", nickname);
                    }
                }
            })?;
        }

        Ok(Proxy { svc, proxy })
    }
}

/// A set of configured onion service proxies.
#[allow(dead_code)] //TODO HSS remove once reconfigure is written.
pub(crate) struct ProxySet {
    /// The proxies themselves, indexed by nickname.
    proxies: HashMap<HsNickname, Proxy>,
}

impl ProxySet {
    /// Create and launch a set of onion service proxies.
    pub(crate) fn launch_new<R: Runtime>(
        client: &arti_client::TorClient<R>,
        config_list: OnionServiceProxyConfigList,
    ) -> anyhow::Result<Self> {
        // TODO HSS: Perhaps OnionServiceProxyConfigList needs to enforce no
        // duplicate nicknames?
        let proxies: HashMap<_, _> = config_list
            .into_iter()
            .map(|cfg| {
                let nickname = cfg.svc_cfg.nickname().clone();
                Ok((nickname, Proxy::launch_new(client, cfg)?))
            })
            .collect::<anyhow::Result<HashMap<_, _>>>()?;

        Ok(Self { proxies })
    }

    // TODO HSS: reconfigure
}
