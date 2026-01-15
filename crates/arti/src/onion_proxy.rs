//! Configure and implement onion service reverse-proxy feature.

use std::{
    collections::{BTreeMap, HashSet, btree_map::Entry},
    sync::{Arc, Mutex},
};

use arti_client::config::onion_service::{OnionServiceConfig, OnionServiceConfigBuilder};
use futures::StreamExt as _;
use tor_config::{
    ConfigBuildError, Flatten, Reconfigure, ReconfigureError, define_list_builder_helper,
    impl_standard_builder,
};
use tor_error::warn_report;
use tor_hsrproxy::{OnionServiceReverseProxy, ProxyConfig, config::ProxyConfigBuilder};
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_rtcompat::{Runtime, SpawnExt};
use tracing::debug;

/// Configuration for running an onion service from `arti`.
///
/// This onion service will forward incoming connections to one or more local
/// ports, depending on its configuration.  If you need it to do something else
/// with incoming connections, or if you need finer-grained control over its
/// behavior, consider using
/// [`TorClient::launch_onion_service`](arti_client::TorClient::launch_onion_service).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct OnionServiceProxyConfig {
    /// Configuration for the onion service itself.
    pub(crate) svc_cfg: OnionServiceConfig,
    /// Configuration for the reverse proxy that handles incoming connections
    /// from the onion service.
    pub(crate) proxy_cfg: ProxyConfig,
}

/// Builder object to construct an [`OnionServiceProxyConfig`].
//
// We cannot easily use derive_builder on this builder type, since we want it to be a
// "Flatten<>" internally.  Fortunately, it's easy enough to implement the
// pieces that we need.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
#[serde(transparent)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct OnionServiceProxyConfigBuilder(
    Flatten<OnionServiceConfigBuilder, ProxyConfigBuilder>,
);

impl OnionServiceProxyConfigBuilder {
    /// Try to construct an [`OnionServiceProxyConfig`].
    ///
    /// Returns an error if any part of this builder is invalid.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn build(&self) -> Result<OnionServiceProxyConfig, ConfigBuildError> {
        let svc_cfg = self.0.0.build()?;
        let proxy_cfg = self.0.1.build()?;
        Ok(OnionServiceProxyConfig { svc_cfg, proxy_cfg })
    }

    /// Return a mutable reference to an onion-service configuration sub-builder.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn service(&mut self) -> &mut OnionServiceConfigBuilder {
        &mut self.0.0
    }

    /// Return a mutable reference to a proxy configuration sub-builder.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) fn proxy(&mut self) -> &mut ProxyConfigBuilder {
        &mut self.0.1
    }
}

impl_standard_builder! { OnionServiceProxyConfig: !Default }

/// Alias for a `BTreeMap` of [`OnionServiceProxyConfig`]; used to make [`derive_builder`] happy.
#[cfg(feature = "onion-service-service")]
pub(crate) type OnionServiceProxyConfigMap = BTreeMap<HsNickname, OnionServiceProxyConfig>;

/// The serialized format of an [`OnionServiceProxyConfigMapBuilder`]:
/// a map from [`HsNickname`] to [`OnionServiceConfigBuilder`].
type ProxyBuilderMap = BTreeMap<HsNickname, OnionServiceProxyConfigBuilder>;

// TODO: Someday we might want to have an API for a MapBuilder that is distinct
// from that of a ListBuilder.  It would have to enforce that everything has a
// key, and that keys are distinct.
#[cfg(feature = "onion-service-service")]
define_list_builder_helper! {
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) struct OnionServiceProxyConfigMapBuilder {
        services: [OnionServiceProxyConfigBuilder],
    }
    built: OnionServiceProxyConfigMap = build_list(services)?;
    default = vec![];
    #[serde(try_from="ProxyBuilderMap", into="ProxyBuilderMap")]
}

/// Construct a [`OnionServiceProxyConfigMap`] from a `Vec` of [`OnionServiceProxyConfig`];
/// enforce that [`HsNickname`]s are unique.
fn build_list(
    services: Vec<OnionServiceProxyConfig>,
) -> Result<OnionServiceProxyConfigMap, ConfigBuildError> {
    // It *is* reachable from OnionServiceProxyConfigMapBuilder::build(), since
    // that builder's API uses push() to add OnionServiceProxyConfigBuilders to
    // an internal _list_.  Alternatively, we might want to have a distinct
    // MapBuilder type.

    let mut map = BTreeMap::new();
    for service in services {
        if let Some(previous_value) = map.insert(service.svc_cfg.nickname().clone(), service) {
            return Err(ConfigBuildError::Inconsistent {
                fields: vec!["nickname".into()],
                problem: format!(
                    "Multiple onion services with the nickname {}",
                    previous_value.svc_cfg.nickname()
                ),
            });
        };
    }
    Ok(map)
}

impl TryFrom<ProxyBuilderMap> for OnionServiceProxyConfigMapBuilder {
    type Error = ConfigBuildError;

    fn try_from(value: ProxyBuilderMap) -> Result<Self, Self::Error> {
        let mut list_builder = OnionServiceProxyConfigMapBuilder::default();
        for (nickname, mut cfg) in value {
            match cfg.0.0.peek_nickname() {
                Some(n) if n == &nickname => (),
                None => (),
                Some(other) => {
                    return Err(ConfigBuildError::Inconsistent {
                        fields: vec![nickname.to_string(), format!("{nickname}.{other}")],
                        problem: "mismatched nicknames on onion service.".into(),
                    });
                }
            }
            cfg.0.0.nickname(nickname);
            list_builder.access().push(cfg);
        }
        Ok(list_builder)
    }
}

impl From<OnionServiceProxyConfigMapBuilder> for ProxyBuilderMap {
    /// Convert our Builder representation of a set of onion services into the
    /// format that serde will serialize.
    ///
    /// Note: This is a potentially lossy conversion, since the serialized format
    /// can't represent partially-built services without a nickname, or
    /// a collection of services with duplicate nicknames.
    fn from(value: OnionServiceProxyConfigMapBuilder) -> Self {
        let mut map = BTreeMap::new();
        for cfg in value.services.into_iter().flatten() {
            let nickname = cfg.0.0.peek_nickname().cloned().unwrap_or_else(|| {
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
#[must_use = "a hidden service Proxy object will terminate the service when dropped"]
struct Proxy {
    /// The onion service.
    ///
    /// This is launched and running.
    svc: Arc<RunningOnionService>,
    /// The reverse proxy that accepts connections from the onion service.
    ///
    /// This is also launched and running.
    proxy: Arc<OnionServiceReverseProxy>,
}

impl Proxy {
    /// Create and launch a new onion service proxy, using a given `client`,
    /// to handle connections according to `config`.
    ///
    /// Returns `Ok(None)` if the service specified is disabled in the config.
    pub(crate) fn launch_new<R: Runtime>(
        client: &arti_client::TorClient<R>,
        config: OnionServiceProxyConfig,
    ) -> anyhow::Result<Option<Self>> {
        let OnionServiceProxyConfig { svc_cfg, proxy_cfg } = config;
        let nickname = svc_cfg.nickname().clone();

        let (svc, request_stream) = match client.launch_onion_service(svc_cfg)? {
            Some(running_service) => running_service,
            None => {
                debug!(
                    "Onion service {} didn't start (disabled in config)",
                    nickname
                );
                return Ok(None);
            }
        };
        let proxy = OnionServiceReverseProxy::new(proxy_cfg);

        {
            let proxy = proxy.clone();
            let runtime_clone = client.runtime().clone();
            let nickname_clone = nickname.clone();
            client.runtime().spawn(async move {
                match proxy
                    .handle_requests(runtime_clone, nickname.clone(), request_stream)
                    .await
                {
                    Ok(()) => {
                        debug!("Onion service {} exited cleanly.", nickname);
                    }
                    Err(e) => {
                        warn_report!(e, "Onion service {} exited with an error", nickname);
                    }
                }
            })?;

            let mut status_stream = svc.status_events();
            client.runtime().spawn(async move {
                while let Some(status) = status_stream.next().await {
                    debug!(
                        nickname=%nickname_clone,
                        status=?status.state(),
                        problem=?status.current_problem(),
                        "Onion service status change",
                    );
                }
            })?;
        }

        Ok(Some(Proxy { svc, proxy }))
    }

    /// Reconfigure this proxy, using the new configuration `config` and the
    /// rules in `how`.
    fn reconfigure(
        &mut self,
        config: OnionServiceProxyConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError> {
        if matches!(how, Reconfigure::AllOrNothing) {
            self.reconfigure_inner(config.clone(), Reconfigure::CheckAllOrNothing)?;
        }

        self.reconfigure_inner(config, how)
    }

    /// Helper for `reconfigure`: Run `reconfigure` on each part of this `Proxy`.
    fn reconfigure_inner(
        &mut self,
        config: OnionServiceProxyConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError> {
        let OnionServiceProxyConfig { svc_cfg, proxy_cfg } = config;

        self.svc.reconfigure(svc_cfg, how)?;
        self.proxy.reconfigure(proxy_cfg, how)?;

        Ok(())
    }
}

/// A set of configured onion service proxies.
#[must_use = "a hidden service ProxySet object will terminate the services when dropped"]
pub(crate) struct ProxySet<R: Runtime> {
    /// The arti_client that we use to launch proxies.
    client: arti_client::TorClient<R>,
    /// The proxies themselves, indexed by nickname.
    proxies: Mutex<BTreeMap<HsNickname, Proxy>>,
}

impl<R: Runtime> ProxySet<R> {
    /// Create and launch a set of onion service proxies.
    pub(crate) fn launch_new(
        client: &arti_client::TorClient<R>,
        config_list: OnionServiceProxyConfigMap,
    ) -> anyhow::Result<Self> {
        let proxies: BTreeMap<_, _> = config_list
            .into_iter()
            .filter_map(|(nickname, cfg)| {
                // Filter out services which are disabled in the config
                match Proxy::launch_new(client, cfg) {
                    Ok(Some(running_service)) => Some(Ok((nickname, running_service))),
                    Err(error) => Some(Err(error)),
                    Ok(None) => None,
                }
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

        Ok(Self {
            client: client.clone(),
            proxies: Mutex::new(proxies),
        })
    }

    /// Try to reconfigure the set of onion proxies according to the
    /// configuration in `new_config`.
    ///
    /// Launches or closes proxies as necessary.  Does not close existing
    /// connections.
    pub(crate) fn reconfigure(
        &self,
        new_config: OnionServiceProxyConfigMap,
        // TODO: this should probably take `how: Reconfigure` and implement an all-or-nothing mode.
        // See #1156.
    ) -> Result<(), anyhow::Error> {
        let mut proxy_map = self.proxies.lock().expect("lock poisoned");

        // Set of the nicknames of defunct proxies.
        let mut defunct_nicknames: HashSet<_> = proxy_map.keys().map(Clone::clone).collect();

        for cfg in new_config.into_values() {
            let nickname = cfg.svc_cfg.nickname().clone();
            // This proxy is still configured, so remove it from the list of
            // defunct proxies.
            defunct_nicknames.remove(&nickname);

            match proxy_map.entry(nickname) {
                Entry::Occupied(mut existing_proxy) => {
                    // We already have a proxy by this name, so we try to
                    // reconfigure it.
                    existing_proxy
                        .get_mut()
                        .reconfigure(cfg, Reconfigure::WarnOnFailures)?;
                }
                Entry::Vacant(ent) => {
                    // We do not have a proxy by this name, so we try to launch
                    // one.
                    match Proxy::launch_new(&self.client, cfg) {
                        Ok(Some(new_proxy)) => {
                            ent.insert(new_proxy);
                        }
                        Ok(None) => {
                            debug!(
                                "Onion service {} didn't start (disabled in config)",
                                ent.key()
                            );
                        }
                        Err(err) => {
                            warn_report!(err, "Unable to launch onion service {}", ent.key());
                        }
                    }
                }
            }
        }

        for nickname in defunct_nicknames {
            // We no longer have any configuration for this proxy, so we remove
            // it from our map.
            let defunct_proxy = proxy_map
                .remove(&nickname)
                .expect("Somehow a proxy disappeared from the map");
            // This "drop" should shut down the proxy.
            drop(defunct_proxy);
        }

        Ok(())
    }

    /// Whether this `ProxySet` is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.proxies.lock().expect("lock poisoned").is_empty()
    }
}

impl<R: Runtime> crate::reload_cfg::ReconfigurableModule for ProxySet<R> {
    fn reconfigure(&self, new: &crate::ArtiCombinedConfig) -> anyhow::Result<()> {
        ProxySet::reconfigure(self, new.0.onion_services.clone())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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

    use tor_config::ConfigBuildError;
    use tor_hsservice::HsNickname;

    /// Get an [`OnionServiceProxyConfig`] with its `svc_cfg` field having the nickname `nick`.
    fn get_onion_service_proxy_config(nick: &HsNickname) -> OnionServiceProxyConfig {
        let mut builder = OnionServiceProxyConfigBuilder::default();
        builder.service().nickname(nick.clone());
        builder.build().unwrap()
    }

    /// Test `super::build_list` with unique and duplicate [`HsNickname`]s.
    #[test]
    fn fn_build_list() {
        let nick_1 = HsNickname::new("nick_1".to_string()).unwrap();
        let nick_2 = HsNickname::new("nick_2".to_string()).unwrap();

        let proxy_configs: Vec<OnionServiceProxyConfig> = [&nick_1, &nick_2]
            .into_iter()
            .map(get_onion_service_proxy_config)
            .collect();
        let actual = build_list(proxy_configs.clone()).unwrap();

        let expected =
            OnionServiceProxyConfigMap::from_iter([nick_1, nick_2].into_iter().zip(proxy_configs));

        assert_eq!(actual, expected);

        let nick = HsNickname::new("nick".to_string()).unwrap();
        let proxy_configs_dup: Vec<OnionServiceProxyConfig> = [&nick, &nick]
            .into_iter()
            .map(get_onion_service_proxy_config)
            .collect();
        let actual = build_list(proxy_configs_dup).unwrap_err();
        let ConfigBuildError::Inconsistent { fields, problem } = actual else {
            panic!("Unexpected error from `build_list`: {actual:?}");
        };

        assert_eq!(fields, vec!["nickname".to_string()]);
        assert_eq!(
            problem,
            format!("Multiple onion services with the nickname {nick}")
        );
    }
}
