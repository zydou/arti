//! Configure and implement onion service reverse-proxy feature.

// TODO HSS remove or justify.
#![allow(unreachable_pub, dead_code)]

use std::collections::HashMap;

use arti_client::config::onion_service::{OnionServiceConfig, OnionServiceConfigBuilder};
use tor_config::{define_list_builder_helper, impl_standard_builder, ConfigBuildError, Flatten};
use tor_hsrproxy::{config::ProxyConfigBuilder, ProxyConfig};
use tor_hsservice::HsNickname;

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
