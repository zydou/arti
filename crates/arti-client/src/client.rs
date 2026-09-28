//! A general interface for Tor client usage.
//!
//! To construct a client, run the [`TorClient::create_bootstrapped`] method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! [`TorClient::connect`].

#[cfg(feature = "rpc")]
use {derive_deftly::Deftly, tor_rpcbase::templates::*};

use crate::address::{IntoTorAddr, ResolveInstructions, StreamInstructions};

use crate::config::{ClientAddrConfig, StreamTimeoutConfig, TorClientConfig};
use crate::status::BootstrapStatus;
use safelog::{Sensitive, sensitive};
use tor_async_utils::{DropNotifyWatchSender, PostageWatchSenderExt};
use tor_chanmgr::ChanMgrConfig;
use tor_circmgr::ClientDataTunnel;
use tor_circmgr::isolation::{Isolation, StreamIsolation};
use tor_circmgr::{IsolationToken, TargetPort, isolation::StreamIsolationBuilder};
use tor_config::MutCfg;
#[cfg(feature = "bridge-client")]
use tor_dirmgr::bridgedesc::BridgeDescMgr;
use tor_dirmgr::{DirMgrStore, Timeliness};
use tor_error::{Bug, error_report, internal};
use tor_guardmgr::{GuardMgr, RetireCircuits};
use tor_keymgr::Keystore;
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::{NetDirProvider, params::NetParameters};
use tor_persist::StateMgr;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tor_persist::TestingStateMgr;
#[cfg(feature = "onion-service-service")]
use tor_persist::state_dir::StateDirectory;
use tor_proto::client::stream::{DataStream, IpVersionPreference, StreamParameters};
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio"),
))]
use tor_rtcompat::PreferredRuntime;
use tor_rtcompat::{Runtime, SleepProviderExt};
#[cfg(feature = "onion-service-client")]
use {
    tor_config::BoolOrAuto,
    tor_hsclient::{HsClientConnector, HsClientDescEncKeypairSpecifier, HsClientSecretKeysBuilder},
    tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncKeypair, HsClientDescEncSecretKey},
    tor_keymgr::CTorClientKeystore,
    tor_netdir::DirEvent,
};

#[cfg(all(feature = "onion-service-service", feature = "experimental-api"))]
use tor_hsservice::HsIdKeypairSpecifier;
#[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
use {tor_hscrypto::pk::HsId, tor_hscrypto::pk::HsIdKeypair, tor_keymgr::KeystoreSelector};

use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, config::ArtiKeystoreKind};

#[cfg(feature = "ephemeral-keystore")]
use tor_keymgr::ArtiEphemeralKeystore;

#[cfg(feature = "onion-service-service")]
use tor_keymgr::CTorServiceKeystore;

use futures::StreamExt as _;
use futures::lock::Mutex as AsyncMutex;
use std::net::IpAddr;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};
use tor_rtcompat::SpawnExt;

use crate::err::ErrorDetail;
use crate::{TorClientBuilder, status, util};
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
use tor_rtcompat::scheduler::TaskHandle;
use tracing::{debug, info, instrument, warn};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tor_persist::FsStateMgr as UsingStateMgr;

// TODO wasm: This is not the right choice, but at least it compiles.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use tor_persist::TestingStateMgr as UsingStateMgr;

/// An active client session on the Tor network.
///
/// While it's running, it will fetch directory information, build
/// circuits, and make connections for you.
///
/// # In the Arti RPC System
///
/// An open client on the Tor network.
///
/// A `TorClient` can be used to open anonymous connections,
/// and (eventually) perform other activities.
///
/// You can use an `RpcSession` as a `TorClient`, or use the `isolated_client` method
/// to create a new `TorClient` whose stream will not share circuits with any other Tor client.
///
/// This ObjectID for this object can be used as the target of a SOCKS stream.
#[cfg_attr(
    feature = "rpc",
    derive(Deftly),
    derive_deftly(Object),
    deftly(rpc(expose_outside_of_session))
)]
pub struct TorClient<R: Runtime> {
    /// Default isolation token for streams through this client.
    ///
    /// This is eventually used for `owner_token` in `tor-circmgr/src/usage.rs`, and is orthogonal
    /// to the `stream_isolation` which comes from `connect_prefs` (or a passed-in `StreamPrefs`).
    /// (ie, both must be the same to share a circuit).
    client_isolation: IsolationToken,
    /// Connection preferences.  Starts out as `Default`,  Inherited by our clones.
    connect_prefs: StreamPrefs,

    /// Inner structure respresenting all components shared across different
    /// TorClients.
    client: Arc<ClientShared<R>>,
}

/// Shared pieces of a `TorClient`, used to implement client functionality.
///
/// In the future, we might choose to expose this along with APIs.
struct ClientShared<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,

    /// Inner typestate object to represent the parts of the ClientShared that may be absent
    /// depending on whether we are running.
    inner: Mutex<Inner<R>>,

    /// Memory quota tracker
    memquota: Arc<MemoryQuotaTracker>,

    /// A handle to this client's [`InertTorClient`].
    ///
    /// Used for accessing the key manager and other persistent state.
    inert_client: InertTorClient,

    /// Location on disk where we store persistent data containing both location and Mistrust information.
    ///
    ///
    /// This path is configured via `[storage]` in the config but is not used directly as a
    /// StateDirectory in most places. Instead, its path and Mistrust information are copied
    /// to subsystems like `dirmgr`, `keymgr`, and `statemgr` during `TorClient` creation.
    #[cfg(feature = "onion-service-service")]
    state_directory: StateDirectory,
    /// Location on disk where we store persistent data (cooked state manager).
    statemgr: UsingStateMgr,

    /// Directory manager persistent storage.
    dirmgr_store: DirMgrStore<R>,

    /// Client address configuration
    addrcfg: MutCfg<ClientAddrConfig>,
    /// Client DNS configuration
    timeoutcfg: MutCfg<StreamTimeoutConfig>,
    /// Mutex used to serialize concurrent attempts to reconfigure a TorClient.
    ///
    /// See [`TorClient::reconfigure`] for more information on its use.
    reconfigure_lock: Arc<Mutex<()>>,

    /// A stream of bootstrap messages that we can clone when a client asks for
    /// it.
    ///
    /// (We don't need to observe this stream ourselves, since it drops each
    /// unobserved status change when the next status change occurs.)
    status_receiver: status::BootstrapEvents,

    /// mutex used to prevent two tasks from trying to bootstrap at once.
    bootstrap_in_progress: AsyncMutex<()>,

    /// Sender used to update changes in our bootstrap settings.
    bootstrap_setting_sender: Mutex<postage::watch::Sender<BootstrapSetting>>,

    /// Whether or not we should call `bootstrap` before doing things that require
    /// bootstrapping.
    ///
    /// If this is [`BootstrapBehavior::OnDemand`], we wait for the client to bootstrap
    /// (launching a bootstrap if necessary) before performing any operation that needs circuits.
    /// If this is [`BootstrapBehavior::Manual`], we give an error if we are told to do
    /// something that needs circuits and we have not been told to bootstrap.
    should_bootstrap: BootstrapBehavior,

    /// Shared boolean for whether we're currently in "dormant mode" or not.
    //
    // The sent value is `Option`, so that `None` is sent when the sender, here,
    // is dropped,.  That shuts down the monitoring task.
    dormant: Mutex<DropNotifyWatchSender<Option<DormantMode>>>,

    /// The path resolver given to us by a [`TorClientConfig`].
    ///
    /// We must not add our own variables to it since `TorClientConfig` uses it to perform its own
    /// path expansions. If we added our own variables, it would introduce an inconsistency where
    /// paths expanded by the `TorClientConfig` would expand differently than when expanded by us.
    path_resolver: Arc<tor_config_path::CfgPathResolver>,
}

/// A typestate object holding the parts of the client state that we may or may not have
/// depending on whether we are running.
enum Inner<R: Runtime> {
    /// The client is not constructed.
    ///
    /// In this state, the client won't try to connect to the network.
    NotConstructed(Box<NotConstructedInner<R>>),

    /// The client is either bootstrapped or trying to bootstrap.
    Running(Arc<RunningInner<R>>),

    /// The client has failed in a non-recoverable way.
    Poisoned(Box<ErrorDetail>),
}

/// Information stored by a never-bootstrapped [`TorClient`],
/// used to eventually construct a [`RunningInner`] and bootstrap.
struct NotConstructedInner<R: Runtime> {
    /// The client's configuration.
    config: TorClientConfig,

    /// A receiver to give to various tasks that want to monitor our dormant status.
    dormant_recv: postage::watch::Receiver<Option<DormantMode>>,

    /// A sender used to produce updates about our bootstrapping status.
    ///
    /// NOTE: The fact that this type is not Clone is the only reason
    /// that [`RunningInner::new`] needs to take NotConstructedInner by value.
    /// With some redesign we could simplify this, and do away with [`Inner::Poisoned`].
    status_sender: postage::watch::Sender<BootstrapStatus>,

    /// A receiver used to inform the bootstrap status processor about changes in our settings.
    bootstrap_setting_receiver: postage::watch::Receiver<BootstrapSetting>,

    /// A (possibly user-provided) builder used to construct our NetDirProvider.
    dirmgr_builder: Arc<dyn crate::builder::DirProviderBuilder<R>>,

    /// A (possibly user-provided) set of in-process extensions for our NetDirProvider.
    dirmgr_extensions: tor_dirmgr::config::DirMgrExtensions,
}

/// Data structures for a "running" client.
///
/// A running client is one that is either bootstrapped, or potentially trying to bootstrap.
///
/// All structures that potentially interact with the network belong here.
///
/// We defer the creation of this structure and its members until bootstrap time,
/// to make sure that before we are bootstrapping, nothing will try to connect to the network
/// or launch expensive background tasks.
struct RunningInner<R: Runtime> {
    /// Channel manager, used by circuits etc.,
    ///
    /// Used directly by client only for reconfiguration.
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<dyn tor_dirmgr::DirProvider>,
    /// Bridge descriptor manager
    ///
    /// None until we have bootstrapped.
    ///
    /// Lock hierarchy: don't acquire this before dormant
    //
    // TODO: after or as part of https://gitlab.torproject.org/tpo/core/arti/-/issues/634
    // this can be   bridge_desc_mgr: BridgeDescMgr<R>>
    // since BridgeDescMgr is Clone and all its methods take `&self` (it has a lock inside)
    // Or maybe BridgeDescMgr should not be Clone, since we want to make Weaks of it,
    // which we can't do when the Arc is inside.
    #[cfg(feature = "bridge-client")]
    bridge_desc_mgr: Arc<Mutex<Option<Arc<BridgeDescMgr<R>>>>>,
    /// Pluggable transport manager.
    #[cfg(feature = "pt-client")]
    pt_mgr: Arc<tor_ptmgr::PtMgr<R>>,
    /// HS client connector
    #[cfg(feature = "onion-service-client")]
    hsclient: HsClientConnector<R>,
    /// Circuit pool for providing onion services with circuits.
    #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
    hs_circ_pool: Arc<tor_circmgr::hspool::HsCircPool<R>>,
    /// Guard manager
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    guardmgr: GuardMgr<R>,
}

/// A Tor client that is not runnable.
///
/// Can be used to access the state that would be used by a running [`TorClient`].
///
/// An `InertTorClient` never connects to the network.
#[derive(Clone)]
pub struct InertTorClient {
    /// The key manager.
    ///
    /// This is used for retrieving private keys, certificates, and other sensitive data (for
    /// example, for retrieving the keys necessary for connecting to hidden services that are
    /// running in restricted discovery mode).
    ///
    /// If this crate is compiled _with_ the `keymgr` feature, [`TorClient`] will use a functional
    /// key manager implementation.
    ///
    /// If this crate is compiled _without_ the `keymgr` feature, then [`TorClient`] will use a
    /// no-op key manager implementation instead.
    ///
    /// See the [`KeyMgr`] documentation for more details.
    keymgr: Option<Arc<KeyMgr>>,
}

impl InertTorClient {
    /// Create an `InertTorClient` from a `TorClientConfig`.
    pub(crate) fn new(config: &TorClientConfig) -> StdResult<Self, ErrorDetail> {
        let keymgr = Self::create_keymgr(config)?;

        Ok(Self { keymgr })
    }

    /// Create a [`KeyMgr`] using the specified configuration.
    ///
    /// Returns `Ok(None)` if keystore use is disabled.
    fn create_keymgr(config: &TorClientConfig) -> StdResult<Option<Arc<KeyMgr>>, ErrorDetail> {
        let keystore = config.storage.keystore();
        let permissions = config.storage.permissions();
        let primary_store: Box<dyn Keystore> = match keystore.primary_kind() {
            Some(ArtiKeystoreKind::Native) => {
                let (state_dir, _mistrust) = config.state_dir()?;
                let key_store_dir = state_dir.join("keystore");

                let native_store =
                    ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)?;
                // Should only log fs paths at debug level or lower,
                // unless they're part of a diagnostic message.
                debug!("Using keystore from {key_store_dir:?}");

                Box::new(native_store)
            }
            #[cfg(feature = "ephemeral-keystore")]
            Some(ArtiKeystoreKind::Ephemeral) => {
                // TODO: make the keystore ID somehow configurable
                let ephemeral_store: ArtiEphemeralKeystore =
                    ArtiEphemeralKeystore::new("ephemeral".to_string());
                Box::new(ephemeral_store)
            }
            None => {
                info!("Running without a keystore");
                return Ok(None);
            }
            ty => return Err(internal!("unrecognized keystore type {ty:?}").into()),
        };

        let mut builder = KeyMgrBuilder::default().primary_store(primary_store);

        #[cfg(feature = "onion-service-service")]
        for config in config.storage.keystore().ctor_svc_stores() {
            let store: Box<dyn Keystore> = Box::new(CTorServiceKeystore::from_path_and_mistrust(
                config.path(),
                permissions,
                config.id().clone(),
                // TODO: these nicknames should be cross-checked with configured
                // svc nicknames as part of config validation!!!
                config.nickname().clone(),
            )?);

            builder.secondary_stores().push(store);
        }

        #[cfg(feature = "onion-service-client")]
        for config in config.storage.keystore().ctor_client_stores() {
            let store: Box<dyn Keystore> = Box::new(CTorClientKeystore::from_path_and_mistrust(
                config.path(),
                permissions,
                config.id().clone(),
            )?);

            builder.secondary_stores().push(store);
        }

        let keymgr = builder
            .build()
            .map_err(|_| internal!("failed to build keymgr"))?;
        Ok(Some(Arc::new(keymgr)))
    }

    /// Generate a service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// See [`TorClient::generate_service_discovery_key`].
    //
    // TODO: decide whether this should use get_or_generate before making it
    // non-experimental
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn generate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        let mut rng = tor_llcrypto::rng::CautiousRng;
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "generate client service discovery key",
            })?
            .generate::<HsClientDescEncKeypair>(
                &spec, selector, &mut rng, false, /* overwrite */
            )?;

        Ok(key.public().clone())
    }

    /// Rotate the service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// See [`TorClient::rotate_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    pub fn rotate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        let mut rng = tor_llcrypto::rng::CautiousRng;
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "rotate client service discovery key",
            })?
            .generate::<HsClientDescEncKeypair>(
                &spec, selector, &mut rng, true, /* overwrite */
            )?;

        Ok(key.public().clone())
    }

    /// Insert a service discovery secret key for connecting to a hidden service running in
    /// "restricted discovery" mode
    ///
    /// See [`TorClient::insert_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn insert_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
        hs_client_desc_enc_secret_key: HsClientDescEncSecretKey,
    ) -> crate::Result<HsClientDescEncKey> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let client_desc_enc_key = HsClientDescEncKey::from(&hs_client_desc_enc_secret_key);
        let client_desc_enc_keypair =
            HsClientDescEncKeypair::new(client_desc_enc_key.clone(), hs_client_desc_enc_secret_key);
        let _key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "insert client service discovery key",
            })?
            .insert::<HsClientDescEncKeypair>(client_desc_enc_keypair, &spec, selector, false)?;
        Ok(client_desc_enc_key)
    }

    /// Return the service discovery public key for the service with the specified `hsid`.
    ///
    /// See [`TorClient::get_service_discovery_key`].
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "onion-service-client", feature = "experimental-api")))
    )]
    pub fn get_service_discovery_key(
        &self,
        hsid: HsId,
    ) -> crate::Result<Option<HsClientDescEncKey>> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let key = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "get client service discovery key",
            })?
            .get::<HsClientDescEncKeypair>(&spec)?
            .map(|key| key.public().clone());

        Ok(key)
    }

    /// Removes the service discovery keypair for the service with the specified `hsid`.
    ///
    /// See [`TorClient::remove_service_discovery_key`].
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn remove_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<Option<()>> {
        let spec = HsClientDescEncKeypairSpecifier::new(hsid);
        let result = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "remove client service discovery key",
            })?
            .remove::<HsClientDescEncKeypair>(&spec, selector)?;
        match result {
            Some(_) => Ok(Some(())),
            None => Ok(None),
        }
    }

    /// Getter for keymgr.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn keymgr(&self) -> crate::Result<&KeyMgr> {
        Ok(self.keymgr.as_ref().ok_or(ErrorDetail::KeystoreRequired {
            action: "get key manager handle",
        })?)
    }

    /// Create (but do not launch) a new
    /// [`OnionService`](tor_hsservice::OnionService)
    /// using the given configuration.
    ///
    /// See [`TorClient::create_onion_service`].
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn create_onion_service(
        &self,
        config: &TorClientConfig,
        svc_config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<tor_hsservice::OnionService> {
        let keymgr = self.keymgr.as_ref().ok_or(ErrorDetail::KeystoreRequired {
            action: "create onion service",
        })?;

        let (state_dir, mistrust) = config.state_dir()?;
        let state_dir =
            self::StateDirectory::new(state_dir, mistrust).map_err(ErrorDetail::StateAccess)?;

        Ok(tor_hsservice::OnionService::builder()
            .config(svc_config)
            .keymgr(keymgr.clone())
            .state_dir(state_dir)
            .build()
            .map_err(ErrorDetail::OnionServiceSetup)?)
    }
}

/// Preferences for whether a [`TorClient`] should bootstrap on its own or not.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootstrapBehavior {
    /// Bootstrap the client automatically when requests are made that require the client to be
    /// bootstrapped.
    #[default]
    OnDemand,
    /// Make no attempts to automatically bootstrap. [`TorClient::bootstrap`] must be manually
    /// invoked in order for the [`TorClient`] to become useful.
    ///
    /// Attempts to use the client (e.g. by creating connections or resolving hosts over the Tor
    /// network) before calling [`bootstrap`](TorClient::bootstrap) will fail, and
    /// return an error that has kind [`ErrorKind::BootstrapRequired`](crate::ErrorKind::BootstrapRequired).
    Manual,
}

/// A representation of whether a [`TorClient`] is allowed to bootstrap, and whether it
/// has begun to do so.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BootstrapSetting {
    /// The configured [`BootstrapBehavior`] for the `TorClient`.
    behavior: BootstrapBehavior,

    /// If true, we have a [`RunningInner`] in the `TorClient`,
    /// indicating that we are trying to bootstrap it.
    running_inner_is_present: bool,
}

impl Default for BootstrapSetting {
    fn default() -> Self {
        Self {
            behavior: BootstrapBehavior::Manual,
            running_inner_is_present: false,
        }
    }
}

impl BootstrapSetting {
    /// Return true if this [`BootstrapSetting`]
    /// indicates that the client is not trying to bootstrap,
    /// and will not try until it is told explicitly to do so.
    pub(crate) fn blocked(&self) -> bool {
        use BootstrapBehavior::*;
        match (self.behavior, self.running_inner_is_present) {
            (OnDemand, _) => false,
            (Manual, true) => false,
            (Manual, false) => true,
        }
    }
}

/// What level of sleep to put a Tor client into.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DormantMode {
    /// The client functions as normal, and background tasks run periodically.
    #[default]
    Normal,
    /// Background tasks are suspended, conserving CPU usage. Attempts to use the client will
    /// wake it back up again.
    Soft,
}

/// Preferences for how to route a stream over the Tor network.
#[derive(Debug, Default, Clone)]
pub struct StreamPrefs {
    /// What kind of IPv6/IPv4 we'd prefer, and how strongly.
    ip_ver_pref: IpVersionPreference,
    /// How should we isolate connection(s)?
    isolation: StreamIsolationPreference,
    /// Whether to return the stream optimistically.
    optimistic_stream: bool,
    // TODO GEOIP Ideally this would be unconditional, with CountryCode maybe being Void
    // This probably applies in many other places, so probably:   git grep 'cfg.*geoip'
    // and consider each one with a view to making it unconditional.  Background:
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537#note_2935256
    //   https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1537#note_2942214
    #[cfg(feature = "geoip")]
    /// A country to restrict the exit relay's location to.
    country_code: Option<CountryCode>,
    /// Whether to try to make connections to onion services.
    ///
    /// `Auto` means to use the client configuration.
    #[cfg(feature = "onion-service-client")]
    pub(crate) connect_to_onion_services: BoolOrAuto,
}

/// Record of how we are isolating connections
#[derive(Debug, Default, Clone)]
enum StreamIsolationPreference {
    /// No additional isolation
    #[default]
    None,
    /// Isolation parameter to use for connections
    Explicit(Box<dyn Isolation>),
    /// Isolate every connection!
    EveryStream,
}

impl From<DormantMode> for tor_chanmgr::Dormancy {
    fn from(dormant: DormantMode) -> tor_chanmgr::Dormancy {
        match dormant {
            DormantMode::Normal => tor_chanmgr::Dormancy::Active,
            DormantMode::Soft => tor_chanmgr::Dormancy::Dormant,
        }
    }
}
#[cfg(feature = "bridge-client")]
impl From<DormantMode> for tor_dirmgr::bridgedesc::Dormancy {
    fn from(dormant: DormantMode) -> tor_dirmgr::bridgedesc::Dormancy {
        match dormant {
            DormantMode::Normal => tor_dirmgr::bridgedesc::Dormancy::Active,
            DormantMode::Soft => tor_dirmgr::bridgedesc::Dormancy::Dormant,
        }
    }
}

impl StreamPrefs {
    /// Construct a new StreamPrefs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv6.
    pub fn ipv6_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv6.
    ///
    /// When this option is set, we will only pick exit relays that
    /// support IPv6, and we will tell them to only give us IPv6
    /// connections.
    pub fn ipv6_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv6Only;
        self
    }

    /// Indicate that a stream may be made over IPv4 or IPv6, but that
    /// we'd prefer IPv4.
    ///
    /// This is the default.
    pub fn ipv4_preferred(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Preferred;
        self
    }

    /// Indicate that a stream may only be made over IPv4.
    ///
    /// When this option is set, we will only pick exit relays that
    /// support IPv4, and we will tell them to only give us IPv4
    /// connections.
    pub fn ipv4_only(&mut self) -> &mut Self {
        self.ip_ver_pref = IpVersionPreference::Ipv4Only;
        self
    }

    /// Indicate that a stream should appear to come from the given country.
    ///
    /// When this option is set, we will only pick exit relays that
    /// have an IP address that matches the country in our GeoIP database.
    #[cfg(feature = "geoip")]
    pub fn exit_country(&mut self, country_code: CountryCode) -> &mut Self {
        self.country_code = Some(country_code);
        self
    }

    /// Indicate that we don't care which country a stream appears to come from.
    ///
    /// This is available even in the case where GeoIP support is compiled out,
    /// to make things easier.
    pub fn any_exit_country(&mut self) -> &mut Self {
        #[cfg(feature = "geoip")]
        {
            self.country_code = None;
        }
        self
    }

    /// Indicate that the stream should be opened "optimistically".
    ///
    /// By default, streams are not "optimistic". When you call
    /// [`TorClient::connect()`], it won't give you a stream until the
    /// exit node has confirmed that it has successfully opened a
    /// connection to your target address.  It's safer to wait in this
    /// way, but it is slower: it takes an entire round trip to get
    /// your confirmation.
    ///
    /// If a stream _is_ configured to be "optimistic", on the other
    /// hand, then `TorClient::connect()` will return the stream
    /// immediately, without waiting for an answer from the exit.  You
    /// can start sending data on the stream right away, though of
    /// course this data will be lost if the connection is not
    /// actually successful.
    pub fn optimistic(&mut self) -> &mut Self {
        self.optimistic_stream = true;
        self
    }

    /// Return true if this stream has been configured as "optimistic".
    ///
    /// See [`StreamPrefs::optimistic`] for more info.
    pub fn is_optimistic(&self) -> bool {
        self.optimistic_stream
    }

    /// Indicate whether connection to a hidden service (`.onion` service) should be allowed
    ///
    /// If `Explicit(false)`, attempts to connect to Onion Services will be forced to fail with
    /// an error of kind [`InvalidStreamTarget`](crate::ErrorKind::InvalidStreamTarget).
    ///
    /// If `Explicit(true)`, Onion Service connections are enabled.
    ///
    /// If `Auto`, the behaviour depends on the `address_filter.allow_onion_addrs`
    /// configuration option, which is in turn enabled by default.
    #[cfg(feature = "onion-service-client")]
    pub fn connect_to_onion_services(
        &mut self,
        connect_to_onion_services: BoolOrAuto,
    ) -> &mut Self {
        self.connect_to_onion_services = connect_to_onion_services;
        self
    }
    /// Return a TargetPort to describe what kind of exit policy our
    /// target circuit needs to support.
    fn wrap_target_port(&self, port: u16) -> TargetPort {
        match self.ip_ver_pref {
            IpVersionPreference::Ipv6Only => TargetPort::ipv6(port),
            _ => TargetPort::ipv4(port),
        }
    }

    /// Return a new StreamParameters based on this configuration.
    fn stream_parameters(&self) -> StreamParameters {
        let mut params = StreamParameters::default();
        params
            .ip_version(self.ip_ver_pref)
            .optimistic(self.optimistic_stream);
        params
    }

    /// Indicate that connections with these preferences should have their own isolation group
    ///
    /// This is a convenience method which creates a fresh [`IsolationToken`]
    /// and sets it for these preferences.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client`
    ///  will not share circuits with the original client, even if the same
    /// `isolation` is specified via the `ConnectionPrefs` in force.
    pub fn new_isolation_group(&mut self) -> &mut Self {
        self.isolation = StreamIsolationPreference::Explicit(Box::new(IsolationToken::new()));
        self
    }

    /// Indicate which other connections might use the same circuit
    /// as this one.
    ///
    /// By default all connections made on a `TorClient` may share connections.
    /// Connections made with a particular `isolation` may share circuits with each other.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client`
    /// will not share circuits with the original client, even if the same
    /// `isolation` is specified via the `ConnectionPrefs` in force.
    pub fn set_isolation<T>(&mut self, isolation: T) -> &mut Self
    where
        T: Into<Box<dyn Isolation>>,
    {
        self.isolation = StreamIsolationPreference::Explicit(isolation.into());
        self
    }

    /// Indicate that no connection should share a circuit with any other.
    ///
    /// **Use with care:** This is likely to have poor performance, and imposes a much greater load
    /// on the Tor network.  Use this option only to make small numbers of connections each of
    /// which needs to be isolated from all other connections.
    ///
    /// (Don't just use this as a "get more privacy!!" method: the circuits
    /// that it put connections on will have no more privacy than any other
    /// circuits.  The only benefit is that these circuits will not be shared
    /// by multiple streams.)
    ///
    /// This can be undone by calling `set_isolation` or `new_isolation_group` on these
    /// preferences.
    pub fn isolate_every_stream(&mut self) -> &mut Self {
        self.isolation = StreamIsolationPreference::EveryStream;
        self
    }

    /// Return an [`Isolation`] which separates according to these `StreamPrefs` (only)
    ///
    /// This describes which connections or operations might use
    /// the same circuit(s) as this one.
    ///
    /// Since this doesn't have access to the `TorClient`,
    /// it doesn't separate streams which ought to be separated because of
    /// the way their `TorClient`s are isolated.
    /// For that, use [`TorClient::isolation`].
    fn prefs_isolation(&self) -> Option<Box<dyn Isolation>> {
        use StreamIsolationPreference as SIP;
        match self.isolation {
            SIP::None => None,
            SIP::Explicit(ref ig) => Some(ig.clone()),
            SIP::EveryStream => Some(Box::new(IsolationToken::new())),
        }
    }

    // TODO: Add some way to be IPFlexible, and require exit to support both.
}

#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
impl TorClient<PreferredRuntime> {
    /// Bootstrap a connection to the Tor network, using the provided `config`.
    ///
    /// Returns a client once there is enough directory material to
    /// connect safely over the Tor network.
    ///
    /// Consider using [`TorClient::builder`] for more fine-grained control.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for [`PreferredRuntime::current`] for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorClient::with_runtime`].
    ///
    /// # Do not fork
    ///
    /// The process [**may not fork**](tor_rtcompat#do-not-fork)
    /// (except, very carefully, before exec)
    /// after calling this function, because it creates a [`PreferredRuntime`].
    pub async fn create_bootstrapped(config: TorClientConfig) -> crate::Result<Arc<Self>> {
        let runtime = PreferredRuntime::current()
            .expect("TorClient could not get an asynchronous runtime; are you running in the right context?");

        Self::with_runtime(runtime)
            .config(config)
            .create_bootstrapped()
            .await
    }

    /// Return a new builder for creating TorClient objects.
    ///
    /// If you want to make a [`TorClient`] synchronously, this is what you want; call
    /// `TorClientBuilder::create_unbootstrapped` on the returned builder.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for `tokio::runtime::Handle::current` for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorClient::with_runtime`].
    ///
    /// # Do not fork
    ///
    /// The process [**may not fork**](tor_rtcompat#do-not-fork)
    /// (except, very carefully, before exec)
    /// after calling this function, because it creates a [`PreferredRuntime`].
    pub fn builder() -> TorClientBuilder<PreferredRuntime> {
        let runtime = PreferredRuntime::current()
            .expect("TorClient could not get an asynchronous runtime; are you running in the right context?");

        TorClientBuilder::new(runtime)
    }
}

impl<R: Runtime> TorClient<R> {
    /// Return a new builder for creating TorClient objects, with a custom provided [`Runtime`].
    ///
    /// See the [`tor_rtcompat`] crate for more information on custom runtimes.
    pub fn with_runtime(runtime: R) -> TorClientBuilder<R> {
        TorClientBuilder::new(runtime)
    }

    /// Implementation of `create_unbootstrapped`, split out in order to avoid manually specifying
    /// double error conversions.
    #[instrument(skip_all, level = "trace")]
    pub(crate) fn create_impl(
        runtime: R,
        config: &TorClientConfig,
        autobootstrap: BootstrapBehavior,
        dirmgr_builder: Arc<dyn crate::builder::DirProviderBuilder<R>>,
        dirmgr_extensions: tor_dirmgr::config::DirMgrExtensions,
    ) -> StdResult<Arc<Self>, ErrorDetail> {
        if crate::util::running_as_setuid() {
            return Err(tor_error::bad_api_usage!(
                "Arti does not support running in a setuid or setgid context."
            )
            .into());
        }

        let memquota = MemoryQuotaTracker::new(&runtime, config.system.memory.clone())?;

        let path_resolver = Arc::new(config.path_resolver.clone());

        let (state_dir, mistrust) = config.state_dir()?;
        #[cfg(feature = "onion-service-service")]
        let state_directory =
            StateDirectory::new(&state_dir, mistrust).map_err(ErrorDetail::StateAccess)?;

        let dormant = DormantMode::Normal;

        let statemgr = Self::statemgr_from_config(config)?;

        // Try to take state ownership early, so we'll know if we have it.
        // Note that this `try_lock()` may return `Ok` even if we can't acquire the lock.
        // (At this point we don't yet care if we have it.)
        let _ignore_status = statemgr.try_lock().map_err(ErrorDetail::StateMgrSetup)?;

        let addr_cfg = config.address_filter.clone();

        let bootstrap_setting = BootstrapSetting {
            behavior: autobootstrap,
            running_inner_is_present: false,
        };
        let (bootstrap_setting_sender, bootstrap_setting_receiver) =
            postage::watch::channel_with(bootstrap_setting);
        let bootstrap_setting_sender = Mutex::new(bootstrap_setting_sender);
        let (status_sender, status_receiver) =
            postage::watch::channel_with(BootstrapStatus::from_setting(bootstrap_setting));
        let status_receiver = status::BootstrapEvents {
            inner: status_receiver,
        };
        let timeout_cfg = config.stream_timeouts.clone();

        let (dormant_send, dormant_recv) = postage::watch::channel_with(Some(dormant));
        let dormant_send = DropNotifyWatchSender::new(dormant_send);
        let client_isolation = IsolationToken::new();
        let inert_client = InertTorClient::new(config)?;

        let dirmgr_store = DirMgrStore::new(&config.dir_mgr_config()?, runtime.clone(), false)
            .map_err(ErrorDetail::DirMgrSetup)?;

        let inner = Box::new(NotConstructedInner {
            config: config.clone(),
            dormant_recv,
            status_sender,
            bootstrap_setting_receiver,
            dirmgr_builder,
            dirmgr_extensions,
        });

        let inner = Mutex::new(Inner::NotConstructed(inner));

        let client = Arc::new(ClientShared {
            runtime,
            inner,
            memquota,
            inert_client,
            statemgr,
            dirmgr_store,
            addrcfg: addr_cfg.into(),
            timeoutcfg: timeout_cfg.into(),
            reconfigure_lock: Arc::new(Mutex::new(())),
            status_receiver,
            bootstrap_in_progress: AsyncMutex::new(()),
            bootstrap_setting_sender,
            should_bootstrap: autobootstrap,
            dormant: Mutex::new(dormant_send),
            #[cfg(feature = "onion-service-service")]
            state_directory,
            path_resolver,
        });

        Ok(Arc::new(TorClient {
            client_isolation,
            connect_prefs: Default::default(),
            client,
        }))
    }

    /// Construct a state manager from the client configuration.
    fn statemgr_from_config(config: &TorClientConfig) -> Result<UsingStateMgr, ErrorDetail> {
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            use tor_persist::FsStateMgr;

            let (state_dir, mistrust) = config.state_dir()?;
            FsStateMgr::from_path_and_mistrust(state_dir, mistrust)
                .map_err(ErrorDetail::StateMgrSetup)
        }
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            unimplemented!()
        }
    }

    /// Bootstrap a connection to the Tor network, with a client created by `create_unbootstrapped`.
    ///
    /// Returns once there is enough directory material to connect safely over the Tor network.
    /// If the client has already been bootstrapped, returns immediately with
    /// success. If a bootstrap is in progress, waits for it to finish, then retries it if it
    /// failed (returning success if it succeeded).
    ///
    /// Bootstrap progress can be tracked by listening to the event receiver returned by
    /// [`bootstrap_events`](TorClient::bootstrap_events).
    ///
    /// # Failures
    ///
    /// If the bootstrapping process fails, returns an error. This function can safely be called
    /// again later to attempt to bootstrap another time.
    #[instrument(skip_all, level = "trace")]
    pub async fn bootstrap(&self) -> crate::Result<()> {
        self.client
            .bootstrap_inner()
            .await
            .map_err(ErrorDetail::into)
    }
}

impl<R: Runtime> NotConstructedInner<R> {
    /// Replace the configuration for this unconstructed client.
    ///
    /// Since most of the client's internals are not yet constructed,
    /// we can still replace nearly all of the items.
    fn reconfigure(
        &mut self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> StdResult<(), ErrorDetail> {
        // We _do_ have to check the cache_dir, since we can't and won't change that
        // while we're running.
        // (We already checked the state_dir in ClientShared::reconfigure_inner.)
        if new_config.storage.cache_dir != self.config.storage.cache_dir {
            how.cannot_change("storage.cache_dir")?;
        }

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        self.config = new_config.clone();

        Ok(())
    }
}

impl<R: Runtime> RunningInner<R> {
    /// Construct a new [`RunningInner`] and launch its associated tasks.
    fn new(
        pending: NotConstructedInner<R>,
        client: &ClientShared<R>,
    ) -> StdResult<Arc<Self>, ErrorDetail> {
        let NotConstructedInner {
            config,
            dormant_recv,
            status_sender,
            bootstrap_setting_receiver,
            dirmgr_builder,
            dirmgr_extensions,
        } = pending;

        let runtime = client.runtime.clone();
        let dormant = dormant_recv
            .borrow()
            .expect("Client somehow dropped while creating RunningInner");
        let memquota = &client.memquota;
        let statemgr = &client.statemgr;
        let path_resolver = &client.path_resolver;
        let (state_dir, _) = config.state_dir()?;

        let chanmgr = Arc::new(
            tor_chanmgr::ChanMgr::new(
                runtime.clone(),
                ChanMgrConfig::new(config.channel.clone()),
                dormant.into(),
                &NetParameters::from_map(&config.override_net_params),
                memquota.clone(),
            )
            .map_err(ErrorDetail::ChanMgrSetup)?,
        );
        let guardmgr = tor_guardmgr::GuardMgr::new(runtime.clone(), statemgr.clone(), &config)
            .map_err(ErrorDetail::GuardMgrSetup)?;

        #[cfg(feature = "pt-client")]
        let pt_mgr = {
            let pt_state_dir = state_dir.as_path().join("pt_state");
            config.storage.permissions().make_directory(&pt_state_dir)?;

            let mgr = Arc::new(tor_ptmgr::PtMgr::new(
                config.bridges.transports.clone(),
                pt_state_dir,
                Arc::clone(path_resolver),
                config.channel.outbound_proxy().cloned(),
                runtime.clone(),
            )?);

            chanmgr.set_pt_mgr(mgr.clone());

            mgr
        };

        let circmgr = Arc::new(
            tor_circmgr::CircMgr::new(
                &config,
                statemgr.clone(),
                &runtime,
                Arc::clone(&chanmgr),
                &guardmgr,
            )
            .map_err(ErrorDetail::CircMgrSetup)?,
        );

        let dir_cfg = {
            let mut c: tor_dirmgr::DirMgrConfig = config.dir_mgr_config()?;
            c.extensions = dirmgr_extensions;
            c
        };
        let dirmgr = dirmgr_builder
            .build(
                runtime.clone(),
                client.dirmgr_store.clone(),
                Arc::clone(&circmgr),
                dir_cfg,
            )
            .map_err(crate::Error::into_detail)?;

        let mut periodic_task_handles = circmgr
            .launch_background_tasks(&runtime, &dirmgr, statemgr.clone())
            .map_err(ErrorDetail::CircMgrSetup)?;
        periodic_task_handles.extend(dirmgr.download_task_handle());

        periodic_task_handles.extend(
            chanmgr
                .launch_background_tasks(&runtime, dirmgr.clone().upcast_arc())
                .map_err(ErrorDetail::ChanMgrSetup)?,
        );

        #[cfg(feature = "bridge-client")]
        // TODO: We can just construct this.
        let bridge_desc_mgr = Arc::new(Mutex::new(None));

        #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
        let hs_circ_pool = {
            let circpool = Arc::new(tor_circmgr::hspool::HsCircPool::new(&circmgr));
            circpool
                .launch_background_tasks(&runtime, &dirmgr.clone().upcast_arc())
                .map_err(ErrorDetail::CircMgrSetup)?;
            circpool
        };

        #[cfg(feature = "onion-service-client")]
        let hsclient = {
            // Prompt the hs connector to do its data housekeeping when we get a new consensus.
            // That's a time we're doing a bunch of thinking anyway, and it's not very frequent.
            let housekeeping = dirmgr.events().filter_map(|event| async move {
                match event {
                    DirEvent::NewConsensus => Some(()),
                    _ => None,
                }
            });
            let housekeeping = Box::pin(housekeeping);

            HsClientConnector::new(runtime.clone(), hs_circ_pool.clone(), &config, housekeeping)?
        };
        let conn_status = chanmgr.bootstrap_events();
        let dir_status = dirmgr.bootstrap_events();
        let skew_status = circmgr.skew_events();

        let rtclone = runtime.clone();

        // TODO: It might be a good idea to check this earlier, in `create_impl`,
        // when we have only the DirMgrStore.
        // But if we do that we need to add a method to DirMgrStore
        // to look at the protocol recommentations.
        #[allow(clippy::print_stderr)]
        crate::protostatus::enforce_protocol_recommendations(
            &runtime,
            Arc::clone(&dirmgr),
            crate::software_release_date(),
            crate::supported_protocols(),
            // TODO #1932: It would be nice to have a cleaner shutdown mechanism here,
            // but that will take some work.
            |fatal| async move {
                use tor_error::ErrorReport as _;
                // We already logged this error, but let's tell stderr too.
                eprintln!(
                    "Shutting down because of unsupported software version.\nError was:\n{}",
                    fatal.report(),
                );
                if let Some(hint) = crate::err::Error::from(fatal).hint() {
                    eprintln!("{}", hint);
                }
                // Give the tracing module a while to flush everything, since it has no built-in
                // flush function.
                rtclone.sleep(std::time::Duration::new(5, 0)).await;
                std::process::exit(1);
            },
        )?;

        runtime
            .spawn(status::report_status(
                status_sender,
                conn_status,
                dir_status,
                skew_status,
                bootstrap_setting_receiver,
            ))
            .map_err(|e| ErrorDetail::from_spawn("top-level status reporter", e))?;

        runtime
            .spawn(tasks_monitor_dormant(
                dormant_recv.clone(),
                dirmgr.clone().upcast_arc(),
                chanmgr.clone(),
                #[cfg(feature = "bridge-client")]
                bridge_desc_mgr.clone(),
                periodic_task_handles,
            ))
            .map_err(|e| ErrorDetail::from_spawn("periodic task dormant monitor", e))?;

        let running_inner = Arc::new(RunningInner {
            chanmgr,
            circmgr,
            dirmgr,
            #[cfg(feature = "bridge-client")]
            bridge_desc_mgr,
            #[cfg(feature = "pt-client")]
            pt_mgr,
            #[cfg(feature = "onion-service-client")]
            hsclient,
            #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
            hs_circ_pool,
            guardmgr,
        });

        Ok(running_inner)
    }

    /// Tell the parts of this [`RunningInner`] to reconfigure themselves
    /// (or to check the new configuration, if `how == CheckAllOrNothing`).
    fn reconfigure(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> crate::Result<()> {
        let dir_cfg = new_config.dir_mgr_config().map_err(wrap_err)?;

        let retire_circuits = self
            .circmgr
            .reconfigure(new_config, how)
            .map_err(wrap_err)?;

        #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
        if retire_circuits != RetireCircuits::None {
            self.hs_circ_pool.retire_all_circuits().map_err(wrap_err)?;
        }

        self.dirmgr.reconfigure(&dir_cfg, how).map_err(wrap_err)?;

        let netparams = self.dirmgr.params();

        self.chanmgr
            .reconfigure(&new_config.channel, how, netparams)
            .map_err(wrap_err)?;

        #[cfg(feature = "pt-client")]
        self.pt_mgr
            .reconfigure(
                how,
                new_config.bridges.transports.clone(),
                new_config.channel.outbound_proxy().cloned(),
            )
            .map_err(wrap_err)?;

        Ok(())
    }
}

impl<R: Runtime> TorClient<R> {
    /// Change the configuration of this TorClient to `new_config`.
    ///
    /// The `how` describes whether to perform an all-or-nothing
    /// reconfiguration: either all of the configuration changes will be
    /// applied, or none will. If you have disabled all-or-nothing changes, then
    /// only fatal errors will be reported in this function's return value.
    ///
    /// When performing a reconfiguration,
    /// a returned error may indicate that the client is now in an inconsistent state.
    ///
    /// This function applies its changes to **all** TorClient instances derived
    /// from the same call to `TorClient::create_*`: even ones whose circuits
    /// are isolated from this handle.
    ///
    /// # Limitations
    ///
    /// Although most options are reconfigurable, there are some whose values
    /// can't be changed on an a running TorClient.  Those options (or their
    /// sections) are explicitly documented not to be changeable.
    /// NOTE: Currently, not all of these non-reconfigurable options are
    /// documented. See [arti#1721][arti-1721].
    ///
    /// [arti-1721]: https://gitlab.torproject.org/tpo/core/arti/-/issues/1721
    ///
    /// Changing some options do not take effect immediately on all open streams
    /// and circuits, but rather affect only future streams and circuits.  Those
    /// are also explicitly documented.
    #[instrument(skip_all, level = "trace")]
    pub fn reconfigure(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
    ) -> crate::Result<()> {
        // We need to hold this lock while we're reconfiguring the client: even
        // though the individual fields have their own synchronization, we can't
        // safely let two threads change them at once.  If we did, then we'd
        // introduce time-of-check/time-of-use bugs in checking our configuration,
        // deciding how to change it, then applying the changes.
        let guard = self.client.reconfigure_lock.lock().expect("Poisoned lock");

        use tor_config::Reconfigure::*;

        match how {
            AllOrNothing => {
                // We have to check before we make any changes.
                self.client
                    .reconfigure_inner(new_config, CheckAllOrNothing, &guard)?;

                // Hopefully this doesn't fail,
                // otherwise we may have returned early from the reconfiguration
                // and its no longer "all-or-nothing".
                let result = self
                    .client
                    .reconfigure_inner(new_config, AllOrNothing, &guard);

                if result.is_err() {
                    warn!(
                        "Attempted an \"all-or-nothing\" reconfigure, but unexpectedly failed. \
                        The client will continue to run in an inconsistent state."
                    );
                }

                result
            }
            WarnOnFailures => {
                let result = self.client.reconfigure_inner(new_config, how, &guard);

                // If there's a fatal error,
                // we may have reconfigured some components and not others.
                if result.is_err() {
                    warn!(
                        "Attempted a reconfigure, but failed. \
                        The client will continue to run in an inconsistent state."
                    );
                }

                result
            }
            CheckAllOrNothing => self.client.reconfigure_inner(new_config, how, &guard),
            _ => self.client.reconfigure_inner(new_config, how, &guard),
        }
    }

    /// Return a new isolated `TorClient` handle.
    ///
    /// The two `TorClient`s will share internal state and configuration, but
    /// their streams will never share circuits with one another.
    ///
    /// Use this function when you want separate parts of your program to
    /// each have a TorClient handle, but where you don't want their
    /// activities to be linkable to one another over the Tor network.
    ///
    /// Calling this function is usually preferable to creating a
    /// completely separate TorClient instance, since it can share its
    /// internals with the existing `TorClient`.
    #[must_use]
    pub fn isolated_client(&self) -> Arc<TorClient<R>> {
        let result = TorClient {
            client_isolation: IsolationToken::new(),
            connect_prefs: self.connect_prefs.clone(),
            client: Arc::clone(&self.client),
        };
        Arc::new(result)
    }

    /// Launch an anonymized connection to the provided address and port over
    /// the Tor network.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote side of
    /// the network, this function takes its address as a string:
    ///
    /// ```no_run
    /// # use arti_client::*;use tor_rtcompat::Runtime;
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// // The most usual way to connect is via an address-port tuple.
    /// let socket = tor_client.connect(("www.example.com", 443)).await?;
    ///
    /// // You can also specify an address and port as a colon-separated string.
    /// let socket = tor_client.connect("www.example.com:443").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Hostnames are _strongly_ preferred here: if this function allowed the
    /// caller here to provide an IPAddr or [`IpAddr`] or
    /// [`SocketAddr`](std::net::SocketAddr) address, then
    ///
    /// ```no_run
    /// # use arti_client::*; use tor_rtcompat::Runtime;
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// # use std::net::ToSocketAddrs;
    /// // BAD: We're about to leak our target address to the local resolver!
    /// let address = "www.example.com:443".to_socket_addrs().unwrap().next().unwrap();
    /// // 🤯 Oh no! Now any eavesdropper can tell where we're about to connect! 🤯
    ///
    /// // Fortunately, this won't compile, since SocketAddr doesn't implement IntoTorAddr.
    /// // let socket = tor_client.connect(address).await?;
    /// //                                 ^^^^^^^ the trait `IntoTorAddr` is not implemented for `std::net::SocketAddr`
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If you really do need to connect to an IP address rather than a
    /// hostname, and if you're **sure** that the IP address came from a safe
    /// location, there are a few ways to do so.
    ///
    /// ```no_run
    /// # use arti_client::{TorClient,Result};use tor_rtcompat::Runtime;
    /// # use std::net::{SocketAddr,IpAddr};
    /// # async fn ex<R:Runtime>(tor_client: TorClient<R>) -> Result<()> {
    /// # use std::net::ToSocketAddrs;
    /// // ⚠️This is risky code!⚠️
    /// // (Make sure your addresses came from somewhere safe...)
    ///
    /// // If we have a fixed address, we can just provide it as a string.
    /// let socket = tor_client.connect("192.0.2.22:443").await?;
    /// let socket = tor_client.connect(("192.0.2.22", 443)).await?;
    ///
    /// // If we have a SocketAddr or an IpAddr, we can use the
    /// // DangerouslyIntoTorAddr trait.
    /// use arti_client::DangerouslyIntoTorAddr;
    /// let sockaddr = SocketAddr::from(([192, 0, 2, 22], 443));
    /// let ipaddr = IpAddr::from([192, 0, 2, 22]);
    /// let socket = tor_client.connect(sockaddr.into_tor_addr_dangerously().unwrap()).await?;
    /// let socket = tor_client.connect((ipaddr, 443).into_tor_addr_dangerously().unwrap()).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip_all, level = "trace")]
    pub async fn connect<A: IntoTorAddr>(&self, target: A) -> crate::Result<DataStream> {
        self.connect_with_prefs(target, &self.connect_prefs).await
    }

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network, with explicit connection preferences.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    /// (See [`TorClient::connect()`] for more information.)
    #[instrument(skip_all, level = "trace")]
    pub async fn connect_with_prefs<A: IntoTorAddr>(
        &self,
        target: A,
        prefs: &StreamPrefs,
    ) -> crate::Result<DataStream> {
        let addr = target.into_tor_addr().map_err(wrap_err)?;
        let mut stream_parameters = prefs.stream_parameters();
        // This macro helps prevent code duplication in the match below.
        //
        // Ideally, the match should resolve to a tuple consisting of the
        // tunnel, and the address, port and stream params,
        // but that's not currently possible because
        // the Exit and Hs branches use different tunnel types.
        //
        // TODO: replace with an async closure (when our MSRV allows it),
        // or with a more elegant approach.
        macro_rules! begin_stream {
            ($tunnel:expr, $addr:expr, $port:expr, $stream_params:expr) => {{
                let fut = $tunnel.begin_stream($addr, $port, $stream_params);
                self.client
                    .runtime
                    .timeout(self.client.timeoutcfg.get().connect_timeout, fut)
                    .await
                    .map_err(|_| ErrorDetail::ExitTimeout)?
                    .map_err(|cause| ErrorDetail::StreamFailed {
                        cause,
                        kind: "data",
                    })
            }};
        }

        let stream = match addr.into_stream_instructions(&self.client.addrcfg.get(), prefs)? {
            StreamInstructions::Exit {
                hostname: addr,
                port,
            } => {
                let exit_ports = [prefs.wrap_target_port(port)];
                let tunnel = self
                    .get_or_launch_exit_tunnel(&exit_ports, prefs)
                    .await
                    .map_err(wrap_err)?;
                debug!(
                    tunnel_id = %tunnel.unique_id(),
                    "Got a circuit for {}:{}", sensitive(&addr), port);

                begin_stream!(tunnel, &addr, port, Some(stream_parameters))
            }

            #[cfg(not(feature = "onion-service-client"))]
            #[allow(unused_variables)] // for hostname and port
            StreamInstructions::Hs {
                hsid,
                hostname,
                port,
            } => void::unreachable(hsid.0),

            #[cfg(feature = "onion-service-client")]
            StreamInstructions::Hs {
                hsid,
                hostname,
                port,
            } => {
                use safelog::DisplayRedacted as _;

                let running = self
                    .client
                    .wait_for_bootstrap_running("connect to hidden service")
                    .await?;

                let netdir = self.netdir(Timeliness::Timely, "connect to a hidden service")?;

                let mut hs_client_secret_keys_builder = HsClientSecretKeysBuilder::default();

                if let Some(keymgr) = &self.client.inert_client.keymgr {
                    let desc_enc_key_spec = HsClientDescEncKeypairSpecifier::new(hsid);

                    let ks_hsc_desc_enc =
                        keymgr.get::<HsClientDescEncKeypair>(&desc_enc_key_spec)?;

                    if let Some(ks_hsc_desc_enc) = ks_hsc_desc_enc {
                        debug!(
                            "Found descriptor decryption key for {}",
                            hsid.display_redacted()
                        );
                        hs_client_secret_keys_builder.ks_hsc_desc_enc(ks_hsc_desc_enc);
                    }
                };

                let hs_client_secret_keys = hs_client_secret_keys_builder
                    .build()
                    .map_err(ErrorDetail::Configuration)?;

                let tunnel = running
                    .hsclient
                    .get_or_launch_tunnel(
                        &netdir,
                        hsid,
                        hs_client_secret_keys,
                        self.isolation(prefs),
                    )
                    .await
                    .map_err(|cause| ErrorDetail::ObtainHsCircuit { cause, hsid })?;
                // On connections to onion services, we have to suppress
                // everything except the port from the BEGIN message.  We also
                // disable optimistic data.
                stream_parameters
                    .suppress_hostname()
                    .suppress_begin_flags()
                    .optimistic(false);

                begin_stream!(tunnel, &hostname, port, Some(stream_parameters))
            }
        };

        Ok(stream?)
    }

    /// Provides a new handle on this client, but with adjusted default preferences.
    ///
    /// Connections made with e.g. [`connect`](TorClient::connect) on the returned handle will use
    /// `connect_prefs`.
    #[must_use]
    pub fn with_prefs(&self, connect_prefs: StreamPrefs) -> Arc<Self> {
        let result = TorClient {
            client_isolation: self.client_isolation,
            connect_prefs,
            client: Arc::clone(&self.client),
        };
        Arc::new(result)
    }

    /// On success, return a list of IP addresses.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve(&self, hostname: &str) -> crate::Result<Vec<IpAddr>> {
        self.resolve_with_prefs(hostname, &self.connect_prefs).await
    }

    /// On success, return a list of IP addresses, but use prefs.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<IpAddr>> {
        // TODO This dummy port is only because `address::Host` is not pub(crate),
        // but I see no reason why it shouldn't be?  Then `into_resolve_instructions`
        // should be a method on `Host`, not `TorAddr`.  -Diziet.
        let addr = (hostname, 1).into_tor_addr().map_err(wrap_err)?;

        match addr.into_resolve_instructions(&self.client.addrcfg.get(), prefs)? {
            ResolveInstructions::Exit(hostname) => {
                let circ = self.get_or_launch_exit_tunnel(&[], prefs).await?;

                let resolve_future = circ.resolve(&hostname);
                let addrs = self
                    .client
                    .runtime
                    .timeout(self.client.timeoutcfg.get().resolve_timeout, resolve_future)
                    .await
                    .map_err(|_| ErrorDetail::ExitTimeout)?
                    .map_err(|cause| ErrorDetail::StreamFailed {
                        cause,
                        kind: "DNS lookup",
                    })?;

                Ok(addrs)
            }
            ResolveInstructions::Return(addrs) => Ok(addrs),
        }
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    #[instrument(skip_all, level = "trace")]
    pub async fn resolve_ptr(&self, addr: IpAddr) -> crate::Result<Vec<String>> {
        self.resolve_ptr_with_prefs(addr, &self.connect_prefs).await
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    #[instrument(level = "trace", skip_all)]
    pub async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<String>> {
        let circ = self.get_or_launch_exit_tunnel(&[], prefs).await?;

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .client
            .runtime
            .timeout(
                self.client.timeoutcfg.get().resolve_ptr_timeout,
                resolve_ptr_future,
            )
            .await
            .map_err(|_| ErrorDetail::ExitTimeout)?
            .map_err(|cause| ErrorDetail::StreamFailed {
                cause,
                kind: "reverse DNS lookup",
            })?;

        Ok(hostnames)
    }

    /// Return a reference to this client's directory manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn dirmgr(&self) -> crate::Result<Arc<dyn tor_dirmgr::DirProvider>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .dirmgr
            .clone())
    }

    /// Return a reference to this client's circuit manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn circmgr(&self) -> crate::Result<Arc<tor_circmgr::CircMgr<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .circmgr
            .clone())
    }

    /// Return a reference to this client's channel manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn chanmgr(&self) -> crate::Result<Arc<tor_chanmgr::ChanMgr<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .chanmgr
            .clone())
    }

    /// Return a reference to this client's circuit pool.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature and any of `onion-service-client`
    /// or `onion-service-service` features. This method is required to invoke
    /// tor_hsservice::OnionService::launch()
    #[cfg(all(
        feature = "experimental-api",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    pub fn hs_circ_pool(&self) -> crate::Result<Arc<tor_circmgr::hspool::HsCircPool<R>>> {
        Ok(self
            .client
            .running_inner("access internal functionality")?
            .hs_circ_pool
            .clone())
    }

    /// Return a reference to the runtime being used by this client.
    //
    // This API is not a hostage to fortune since we already require that R: Clone,
    // and necessarily a TorClient must have a clone of it.
    //
    // We provide it simply to save callers who have a TorClient from
    // having to separately keep their own handle,
    pub fn runtime(&self) -> &R {
        &self.client.runtime
    }

    /// Return a netdir that is timely according to the rules of `timeliness`.
    ///
    /// The `action` string is a description of what we wanted to do with the
    /// directory, to be put into the error message if we couldn't find a directory.
    fn netdir(
        &self,
        timeliness: Timeliness,
        action: &'static str,
    ) -> StdResult<Arc<tor_netdir::NetDir>, ErrorDetail> {
        use tor_netdir::Error as E;
        // TODO: Conceivably we could take a NetDir from our DirMgrStore.
        match self.client.running_inner(action)?.dirmgr.netdir(timeliness) {
            Ok(netdir) => Ok(netdir),
            Err(E::NoInfo) | Err(E::NotEnoughInfo) => {
                Err(ErrorDetail::BootstrapRequired { action })
            }
            Err(error) => Err(ErrorDetail::NoDir { error, action }),
        }
    }

    /// Get or launch an exit-suitable circuit with a given set of
    /// exit ports.
    #[instrument(skip_all, level = "trace")]
    async fn get_or_launch_exit_tunnel(
        &self,
        exit_ports: &[TargetPort],
        prefs: &StreamPrefs,
    ) -> StdResult<ClientDataTunnel, ErrorDetail> {
        let running = self
            .client
            .wait_for_bootstrap_running("build a circuit")
            .await?;
        // TODO HS probably this netdir ought to be made in connect_with_prefs
        // like for StreamInstructions::Hs.
        let dir = self.netdir(Timeliness::Timely, "build a circuit")?;

        let tunnel = running
            .circmgr
            .get_or_launch_exit(
                dir.as_ref().into(),
                exit_ports,
                self.isolation(prefs),
                #[cfg(feature = "geoip")]
                prefs.country_code,
            )
            .await
            .map_err(|cause| ErrorDetail::ObtainExitCircuit {
                cause,
                exit_ports: Sensitive::new(exit_ports.into()),
            })?;
        drop(dir); // This decreases the refcount on the netdir.

        Ok(tunnel)
    }

    /// Return an overall [`Isolation`] for this `TorClient` and a `StreamPrefs`.
    ///
    /// This describes which operations might use
    /// circuit(s) with this one.
    ///
    /// This combines isolation information from
    /// [`StreamPrefs::prefs_isolation`]
    /// and the `TorClient`'s isolation (eg from [`TorClient::isolated_client`]).
    fn isolation(&self, prefs: &StreamPrefs) -> StreamIsolation {
        let mut b = StreamIsolationBuilder::new();
        // Always consider our client_isolation.
        b.owner_token(self.client_isolation);
        // Consider stream isolation too, if it's set.
        if let Some(tok) = prefs.prefs_isolation() {
            b.stream_isolation(tok);
        }
        // Failure should be impossible with this builder.
        b.build().expect("Failed to construct StreamIsolation")
    }

    /// Try to launch an onion service with a given configuration.
    ///
    /// Returns `Ok(None)` if the service specified is disabled in the config.
    ///
    /// This onion service will not actually handle any requests on its own: you
    /// will need to
    /// pull [`RendRequest`](tor_hsservice::RendRequest) objects from the returned stream,
    /// [`accept`](tor_hsservice::RendRequest::accept) the ones that you want to
    /// answer, and then wait for them to give you [`StreamRequest`](tor_hsservice::StreamRequest)s.
    ///
    /// You may find the [`tor_hsservice::handle_rend_requests`] API helpful for
    /// translating `RendRequest`s into `StreamRequest`s.
    ///
    /// If you want to forward all the requests from an onion service to a set
    /// of local ports, you may want to use the `tor-hsrproxy` crate.
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn launch_onion_service(
        &self,
        config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<
        Option<(
            Arc<tor_hsservice::RunningOnionService>,
            impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,
        )>,
    > {
        let nickname = config.nickname();

        if !config.enabled() {
            info!(
                nickname=%nickname,
                "Skipping onion service because it was disabled in the config"
            );
            return Ok(None);
        }

        let running = self
            .client
            .initiate_bootstrap_if_needed("launch onion service")?;

        let keymgr = self
            .client
            .inert_client
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "launch onion service",
            })?
            .clone();
        let state_dir = self.client.state_directory.clone();

        let service = tor_hsservice::OnionService::builder()
            .config(config) // TODO #1186: Allow override of KeyMgr for "ephemeral" operation?
            .keymgr(keymgr)
            // TODO #1186: Allow override of StateMgr for "ephemeral" operation?
            .state_dir(state_dir)
            .build()
            .map_err(ErrorDetail::LaunchOnionService)?;
        Ok(service
            .launch(
                self.client.runtime.clone(),
                running.dirmgr.clone().upcast_arc(),
                running.hs_circ_pool.clone(),
                Arc::clone(&self.client.path_resolver),
            )
            .map_err(ErrorDetail::LaunchOnionService)?)
    }

    /// Try to launch an onion service with a given configuration and provided
    /// [`HsIdKeypair`]. If an onion service with the given nickname already has an
    /// associated `HsIdKeypair`  in this `TorClient`'s `KeyMgr`, then this operation
    /// fails rather than overwriting the existing key.
    ///
    /// Returns `Ok(None)` if the service specified is disabled in the config.
    ///
    /// The specified `HsIdKeypair` will be inserted in the primary keystore.
    ///
    /// **Important**: depending on the configuration of your
    /// [primary keystore](tor_keymgr::config::PrimaryKeystoreConfig),
    /// the `HsIdKeypair` **may** get persisted to disk.
    /// By default, Arti's primary keystore is the [native](ArtiKeystoreKind::Native),
    /// disk-based keystore.
    ///
    /// This onion service will not actually handle any requests on its own: you
    /// will need to
    /// pull [`RendRequest`](tor_hsservice::RendRequest) objects from the returned stream,
    /// [`accept`](tor_hsservice::RendRequest::accept) the ones that you want to
    /// answer, and then wait for them to give you [`StreamRequest`](tor_hsservice::StreamRequest)s.
    ///
    /// You may find the [`tor_hsservice::handle_rend_requests`] API helpful for
    /// translating `RendRequest`s into `StreamRequest`s.
    ///
    /// If you want to forward all the requests from an onion service to a set
    /// of local ports, you may want to use the `tor-hsrproxy` crate.
    #[cfg(all(feature = "onion-service-service", feature = "experimental-api"))]
    #[instrument(skip_all, level = "trace")]
    pub fn launch_onion_service_with_hsid(
        &self,
        config: tor_hsservice::OnionServiceConfig,
        id_keypair: HsIdKeypair,
    ) -> crate::Result<
        Option<(
            Arc<tor_hsservice::RunningOnionService>,
            impl futures::Stream<Item = tor_hsservice::RendRequest> + use<R>,
        )>,
    > {
        let nickname = config.nickname();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let selector = KeystoreSelector::Primary;

        let _kp = self
            .client
            .inert_client
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "launch onion service ex",
            })?
            .insert::<HsIdKeypair>(id_keypair, &hsid_spec, selector, false)?;

        self.launch_onion_service(config)
    }

    /// Generate a service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to generate the
    /// keypair in it, you can do so by calling this function with a [KeystoreSelector::Id]
    /// specifying the keystore ID of your keystore.
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Returns an error if the key already exists in the specified key store.
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    //
    // TODO: decide whether this should use get_or_generate before making it
    // non-experimental
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    pub fn generate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client
            .inert_client
            .generate_service_discovery_key(selector, hsid)
    }

    /// Rotate the service discovery keypair for connecting to a hidden service running in
    /// "restricted discovery" mode.
    ///
    /// **If the specified keystore already contains a restricted discovery keypair
    /// for the service, it will be overwritten.** Otherwise, a new keypair is generated.
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to generate the
    /// keypair in it, you can do so by calling this function with a [KeystoreSelector::Id]
    /// specifying the keystore ID of your keystore.
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn rotate_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client
            .inert_client
            .rotate_service_discovery_key(selector, hsid)
    }

    /// Insert a service discovery secret key for connecting to a hidden service running in
    /// "restricted discovery" mode
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to insert the
    /// key in it, you can do so by calling this function with a [KeystoreSelector::Id]
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    ///
    /// Returns an error if the key already exists in the specified key store.
    ///
    /// Important: the public part of the generated keypair must be shared with the service, and
    /// the service needs to be configured to allow the owner of its private counterpart to
    /// discover its introduction points. The caller is responsible for sharing the public part of
    /// the key with the hidden service.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn insert_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
        hs_client_desc_enc_secret_key: HsClientDescEncSecretKey,
    ) -> crate::Result<HsClientDescEncKey> {
        self.client.inert_client.insert_service_discovery_key(
            selector,
            hsid,
            hs_client_desc_enc_secret_key,
        )
    }

    /// Return the service discovery public key for the service with the specified `hsid`.
    ///
    /// Returns `Ok(None)` if no such key exists.
    ///
    /// This function does not require the `TorClient` to be running or bootstrapped.
    #[cfg(all(feature = "onion-service-client", feature = "experimental-api"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(feature = "onion-service-client", feature = "experimental-api")))
    )]
    pub fn get_service_discovery_key(
        &self,
        hsid: HsId,
    ) -> crate::Result<Option<HsClientDescEncKey>> {
        self.client.inert_client.get_service_discovery_key(hsid)
    }

    /// Removes the service discovery keypair for the service with the specified `hsid`.
    ///
    /// Returns an error if the selected keystore is not the default keystore or one of the
    /// configured secondary stores.
    ///
    /// Returns `Ok(None)` if no such keypair exists whereas `Ok(Some()) means the keypair was successfully removed.
    ///
    /// Returns `Err` if an error occurred while trying to remove the key.
    #[cfg(all(
        feature = "onion-service-client",
        feature = "experimental-api",
        feature = "keymgr"
    ))]
    #[cfg_attr(
        docsrs,
        doc(cfg(all(
            feature = "onion-service-client",
            feature = "experimental-api",
            feature = "keymgr"
        )))
    )]
    pub fn remove_service_discovery_key(
        &self,
        selector: KeystoreSelector,
        hsid: HsId,
    ) -> crate::Result<Option<()>> {
        self.client
            .inert_client
            .remove_service_discovery_key(selector, hsid)
    }

    /// Create (but do not launch) a new
    /// [`OnionService`](tor_hsservice::OnionService)
    /// using the given configuration.
    ///
    /// This is useful for managing an onion service without needing to start a `TorClient` or the
    /// onion service itself.
    /// If you only wish to run the onion service, see
    /// [`TorClient::launch_onion_service()`]
    /// which allows you to launch an onion service from a running `TorClient`.
    ///
    /// The returned `OnionService` can be launched using
    /// [`OnionService::launch()`](tor_hsservice::OnionService::launch).
    /// Note that `launch()` requires a [`NetDirProvider`],
    /// [`HsCircPool`](tor_circmgr::hspool::HsCircPool), etc,
    /// which you should obtain from a running `TorClient`.
    /// But these are only accessible from a `TorClient` if the "experimental-api" feature is
    /// enabled.
    /// The behaviour is not specified if you create the `OnionService` with
    /// `create_onion_service()` using one [`TorClientConfig`],
    /// but launch it using a `TorClient` generated from a different `TorClientConfig`.
    // TODO #2249: Look into this behaviour more, and possibly error if there is a different config.
    #[cfg(feature = "onion-service-service")]
    #[instrument(skip_all, level = "trace")]
    pub fn create_onion_service(
        config: &TorClientConfig,
        svc_config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<tor_hsservice::OnionService> {
        let inert_client = InertTorClient::new(config)?;
        inert_client.create_onion_service(config, svc_config)
    }

    /// Return a current [`status::BootstrapStatus`] describing how close this client
    /// is to being ready for user traffic.
    pub fn bootstrap_status(&self) -> status::BootstrapStatus {
        self.client.status_receiver.inner.borrow().clone()
    }

    /// Return a stream of [`status::BootstrapStatus`] events that will be updated
    /// whenever the client's status changes.
    ///
    /// The receiver might not receive every update sent to this stream, though
    /// when it does poll the stream it should get the most recent one.
    //
    // TODO(nickm): will this also need to implement Send and 'static?
    pub fn bootstrap_events(&self) -> status::BootstrapEvents {
        self.client.status_receiver.clone()
    }

    /// Change the client's current dormant mode, putting background tasks to sleep
    /// or waking them up as appropriate.
    ///
    /// This can be used to conserve CPU usage if you aren't planning on using the
    /// client for a while, especially on mobile platforms.
    ///
    /// See the [`DormantMode`] documentation for more details.
    pub fn set_dormant(&self, mode: DormantMode) {
        *self
            .client
            .dormant
            .lock()
            .expect("dormant lock poisoned")
            .borrow_mut() = Some(mode);
    }

    /// Return a [`Future`] which resolves
    /// once this TorClient has stopped.
    #[cfg(feature = "experimental-api")]
    #[instrument(skip_all, level = "trace")]
    pub fn wait_for_stop(
        &self,
    ) -> impl futures::Future<Output = ()> + Send + Sync + 'static + use<R> {
        // We defer to the "wait for unlock" handle on our statemgr.
        //
        // The statemgr won't actually be unlocked until it is finally
        // dropped, which will happen when this TorClient is
        // dropped—which is what we want.
        self.client.statemgr.wait_for_unlock()
    }

    /// Getter for keymgr.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn keymgr(&self) -> crate::Result<&KeyMgr> {
        self.client.inert_client.keymgr()
    }
}

impl<R: Runtime> ClientShared<R> {
    /// Used by `bootstrap_inner`: Return a `RunningInner`, constructing it if necessary.
    fn instantiate_running_inner(
        &self,
        mut inner_guard: std::sync::MutexGuard<'_, Inner<R>>,
    ) -> Result<Arc<RunningInner<R>>, ErrorDetail> {
        match &*inner_guard {
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
            Inner::NotConstructed(_) => {
                let error = ErrorDetail::from(internal!("Client under construction"));
                let mut pending = Inner::Poisoned(Box::new(error));
                std::mem::swap(&mut pending, &mut *inner_guard);
                let Inner::NotConstructed(pending) = pending else {
                    panic!("Surprising type change");
                };
                match RunningInner::new(*pending, self) {
                    Ok(running_inner) => {
                        *inner_guard = Inner::Running(Arc::clone(&running_inner));
                        self.bootstrap_setting_sender
                            .lock()
                            .expect("lock poisoned")
                            .borrow_mut()
                            .running_inner_is_present = true;
                        Ok(running_inner)
                    }
                    Err(e) => {
                        *inner_guard = Inner::Poisoned(Box::new(e.clone()));
                        Err(e)
                    }
                }
            }
        }
    }

    /// Implementation of `bootstrap`, split out in order to avoid manually specifying
    /// double error conversions.
    async fn bootstrap_inner(&self) -> StdResult<(), ErrorDetail> {
        // Wait for an existing bootstrap attempt to finish first.
        //
        // This is a futures::lock::Mutex, so it's okay to await while we hold it.
        let _bootstrap_lock = self.bootstrap_in_progress.lock().await;

        let running = self.instantiate_running_inner(self.inner.lock().expect("lock poisoned"))?;

        // Make sure we have a bridge descriptor manager, which is active iff required
        #[cfg(feature = "bridge-client")]
        {
            let mut dormant = self.dormant.lock().expect("dormant lock poisoned");
            let dormant = dormant.borrow();
            let dormant = dormant.ok_or_else(|| internal!("dormant dropped"))?.into();

            let mut bdm = running.bridge_desc_mgr.lock().expect("bdm lock poisoned");
            if bdm.is_none() {
                let new_bdm = Arc::new(BridgeDescMgr::new(
                    &Default::default(),
                    self.runtime.clone(),
                    self.dirmgr_store.clone(),
                    running.circmgr.clone(),
                    dormant,
                )?);
                running
                    .guardmgr
                    .install_bridge_desc_provider(&(new_bdm.clone() as _))
                    .map_err(ErrorDetail::GuardMgrSetup)?;
                // If ^ that fails, we drop the BridgeDescMgr again.  It may do some
                // work but will hopefully eventually quit.
                *bdm = Some(new_bdm);
            }
        }

        if self
            .statemgr
            .try_lock()
            .map_err(ErrorDetail::StateAccess)?
            .held()
        {
            debug!("It appears we have the lock on our state files.");
        } else {
            info!(
                "Another process has the lock on our state files. We'll proceed in read-only mode."
            );
        }

        // If we fail to bootstrap (i.e. we return before the disarm() point below), attempt to
        // unlock the state files.
        let unlock_guard = util::StateMgrUnlockGuard::new(&self.statemgr);

        running
            .dirmgr
            .bootstrap()
            .await
            .map_err(ErrorDetail::DirMgrBootstrap)?;

        // Since we succeeded, disarm the unlock guard.
        unlock_guard.disarm();

        Ok(())
    }

    /// Ensure that this client is running and bootstrapped, and return a [`RunningInner`] if it is.
    ///
    /// If we're not bootstrapped,
    /// we either try to bootstrap or return an error,
    /// depending on `self.should_bootstrap`:
    ///
    /// ## For `BootstrapBehavior::OnDemand` clients
    ///
    /// Initiate a bootstrap by calling `bootstrap_inner`
    /// (which is idempotent, so attempts to bootstrap twice will just do nothing).
    ///
    /// ## For `BootstrapBehavior::Manual` clients
    ///
    /// Check whether a bootstrap is in progress; if one is, wait until it finishes.
    /// Then see whether we're bootstrapped, and return either a success or a failure.
    #[instrument(skip_all, level = "trace")]
    async fn wait_for_bootstrap_running(
        &self,
        action: &'static str,
    ) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        match self.should_bootstrap {
            BootstrapBehavior::OnDemand => {
                self.bootstrap_inner().await?;
            }
            BootstrapBehavior::Manual => {
                // Grab the lock, and immediately release it.  That will ensure that nobody else is trying to bootstrap.
                self.bootstrap_in_progress.lock().await;
            }
        }
        self.dormant
            .lock()
            .map_err(|_| internal!("dormant poisoned"))?
            .try_maybe_send(|dormant| {
                Ok::<_, Bug>(Some({
                    match dormant.ok_or_else(|| internal!("dormant dropped"))? {
                        DormantMode::Soft => DormantMode::Normal,
                        other @ DormantMode::Normal => other,
                    }
                }))
            })?;
        self.running_inner(action)
    }

    /// If we are currently bootstrapping or running, return a [`RunningInner`].
    fn running_inner(&self, action: &'static str) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        let guard = self.inner.lock().expect("Lock poisoned");
        match &*guard {
            Inner::NotConstructed(_) => Err(ErrorDetail::BootstrapRequired { action }),
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
        }
    }

    /// Ensure that our bootstrap state is [`RunningInner`], if possible.
    ///
    /// Return an error if our [`BootstrapBehavior`] is `Manual` and have not created a
    /// [`RunningInner`].
    fn initiate_bootstrap_if_needed(
        &self,
        action: &'static str,
    ) -> StdResult<Arc<RunningInner<R>>, ErrorDetail> {
        let guard = self.inner.lock().expect("Lock poisoned");
        match &*guard {
            Inner::Running(running_inner) => Ok(Arc::clone(running_inner)),
            Inner::Poisoned(e) => Err(e.as_ref().clone()),
            Inner::NotConstructed(_) => match self.should_bootstrap {
                BootstrapBehavior::Manual => Err(ErrorDetail::BootstrapRequired { action }),
                BootstrapBehavior::OnDemand => self.instantiate_running_inner(guard),
            },
        }
    }

    /// This is split out from `reconfigure` so we can do the all-or-nothing
    /// check without recursion. the caller to this method must hold the
    /// `reconfigure_lock`.
    #[instrument(level = "trace", skip_all)]
    fn reconfigure_inner(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
        _reconfigure_lock_guard: &std::sync::MutexGuard<'_, ()>,
    ) -> crate::Result<()> {
        // We ignore 'new_config.path_resolver' here since CfgPathResolver does not impl PartialEq
        // and we have no way to compare them, but this field is explicitly documented as being
        // non-reconfigurable anyways.
        let addr_cfg = &new_config.address_filter;
        let timeout_cfg = &new_config.stream_timeouts;
        let state_cfg = new_config
            .storage
            .expand_state_dir(&self.path_resolver)
            .map_err(wrap_err)?;

        // TODO wasm: This ins't really how things should be long term,
        // but once we have a more generic notion of configuring storage
        // we can change this to comply with it.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            if state_cfg != self.statemgr.path() {
                how.cannot_change("storage.state_dir").map_err(wrap_err)?;
            }
        }

        self.memquota
            .reconfigure(new_config.system.memory.clone(), how)
            .map_err(wrap_err)?;

        let mut inner_lock = self.inner.lock().expect("Lock poisoned");
        match &mut *inner_lock {
            Inner::Poisoned(e) => return Err(e.as_ref().clone().into()),
            Inner::NotConstructed(nc) => nc.reconfigure(new_config, how)?,
            Inner::Running(r) => {
                let running = Arc::clone(r);
                drop(inner_lock);
                running.reconfigure(new_config, how)?;
            }
        }
        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        self.addrcfg.replace(addr_cfg.clone());
        self.timeoutcfg.replace(timeout_cfg.clone());

        Ok(())
    }
}

/// Monitor `dormant_mode` and enable/disable periodic tasks as applicable
///
/// This function is spawned as a task during client construction.
// TODO should this perhaps be done by each TaskHandle?
async fn tasks_monitor_dormant<R: Runtime>(
    mut dormant_rx: postage::watch::Receiver<Option<DormantMode>>,
    netdir: Arc<dyn NetDirProvider>,
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    #[cfg(feature = "bridge-client")] bridge_desc_mgr: Arc<Mutex<Option<Arc<BridgeDescMgr<R>>>>>,
    periodic_task_handles: Vec<TaskHandle>,
) {
    while let Some(Some(mode)) = dormant_rx.next().await {
        let netparams = netdir.params();

        chanmgr
            .set_dormancy(mode.into(), netparams)
            .unwrap_or_else(|e| error_report!(e, "couldn't set dormancy"));

        // IEFI simplifies handling of exceptional cases, as "never mind, then".
        #[cfg(feature = "bridge-client")]
        (|| {
            let mut bdm = bridge_desc_mgr.lock().ok()?;
            let bdm = bdm.as_mut()?;
            bdm.set_dormancy(mode.into());
            Some(())
        })();

        let is_dormant = matches!(mode, DormantMode::Soft);

        for task in periodic_task_handles.iter() {
            if is_dormant {
                task.cancel();
            } else {
                task.fire();
            }
        }
    }
}

/// Alias for TorError::from(Error)
pub(crate) fn wrap_err<T>(err: T) -> crate::Error
where
    ErrorDetail: From<T>,
{
    ErrorDetail::from(err).into()
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use tor_config::Reconfigure;

    use super::*;
    use crate::config::TorClientConfigBuilder;
    use crate::{ErrorKind, HasKind};

    #[test]
    fn create_unbootstrapped() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            let _ = TorClient::with_runtime(rt)
                .config(cfg)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped()
                .unwrap();
        });
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            let _ = TorClient::with_runtime(rt)
                .config(cfg)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped_async()
                .await
                .unwrap();
        });
    }

    #[test]
    fn unbootstrapped_client_unusable() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            // Test sync
            let client = TorClient::with_runtime(rt)
                .config(cfg)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped()
                .unwrap();
            let result = client.connect("example.com:80").await;
            assert!(result.is_err());
            assert_eq!(result.err().unwrap().kind(), ErrorKind::BootstrapRequired);
        });
        // Need a separate test for async because Runtime and TorClientConfig are consumed by the
        // builder
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            // Test sync
            let client = TorClient::with_runtime(rt)
                .config(cfg)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped_async()
                .await
                .unwrap();
            let result = client.connect("example.com:80").await;
            assert!(result.is_err());
            assert_eq!(result.err().unwrap().kind(), ErrorKind::BootstrapRequired);
        });
    }

    #[test]
    fn streamprefs_isolate_every_stream() {
        let mut observed = StreamPrefs::new();
        observed.isolate_every_stream();
        match observed.isolation {
            StreamIsolationPreference::EveryStream => (),
            _ => panic!("unexpected isolation: {:?}", observed.isolation),
        };
    }

    #[test]
    fn streamprefs_new_has_expected_defaults() {
        let observed = StreamPrefs::new();
        assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Preferred);
        assert!(!observed.optimistic_stream);
        // StreamIsolationPreference does not implement Eq, check manually.
        match observed.isolation {
            StreamIsolationPreference::None => (),
            _ => panic!("unexpected isolation: {:?}", observed.isolation),
        };
    }

    #[test]
    fn streamprefs_new_isolation_group() {
        let mut observed = StreamPrefs::new();
        observed.new_isolation_group();
        match observed.isolation {
            StreamIsolationPreference::Explicit(_) => (),
            _ => panic!("unexpected isolation: {:?}", observed.isolation),
        };
    }

    #[test]
    fn streamprefs_ipv6_only() {
        let mut observed = StreamPrefs::new();
        observed.ipv6_only();
        assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv6Only);
    }

    #[test]
    fn streamprefs_ipv6_preferred() {
        let mut observed = StreamPrefs::new();
        observed.ipv6_preferred();
        assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv6Preferred);
    }

    #[test]
    fn streamprefs_ipv4_only() {
        let mut observed = StreamPrefs::new();
        observed.ipv4_only();
        assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Only);
    }

    #[test]
    fn streamprefs_ipv4_preferred() {
        let mut observed = StreamPrefs::new();
        observed.ipv4_preferred();
        assert_eq!(observed.ip_ver_pref, IpVersionPreference::Ipv4Preferred);
    }

    #[test]
    fn streamprefs_optimistic() {
        let mut observed = StreamPrefs::new();
        observed.optimistic();
        assert!(observed.optimistic_stream);
    }

    #[test]
    fn streamprefs_set_isolation() {
        let mut observed = StreamPrefs::new();
        observed.set_isolation(IsolationToken::new());
        match observed.isolation {
            StreamIsolationPreference::Explicit(_) => (),
            _ => panic!("unexpected isolation: {:?}", observed.isolation),
        };
    }

    #[test]
    fn reconfigure_all_or_nothing() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            let tor_client = TorClient::with_runtime(rt)
                .config(cfg.clone())
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped()
                .unwrap();
            tor_client
                .reconfigure(&cfg, Reconfigure::AllOrNothing)
                .unwrap();
        });
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            let tor_client = TorClient::with_runtime(rt)
                .config(cfg.clone())
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped_async()
                .await
                .unwrap();
            tor_client
                .reconfigure(&cfg, Reconfigure::AllOrNothing)
                .unwrap();
        });
    }
}
