//! A general interface for Tor client usage.
//!
//! To construct a client, run the [`TorClient::create_bootstrapped`] method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! [`TorClient::connect`].

#[cfg(feature = "rpc")]
mod rpc;

use crate::address::{IntoTorAddr, ResolveInstructions, StreamInstructions};

use crate::config::{ClientAddrConfig, StreamTimeoutConfig, TorClientConfig};
use safelog::{sensitive, Sensitive};
use tor_async_utils::{DropNotifyWatchSender, PostageWatchSenderExt};
use tor_circmgr::isolation::{Isolation, StreamIsolation};
use tor_circmgr::{isolation::StreamIsolationBuilder, IsolationToken, TargetPort};
use tor_config::MutCfg;
#[cfg(feature = "bridge-client")]
use tor_dirmgr::bridgedesc::BridgeDescMgr;
use tor_dirmgr::{DirMgrStore, Timeliness};
use tor_error::{error_report, internal, Bug};
use tor_guardmgr::GuardMgr;
use tor_netdir::{params::NetParameters, NetDirProvider};
#[cfg(feature = "onion-service-service")]
use tor_persist::state_dir::StateDirectory;
use tor_persist::{FsStateMgr, StateMgr};
use tor_proto::circuit::ClientCirc;
use tor_proto::stream::{DataStream, IpVersionPreference, StreamParameters};
#[cfg(all(
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "async-std", feature = "tokio")
))]
use tor_rtcompat::PreferredRuntime;
use tor_rtcompat::{Runtime, SleepProviderExt};
#[cfg(feature = "onion-service-client")]
use {
    tor_config::BoolOrAuto,
    tor_hsclient::{HsClientConnector, HsClientDescEncKeypairSpecifier, HsClientSecretKeysBuilder},
    tor_hscrypto::pk::HsClientDescEncKeypair,
    tor_netdir::DirEvent,
};

use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder};

use futures::lock::Mutex as AsyncMutex;
use futures::task::SpawnExt;
use futures::StreamExt as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use crate::err::ErrorDetail;
use crate::{status, util, TorClientBuilder};
#[cfg(feature = "geoip")]
use tor_geoip::CountryCode;
use tor_rtcompat::scheduler::TaskHandle;
use tracing::{debug, info};

/// An active client session on the Tor network.
///
/// While it's running, it will fetch directory information, build
/// circuits, and make connections for you.
///
/// Cloning this object makes a new reference to the same underlying
/// handles: it's usually better to clone the `TorClient` than it is to
/// create a new one.
// TODO(nickm): This type now has 5 Arcs inside it, and 2 types that have
// implicit Arcs inside them! maybe it's time to replace much of the insides of
// this with an Arc<TorClientInner>?
#[derive(Clone)]
pub struct TorClient<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,
    /// Default isolation token for streams through this client.
    ///
    /// This is eventually used for `owner_token` in `tor-circmgr/src/usage.rs`, and is orthogonal
    /// to the `stream_isolation` which comes from `connect_prefs` (or a passed-in `StreamPrefs`).
    /// (ie, both must be the same to share a circuit).
    client_isolation: IsolationToken,
    /// Connection preferences.  Starts out as `Default`,  Inherited by our clones.
    connect_prefs: StreamPrefs,
    /// Channel manager, used by circuits etc.,
    ///
    /// Used directly by client only for reconfiguration.
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager persistent storage.
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    dirmgr_store: DirMgrStore<R>,
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
    /// The key manager.
    ///
    /// This is used for retrieving private keys, certificates, and other sensitive data (for
    /// example, for retrieving the keys necessary for connecting to hidden services that require
    /// client authentication).
    ///
    /// If this crate is compiled _with_ the `keymgr` feature, [`TorClient`] will use a functional
    /// key manager implementation.
    ///
    /// If this crate is compiled _without_ the `keymgr` feature, then [`TorClient`] will use a
    /// no-op key manager implementation instead.
    ///
    /// See the [`KeyMgr`] documentation for more details.
    keymgr: Option<Arc<KeyMgr>>,
    /// Guard manager
    #[cfg_attr(not(feature = "bridge-client"), allow(dead_code))]
    guardmgr: GuardMgr<R>,
    /// Location on disk where we store persistent data (raw directory).
    // TODO replace this and storage_mistrust with tor_persist::state_dir::StateDirectory?
    #[cfg(feature = "onion-service-service")]
    state_dir: PathBuf,
    /// Permissions `Mistrust` configuration for all our on-disk storage
    ///
    /// This applies to `state_dir`, but it comes from `[storage]` in our config,
    /// so this configuration is the same one as used for eg the netdir cache.
    /// (It's mostly copied during `TorClient` creation, and ends up within
    /// the subsystems in fields like `dirmgr`, `keymgr` and `statemgr`.)
    #[cfg(feature = "onion-service-service")]
    storage_mistrust: fs_mistrust::Mistrust,
    /// Location on disk where we store persistent data (cooked state manager).
    statemgr: FsStateMgr,
    /// Client address configuration
    addrcfg: Arc<MutCfg<ClientAddrConfig>>,
    /// Client DNS configuration
    timeoutcfg: Arc<MutCfg<StreamTimeoutConfig>>,
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
    bootstrap_in_progress: Arc<AsyncMutex<()>>,

    /// Whether or not we should call `bootstrap` before doing things that require
    /// bootstrapping. If this is `false`, we will just call `wait_for_bootstrap`
    /// instead.
    should_bootstrap: BootstrapBehavior,

    /// Shared boolean for whether we're currently in "dormant mode" or not.
    //
    // The sent value is `Option`, so that `None` is sent when the sender, here,
    // is dropped,.  That shuts down the monitoring task.
    dormant: Arc<Mutex<DropNotifyWatchSender<Option<DormantMode>>>>,
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
    #[cfg_attr(docsrs, doc(cfg(feature = "geoip")))]
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

    /// Indicate whether connection to a hidden service (`.onion` service) should be allowed
    ///
    /// If `Explicit(false)`, attempts to connect to Onion Services will be forced to fail with
    /// an error of kind [`InvalidStreamTarget`](crate::ErrorKind::InvalidStreamTarget).
    ///
    /// If `Explicit(true)`, Onion Service connections are enabled.
    ///
    /// If `Auto`, the behaviour depends on the `address_filter.allow_onion_addrs`
    /// configuration option, which is in turn **disabled** by default.
    ///
    /// **Note**: Arti currently lacks the
    /// "vanguards" feature that Tor uses to prevent guard discovery attacks over time.
    /// As such, you should probably stick with C Tor if you need to make a large
    /// number of onion service connections, or if you are using the Tor protocol
    /// in a way that lets an attacker control how many onion services connections that you make -
    /// for example, when using Arti's SOCKS support from a web browser such as Tor Browser.
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
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client` (and its
    /// clones) will not share circuits with the original client, even if the same
    /// `isolation` is specified via the `ConnectionPrefs` in force.
    pub fn new_isolation_group(&mut self) -> &mut Self {
        self.isolation = StreamIsolationPreference::Explicit(Box::new(IsolationToken::new()));
        self
    }

    /// Indicate which other connections might use the same circuit
    /// as this one.
    ///
    /// By default all connections made on all clones of a `TorClient` may share connections.
    /// Connections made with a particular `isolation` may share circuits with each other.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client` (and its
    /// clones) will not share circuits with the original client, even if the same
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
    pub async fn create_bootstrapped(config: TorClientConfig) -> crate::Result<Self> {
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
    pub(crate) fn create_inner(
        runtime: R,
        config: &TorClientConfig,
        autobootstrap: BootstrapBehavior,
        dirmgr_builder: &dyn crate::builder::DirProviderBuilder<R>,
        dirmgr_extensions: tor_dirmgr::config::DirMgrExtensions,
    ) -> StdResult<Self, ErrorDetail> {
        if crate::util::running_as_setuid() {
            return Err(tor_error::bad_api_usage!(
                "Arti does not support running in a setuid or setgid context."
            )
            .into());
        }

        let (state_dir, mistrust) = Self::state_dir(config)?;

        let dormant = DormantMode::Normal;
        let dir_cfg = {
            let mut c: tor_dirmgr::DirMgrConfig = config.dir_mgr_config()?;
            c.extensions = dirmgr_extensions;
            c
        };
        let statemgr = FsStateMgr::from_path_and_mistrust(&state_dir, mistrust)
            .map_err(ErrorDetail::StateMgrSetup)?;
        // Try to take state ownership early, so we'll know if we have it.
        // (At this point we don't yet care if we have it.)
        let _ignore_status = statemgr.try_lock().map_err(ErrorDetail::StateMgrSetup)?;

        let addr_cfg = config.address_filter.clone();

        let (status_sender, status_receiver) = postage::watch::channel();
        let status_receiver = status::BootstrapEvents {
            inner: status_receiver,
        };
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &config.channel,
            dormant.into(),
            &NetParameters::from_map(&config.override_net_params),
        ));
        let guardmgr = tor_guardmgr::GuardMgr::new(runtime.clone(), statemgr.clone(), config)
            .map_err(ErrorDetail::GuardMgrSetup)?;

        #[cfg(feature = "pt-client")]
        let pt_mgr = {
            let pt_state_dir = state_dir.as_path().join("pt_state");
            config.storage.permissions().make_directory(&pt_state_dir)?;

            let mgr = Arc::new(tor_ptmgr::PtMgr::new(
                config.bridges.transports.clone(),
                pt_state_dir,
                runtime.clone(),
            )?);

            chanmgr.set_pt_mgr(mgr.clone());

            mgr
        };

        let circmgr = tor_circmgr::CircMgr::new(
            config,
            statemgr.clone(),
            &runtime,
            Arc::clone(&chanmgr),
            guardmgr.clone(),
        )
        .map_err(ErrorDetail::CircMgrSetup)?;

        let timeout_cfg = config.stream_timeouts.clone();

        let dirmgr_store =
            DirMgrStore::new(&dir_cfg, runtime.clone(), false).map_err(ErrorDetail::DirMgrSetup)?;
        let dirmgr = dirmgr_builder
            .build(
                runtime.clone(),
                dirmgr_store.clone(),
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

        let (dormant_send, dormant_recv) = postage::watch::channel_with(Some(dormant));
        let dormant_send = DropNotifyWatchSender::new(dormant_send);
        #[cfg(feature = "bridge-client")]
        let bridge_desc_mgr = Arc::new(Mutex::new(None));

        #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
        let hs_circ_pool = {
            let circpool = tor_circmgr::hspool::HsCircPool::new(&circmgr);
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

            HsClientConnector::new(runtime.clone(), hs_circ_pool.clone(), config, housekeeping)?
        };

        let keymgr = Self::create_keymgr(config)?;

        runtime
            .spawn(tasks_monitor_dormant(
                dormant_recv,
                dirmgr.clone().upcast_arc(),
                chanmgr.clone(),
                #[cfg(feature = "bridge-client")]
                bridge_desc_mgr.clone(),
                periodic_task_handles,
            ))
            .map_err(|e| ErrorDetail::from_spawn("periodic task dormant monitor", e))?;

        let conn_status = chanmgr.bootstrap_events();
        let dir_status = dirmgr.bootstrap_events();
        let skew_status = circmgr.skew_events();
        runtime
            .spawn(status::report_status(
                status_sender,
                conn_status,
                dir_status,
                skew_status,
            ))
            .map_err(|e| ErrorDetail::from_spawn("top-level status reporter", e))?;

        let client_isolation = IsolationToken::new();

        Ok(TorClient {
            runtime,
            client_isolation,
            connect_prefs: Default::default(),
            chanmgr,
            circmgr,
            dirmgr_store,
            dirmgr,
            #[cfg(feature = "bridge-client")]
            bridge_desc_mgr,
            #[cfg(feature = "pt-client")]
            pt_mgr,
            #[cfg(feature = "onion-service-client")]
            hsclient,
            #[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
            hs_circ_pool,
            keymgr,
            guardmgr,
            statemgr,
            addrcfg: Arc::new(addr_cfg.into()),
            timeoutcfg: Arc::new(timeout_cfg.into()),
            reconfigure_lock: Arc::new(Mutex::new(())),
            status_receiver,
            bootstrap_in_progress: Arc::new(AsyncMutex::new(())),
            should_bootstrap: autobootstrap,
            dormant: Arc::new(Mutex::new(dormant_send)),
            #[cfg(feature = "onion-service-service")]
            state_dir,
            #[cfg(feature = "onion-service-service")]
            storage_mistrust: mistrust.clone(),
        })
    }

    /// Bootstrap a connection to the Tor network, with a client created by `create_unbootstrapped`.
    ///
    /// Since cloned copies of a `TorClient` share internal state, you can bootstrap a client by
    /// cloning it and running this function in a background task (or similar). This function
    /// only needs to be called on one client in order to bootstrap all of its clones.
    ///
    /// Returns once there is enough directory material to connect safely over the Tor network.
    /// If the client or one of its clones has already been bootstrapped, returns immediately with
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
    pub async fn bootstrap(&self) -> crate::Result<()> {
        self.bootstrap_inner().await.map_err(ErrorDetail::into)
    }

    /// Implementation of `bootstrap`, split out in order to avoid manually specifying
    /// double error conversions.
    async fn bootstrap_inner(&self) -> StdResult<(), ErrorDetail> {
        // Make sure we have a bridge descriptor manager, which is active iff required
        #[cfg(feature = "bridge-client")]
        {
            let mut dormant = self.dormant.lock().expect("dormant lock poisoned");
            let dormant = dormant.borrow();
            let dormant = dormant.ok_or_else(|| internal!("dormant dropped"))?.into();

            let mut bdm = self.bridge_desc_mgr.lock().expect("bdm lock poisoned");
            if bdm.is_none() {
                let new_bdm = Arc::new(BridgeDescMgr::new(
                    &Default::default(),
                    self.runtime.clone(),
                    self.dirmgr_store.clone(),
                    self.circmgr.clone(),
                    dormant,
                )?);
                self.guardmgr
                    .install_bridge_desc_provider(&(new_bdm.clone() as _))
                    .map_err(ErrorDetail::GuardMgrSetup)?;
                // If ^ that fails, we drop the BridgeDescMgr again.  It may do some
                // work but will hopefully eventually quit.
                *bdm = Some(new_bdm);
            }
        }

        // Wait for an existing bootstrap attempt to finish first.
        //
        // This is a futures::lock::Mutex, so it's okay to await while we hold it.
        let _bootstrap_lock = self.bootstrap_in_progress.lock().await;

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

        self.dirmgr
            .bootstrap()
            .await
            .map_err(ErrorDetail::DirMgrBootstrap)?;

        // Since we succeeded, disarm the unlock guard.
        unlock_guard.disarm();

        Ok(())
    }

    /// ## For `BootstrapBehavior::OnDemand` clients
    ///
    /// Initiate a bootstrap by calling `bootstrap` (which is idempotent, so attempts to
    /// bootstrap twice will just do nothing).
    ///
    /// ## For `BootstrapBehavior::Manual` clients
    ///
    /// Check whether a bootstrap is in progress; if one is, wait until it finishes
    /// and then return. (Otherwise, return immediately.)
    async fn wait_for_bootstrap(&self) -> StdResult<(), ErrorDetail> {
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
        Ok(())
    }

    /// Change the configuration of this TorClient to `new_config`.
    ///
    /// The `how` describes whether to perform an all-or-nothing
    /// reconfiguration: either all of the configuration changes will be
    /// applied, or none will. If you have disabled all-or-nothing changes, then
    /// only fatal errors will be reported in this function's return value.
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
    ///
    /// Changing some options do not take effect immediately on all open streams
    /// and circuits, but rather affect only future streams and circuits.  Those
    /// are also explicitly documented.
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
        let guard = self.reconfigure_lock.lock().expect("Poisoned lock");

        match how {
            tor_config::Reconfigure::AllOrNothing => {
                // We have to check before we make any changes.
                self.reconfigure_inner(
                    new_config,
                    tor_config::Reconfigure::CheckAllOrNothing,
                    &guard,
                )?;
            }
            tor_config::Reconfigure::CheckAllOrNothing => {}
            tor_config::Reconfigure::WarnOnFailures => {}
            _ => {}
        }

        // Actually reconfigure
        self.reconfigure_inner(new_config, how, &guard)?;

        Ok(())
    }

    /// This is split out from `reconfigure` so we can do the all-or-nothing
    /// check without recursion. the caller to this method must hold the
    /// `reconfigure_lock`.
    fn reconfigure_inner(
        &self,
        new_config: &TorClientConfig,
        how: tor_config::Reconfigure,
        _reconfigure_lock_guard: &std::sync::MutexGuard<'_, ()>,
    ) -> crate::Result<()> {
        let dir_cfg = new_config.dir_mgr_config().map_err(wrap_err)?;
        let state_cfg = new_config.storage.expand_state_dir().map_err(wrap_err)?;
        let addr_cfg = &new_config.address_filter;
        let timeout_cfg = &new_config.stream_timeouts;

        #[cfg(all(
            feature = "vanguards",
            any(feature = "onion-service-client", feature = "onion-service-service")
        ))]
        let vanguard_cfg = &new_config.vanguards;

        if state_cfg != self.statemgr.path() {
            how.cannot_change("storage.state_dir").map_err(wrap_err)?;
        }

        self.circmgr
            .reconfigure(new_config, how)
            .map_err(wrap_err)?;

        #[cfg(all(
            feature = "vanguards",
            any(feature = "onion-service-client", feature = "onion-service-service")
        ))]
        self.hs_circ_pool
            .reconfigure(vanguard_cfg)
            .map_err(wrap_err)?;

        self.dirmgr.reconfigure(&dir_cfg, how).map_err(wrap_err)?;

        let netparams = self.dirmgr.params();

        self.chanmgr
            .reconfigure(&new_config.channel, how, netparams)
            .map_err(wrap_err)?;

        #[cfg(feature = "pt-client")]
        self.pt_mgr
            .reconfigure(how, new_config.bridges.transports.clone())
            .map_err(wrap_err)?;

        if how == tor_config::Reconfigure::CheckAllOrNothing {
            return Ok(());
        }

        self.addrcfg.replace(addr_cfg.clone());
        self.timeoutcfg.replace(timeout_cfg.clone());

        Ok(())
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
    ///
    /// (Connections made with clones of the returned `TorClient` may
    /// share circuits with each other.)
    #[must_use]
    pub fn isolated_client(&self) -> TorClient<R> {
        let mut result = self.clone();
        result.client_isolation = IsolationToken::new();
        result
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
    pub async fn connect<A: IntoTorAddr>(&self, target: A) -> crate::Result<DataStream> {
        self.connect_with_prefs(target, &self.connect_prefs).await
    }

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network, with explicit connection preferences.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    /// (See [`TorClient::connect()`] for more information.)
    pub async fn connect_with_prefs<A: IntoTorAddr>(
        &self,
        target: A,
        prefs: &StreamPrefs,
    ) -> crate::Result<DataStream> {
        let addr = target.into_tor_addr().map_err(wrap_err)?;
        let mut stream_parameters = prefs.stream_parameters();

        let (circ, addr, port) = match addr.into_stream_instructions(&self.addrcfg.get(), prefs)? {
            StreamInstructions::Exit {
                hostname: addr,
                port,
            } => {
                let exit_ports = [prefs.wrap_target_port(port)];
                let circ = self
                    .get_or_launch_exit_circ(&exit_ports, prefs)
                    .await
                    .map_err(wrap_err)?;
                debug!("Got a circuit for {}:{}", sensitive(&addr), port);
                (circ, addr, port)
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
                self.wait_for_bootstrap().await?;
                let netdir = self.netdir(Timeliness::Timely, "connect to a hidden service")?;

                let mut hs_client_secret_keys_builder = HsClientSecretKeysBuilder::default();

                if let Some(keymgr) = &self.keymgr {
                    let desc_enc_key_spec = HsClientDescEncKeypairSpecifier::new(hsid);

                    // TODO hs: refactor to reduce code duplication.
                    //
                    // The code that reads ks_hsc_desc_enc and ks_hsc_intro_auth and builds the
                    // HsClientSecretKeys is very repetitive and should be refactored.
                    let ks_hsc_desc_enc =
                        keymgr.get::<HsClientDescEncKeypair>(&desc_enc_key_spec)?;

                    if let Some(ks_hsc_desc_enc) = ks_hsc_desc_enc {
                        debug!("Found descriptor decryption key for {hsid}");
                        hs_client_secret_keys_builder.ks_hsc_desc_enc(ks_hsc_desc_enc);
                    }
                };

                let hs_client_secret_keys = hs_client_secret_keys_builder
                    .build()
                    .map_err(ErrorDetail::Configuration)?;

                let circ = self
                    .hsclient
                    .get_or_launch_circuit(
                        &netdir,
                        hsid,
                        hs_client_secret_keys,
                        self.isolation(prefs),
                    )
                    .await
                    .map_err(|cause| ErrorDetail::ObtainHsCircuit {
                        cause,
                        hsid: hsid.into(),
                    })?;
                // On connections to onion services, we have to suppress
                // everything except the port from the BEGIN message.  We also
                // disable optimistic data.
                stream_parameters
                    .suppress_hostname()
                    .suppress_begin_flags()
                    .optimistic(false);
                (circ, hostname, port)
            }
        };

        let stream_future = circ.begin_stream(&addr, port, Some(stream_parameters));
        // This timeout is needless but harmless for optimistic streams.
        let stream = self
            .runtime
            .timeout(self.timeoutcfg.get().connect_timeout, stream_future)
            .await
            .map_err(|_| ErrorDetail::ExitTimeout)?
            .map_err(|cause| ErrorDetail::StreamFailed {
                cause,
                kind: "data",
            })?;

        Ok(stream)
    }

    /// Sets the default preferences for future connections made with this client.
    ///
    /// The preferences set with this function will be inherited by clones of this client, but
    /// updates to the preferences in those clones will not propagate back to the original.  I.e.,
    /// the preferences are copied by `clone`.
    ///
    /// Connection preferences always override configuration, even configuration set later
    /// (eg, by a config reload).
    pub fn set_stream_prefs(&mut self, connect_prefs: StreamPrefs) {
        self.connect_prefs = connect_prefs;
    }

    /// Provides a new handle on this client, but with adjusted default preferences.
    ///
    /// Connections made with e.g. [`connect`](TorClient::connect) on the returned handle will use
    /// `connect_prefs`.  This is a convenience wrapper for `clone` and `set_connect_prefs`.
    #[must_use]
    pub fn clone_with_prefs(&self, connect_prefs: StreamPrefs) -> Self {
        let mut result = self.clone();
        result.set_stream_prefs(connect_prefs);
        result
    }

    /// On success, return a list of IP addresses.
    pub async fn resolve(&self, hostname: &str) -> crate::Result<Vec<IpAddr>> {
        self.resolve_with_prefs(hostname, &self.connect_prefs).await
    }

    /// On success, return a list of IP addresses, but use prefs.
    pub async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<IpAddr>> {
        // TODO This dummy port is only because `address::Host` is not pub(crate),
        // but I see no reason why it shouldn't be?  Then `into_resolve_instructions`
        // should be a method on `Host`, not `TorAddr`.  -Diziet.
        let addr = (hostname, 1).into_tor_addr().map_err(wrap_err)?;

        match addr.into_resolve_instructions(&self.addrcfg.get(), prefs)? {
            ResolveInstructions::Exit(hostname) => {
                let circ = self.get_or_launch_exit_circ(&[], prefs).await?;

                let resolve_future = circ.resolve(&hostname);
                let addrs = self
                    .runtime
                    .timeout(self.timeoutcfg.get().resolve_timeout, resolve_future)
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
    pub async fn resolve_ptr(&self, addr: IpAddr) -> crate::Result<Vec<String>> {
        self.resolve_ptr_with_prefs(addr, &self.connect_prefs).await
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    pub async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &StreamPrefs,
    ) -> crate::Result<Vec<String>> {
        let circ = self.get_or_launch_exit_circ(&[], prefs).await?;

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .runtime
            .timeout(
                self.timeoutcfg.get().resolve_ptr_timeout,
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
    pub fn dirmgr(&self) -> &Arc<dyn tor_dirmgr::DirProvider> {
        &self.dirmgr
    }

    /// Return a reference to this client's circuit manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn circmgr(&self) -> &Arc<tor_circmgr::CircMgr<R>> {
        &self.circmgr
    }

    /// Return a reference to this client's channel manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn chanmgr(&self) -> &Arc<tor_chanmgr::ChanMgr<R>> {
        &self.chanmgr
    }

    /// Return a reference to the runtime being used by this client.
    //
    // This API is not a hostage to fortune since we already require that R: Clone,
    // and necessarily a TorClient must have a clone of it.
    //
    // We provide it simply to save callers who have a TorClient from
    // having to separately keep their own handle,
    pub fn runtime(&self) -> &R {
        &self.runtime
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
        match self.dirmgr.netdir(timeliness) {
            Ok(netdir) => Ok(netdir),
            Err(E::NoInfo) | Err(E::NotEnoughInfo) => {
                Err(ErrorDetail::BootstrapRequired { action })
            }
            Err(error) => Err(ErrorDetail::NoDir { error, action }),
        }
    }

    /// Get or launch an exit-suitable circuit with a given set of
    /// exit ports.
    async fn get_or_launch_exit_circ(
        &self,
        exit_ports: &[TargetPort],
        prefs: &StreamPrefs,
    ) -> StdResult<Arc<ClientCirc>, ErrorDetail> {
        // TODO HS probably this netdir ought to be made in connect_with_prefs
        // like for StreamInstructions::Hs.
        self.wait_for_bootstrap().await?;
        let dir = self.netdir(Timeliness::Timely, "build a circuit")?;

        let circ = self
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

        Ok(circ)
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
    pub fn launch_onion_service(
        &self,
        config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<(
        Arc<tor_hsservice::RunningOnionService>,
        impl futures::Stream<Item = tor_hsservice::RendRequest>,
    )> {
        let keymgr = self
            .keymgr
            .as_ref()
            .ok_or(ErrorDetail::KeystoreRequired {
                action: "launch onion service",
            })?
            .clone();
        let state_dir = self::StateDirectory::new(&self.state_dir, &self.storage_mistrust)
            .map_err(ErrorDetail::StateAccess)?;
        let service = tor_hsservice::OnionService::new(
            config, // TODO #1186: Allow override of KeyMgr for "ephemeral" operation?
            keymgr,
            // TODO #1186: Allow override of StateMgr for "ephemeral" operation?
            &state_dir,
        )
        .map_err(ErrorDetail::LaunchOnionService)?;
        let (service, stream) = service
            .launch(
                self.runtime.clone(),
                self.dirmgr.clone().upcast_arc(),
                self.hs_circ_pool.clone(),
            )
            .map_err(ErrorDetail::LaunchOnionService)?;

        Ok((service, stream))
    }

    /// Create (but do not launch) a new
    /// [`OnionService`](tor_hsservice::OnionService)
    /// using the given configuration.
    ///
    /// The returned `OnionService` can be launched using
    /// [`OnionService::launch()`](tor_hsservice::OnionService::launch).
    #[cfg(feature = "onion-service-service")]
    pub fn create_onion_service(
        config: &TorClientConfig,
        svc_config: tor_hsservice::OnionServiceConfig,
    ) -> crate::Result<tor_hsservice::OnionService> {
        let keymgr = Self::create_keymgr(config)?.ok_or(ErrorDetail::KeystoreRequired {
            action: "create onion service",
        })?;

        let (state_dir, mistrust) = Self::state_dir(config)?;
        let state_dir =
            self::StateDirectory::new(state_dir, mistrust).map_err(ErrorDetail::StateAccess)?;

        Ok(
            tor_hsservice::OnionService::new(svc_config, keymgr, &state_dir)
                // TODO: do we need an ErrorDetail::CreateOnionService?
                .map_err(ErrorDetail::LaunchOnionService)?,
        )
    }

    /// Return a current [`status::BootstrapStatus`] describing how close this client
    /// is to being ready for user traffic.
    pub fn bootstrap_status(&self) -> status::BootstrapStatus {
        self.status_receiver.inner.borrow().clone()
    }

    /// Return a stream of [`status::BootstrapStatus`] events that will be updated
    /// whenever the client's status changes.
    ///
    /// The receiver might not receive every update sent to this stream, though
    /// when it does poll the stream it should get the most recent one.
    //
    // TODO(nickm): will this also need to implement Send and 'static?
    pub fn bootstrap_events(&self) -> status::BootstrapEvents {
        self.status_receiver.clone()
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
            .dormant
            .lock()
            .expect("dormant lock poisoned")
            .borrow_mut() = Some(mode);
    }

    /// Create a [`KeyMgr`] using the specified configuration.
    ///
    /// Returns `Ok(None)` if keystore use is disabled.
    fn create_keymgr(config: &TorClientConfig) -> StdResult<Option<Arc<KeyMgr>>, ErrorDetail> {
        let keystore = config.storage.keystore();
        if keystore.is_enabled() {
            let (state_dir, _mistrust) = Self::state_dir(config)?;
            let key_store_dir = state_dir.join("keystore");
            let permissions = config.storage.permissions();

            let arti_store =
                ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)?;
            info!("Using keystore from {key_store_dir:?}");

            // TODO #1106: make the default store configurable
            let default_store = arti_store;

            let keymgr = KeyMgrBuilder::default()
                .default_store(Box::new(default_store))
                .build()
                .map_err(|_| internal!("failed to build keymgr"))?;

            // TODO #858: add support for the C Tor key store
            Ok(Some(Arc::new(keymgr)))
        } else {
            info!("Running without a keystore");
            Ok(None)
        }
    }

    /// Get the state directory and its corresponding
    /// [`Mistrust`](fs_mistrust::Mistrust) configuration.
    fn state_dir(
        config: &TorClientConfig,
    ) -> StdResult<(PathBuf, &fs_mistrust::Mistrust), ErrorDetail> {
        let state_dir = config
            .storage
            .expand_state_dir()
            .map_err(ErrorDetail::Configuration)?;
        let mistrust = config.storage.permissions();

        Ok((state_dir, mistrust))
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
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
    }

    #[test]
    fn unbootstrapped_client_unusable() {
        tor_rtcompat::test_with_one_runtime!(|rt| async {
            let state_dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cfg = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .unwrap();
            let client = TorClient::with_runtime(rt)
                .config(cfg)
                .bootstrap_behavior(BootstrapBehavior::Manual)
                .create_unbootstrapped()
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
    }
}
