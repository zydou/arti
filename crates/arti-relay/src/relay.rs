//! Entry point of a Tor relay that is the [`TorRelay`] objects

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use fs_mistrust::Mistrust;
use tor_chanmgr::{ChanMgr, ChanMgrConfig, Dormancy};
use tor_config_path::CfgPathResolver;
use tor_dirmgr::DirMgrConfig;
use tor_keymgr::{
    ArtiEphemeralKeystore, ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeystoreSelector,
};
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::params::NetParameters;
use tor_persist::state_dir::StateDirectory;
use tor_persist::{FsStateMgr, StateMgr};
use tor_relay_crypto::pk::{RelayIdentityKeypair, RelayIdentityKeypairSpecifier};
use tor_rtcompat::{NetStreamProvider, Runtime};

use crate::client::RelayClient;
use crate::config::TorRelayConfig;

/// An initialized but unbootstrapped relay.
///
/// This intentionally does not have access to the runtime to prevent it from doing network io.
///
/// The idea is that we can build up the relay's components in an `InertTorRelay` without a runtime,
/// and then call `bootstrap()` on it and provide a runtime to turn it into a network-capable relay.
/// This gives us two advantages:
///
/// - We can initialize the internal data structures in the `InertTorRelay` (load the keystores,
///   configure memquota, etc), which leaves `TorRelay` to just "running" the relay (bootstrapping,
///   setting up listening sockets, etc). We don't need to combine the initialization and "running
///   the relay" all within the same object.
/// - We will likely want to share some of arti's key management subcommands in the future.
///   arti-client has an `InertTorClient` which is used so that arti subcommands can access the
///   keystore. If we do a similar thing here in arti-relay in the future, it might be nice to have
///   an `InertTorRelay` which has these internal data structures, but doesn't need a runtime or
///   have any networking capabilities.
///
/// Time will tell if this ends up being a bad design decision in practice, and we can always change
/// it later.
#[derive(Clone)]
pub(crate) struct InertTorRelay {
    /// The configuration options for the relay.
    config: TorRelayConfig,

    /// The configuration options for the client's directory manager.
    dirmgr_config: DirMgrConfig,

    /// Path resolver for expanding variables in [`CfgPath`](tor_config_path::CfgPath)s.
    #[expect(unused)] // TODO RELAY remove
    path_resolver: CfgPathResolver,

    /// State directory path.
    ///
    /// The [`StateDirectory`] stored in `state_dir` doesn't seem to have a way of getting the state
    /// directory path, so we need to store a copy of the path here.
    #[expect(unused)] // TODO RELAY remove
    state_path: PathBuf,

    /// Relay's state directory.
    #[expect(unused)] // TODO RELAY remove
    state_dir: StateDirectory,

    /// Location on disk where we store persistent data.
    state_mgr: FsStateMgr,

    /// Key manager holding all relay keys and certificates.
    keymgr: Arc<KeyMgr>,
}

impl InertTorRelay {
    /// Create a new Tor relay with the given configuration.
    pub(crate) fn new(
        config: TorRelayConfig,
        path_resolver: CfgPathResolver,
    ) -> anyhow::Result<Self> {
        let state_path = config.storage.state_dir(&path_resolver)?;
        let cache_path = config.storage.cache_dir(&path_resolver)?;

        let state_dir = StateDirectory::new(&state_path, config.storage.permissions())
            .context("Failed to create `StateDirectory`")?;
        let state_mgr =
            FsStateMgr::from_path_and_mistrust(&state_path, config.storage.permissions())
                .context("Failed to create `FsStateMgr`")?;

        // Try to take state ownership early, so we'll know if we have it.
        // Note that this `try_lock()` may return `Ok` even if we can't acquire the lock.
        // (At this point we don't yet care if we have it.)
        let _ignore_status = state_mgr
            .try_lock()
            .context("Failed to try locking the state manager")?;

        let keymgr = Self::create_keymgr(&state_path, config.storage.permissions())
            .context("Failed to create key manager")?;

        let dirmgr_config = DirMgrConfig {
            cache_dir: cache_path,
            cache_trust: config.storage.permissions().clone(),
            network: config.tor_network.clone(),
            schedule: Default::default(),
            tolerance: Default::default(),
            override_net_params: Default::default(),
            extensions: Default::default(),
        };

        Ok(Self {
            config,
            dirmgr_config,
            path_resolver,
            state_path,
            state_dir,
            state_mgr,
            keymgr,
        })
    }

    /// Connect the [`InertTorRelay`] to the Tor network.
    pub(crate) async fn init<R: Runtime>(self, runtime: R) -> anyhow::Result<TorRelay<R>> {
        // Attempt to generate any missing keys/cert from the KeyMgr.
        Self::try_generate_keys(&self.keymgr).context("Failed to generate keys")?;

        TorRelay::init(runtime, self).await
    }

    /// Create the [key manager](KeyMgr).
    fn create_keymgr(state_path: &Path, mistrust: &Mistrust) -> anyhow::Result<Arc<KeyMgr>> {
        let key_store_dir = state_path.join("keystore");

        // Store for the short-term keys that we don't need to keep on disk. The store identifier
        // is relay explicit because it can be used in other crates for channel and circuit.
        let ephemeral_store = ArtiEphemeralKeystore::new("relay-ephemeral".into());
        let persistent_store = ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, mistrust)
            .context("Failed to construct the native keystore")?;

        // Should only log fs paths at debug level or lower,
        // unless they're part of a diagnostic message.
        debug!("Using relay keystore from {key_store_dir:?}");

        let keymgr = KeyMgrBuilder::default()
            .primary_store(Box::new(persistent_store))
            .set_secondary_stores(vec![Box::new(ephemeral_store)])
            .build()
            .context("Failed to build the 'KeyMgr'")?;
        let keymgr = Arc::new(keymgr);

        // TODO: support C-tor keystore

        Ok(keymgr)
    }

    /// Generate the relay keys.
    fn try_generate_keys(keymgr: &KeyMgr) -> anyhow::Result<()> {
        let mut rng = tor_llcrypto::rng::CautiousRng;

        // Attempt to get the relay long-term identity key from the key manager. If not present,
        // generate it. We need this key to sign the signing certificates.
        let _kp_relay_id = keymgr
            .get_or_generate::<RelayIdentityKeypair>(
                &RelayIdentityKeypairSpecifier::new(),
                KeystoreSelector::default(),
                &mut rng,
            )
            .context("Failed to get or generate the long-term identity key")?;

        // TODO #1598: We need to get_or_generate RSA keys here, but that currently fails because
        // upstream ssh-key doesn't support 1024 bit keys. Once they do, we should add that here.

        // TODO: Once certificate supports is added to the KeyMgr, we need to get/gen the
        // RelaySigning (KP_relaysign_ed) certs from the native persistent store.
        //
        // If present, rotate it if expired. Else, generate it. Rotation or creation require the
        // relay identity keypair (above) in order to sign the RelaySigning.
        //
        // We then need to generate the RelayLink (KP_link_ed) certificate which is in turn signed
        // by the RelaySigning cert.

        Ok(())
    }
}

/// Represent an active Relay on the Tor network.
pub(crate) struct TorRelay<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,

    /// Memory quota tracker.
    #[expect(unused)] // TODO RELAY remove
    memquota: Arc<MemoryQuotaTracker>,

    /// A "client" used by relays to construct circuits.
    client: RelayClient<R>,

    /// Channel manager, used by circuits etc.
    chanmgr: Arc<ChanMgr<R>>,

    /// See [`InertTorRelay::keymgr`].
    #[expect(unused)] // TODO RELAY remove
    keymgr: Arc<KeyMgr>,

    /// Listening OR ports.
    or_listeners: Vec<<R as NetStreamProvider<SocketAddr>>::Listener>,

    /// Advertised IP address(es) found in the config file.
    ///
    /// They are kept here so they can be passed on to the OR listener task which in turn uses them
    /// for new inbound channels to send them in the NETINFO cell.
    advertised_addresses: crate::config::Advertise,
}

impl<R: Runtime> TorRelay<R> {
    /// Create a new Tor relay with the given [`runtime`][tor_rtcompat].
    ///
    /// We use this to initialize components, open sockets, etc.
    /// Doing work with these components should happen in [`TorRelay::run()`].
    ///
    /// Expected to be called from [`InertTorRelay::init()`].
    async fn init(runtime: R, inert: InertTorRelay) -> anyhow::Result<Self> {
        let memquota = MemoryQuotaTracker::new(&runtime, inert.config.system.memory.clone())
            .context("Failed to initialize memquota tracker")?;

        let chanmgr = Arc::new(ChanMgr::new(
            runtime.clone(),
            ChanMgrConfig::new(inert.config.channel.clone()),
            Dormancy::Active,
            &NetParameters::default(),
            memquota.clone(),
        ));

        let client = RelayClient::new(
            runtime.clone(),
            Arc::clone(&chanmgr),
            &inert.config,
            &inert.config,
            inert.dirmgr_config,
            inert.state_mgr,
        )
        .context("Failed to construct the relay's client")?;

        // An iterator of `listen()` futures with some extra error handling.
        let or_listeners = inert.config.relay.listen.addrs().map(async |addr| {
            match runtime.listen(addr).await {
                Ok(x) => Some(Ok(x)),
                // If we don't support the address family (typically IPv6), only warn.
                #[cfg(unix)]
                Err(ref e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => {
                    let message =
                        format!("Could not listen at {addr}: address family not supported");
                    if addr.is_ipv6() {
                        warn!("{message}");
                    } else {
                        // If we got `EAFNOSUPPORT` for a non-IPv6 address, then warn louder.
                        tor_error::warn_report!(e, "{message}");
                    }
                    None
                }
                Err(e) => {
                    Some(Err(e).with_context(|| format!("Failed to listen at address {addr}")))
                }
            }
        });

        // We await the futures sequentially rather than with something like `join_all` to make
        // errors more reproducible.
        let or_listeners = {
            let mut awaited_listeners = vec![];
            for listener in or_listeners {
                match listener.await {
                    Some(Ok(x)) => awaited_listeners.push(x),
                    Some(Err(e)) => return Err(e),
                    None => {}
                };
            }
            awaited_listeners
        };

        // Typically we would have returned with an error if we failed to listen on an address,
        // but we ignore `EAFNOSUPPORT` errors above, so it's possible that all failed with
        // `EAFNOSUPPORT` and we ended up here.
        if or_listeners.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not listen at any OR port addresses: {}",
                crate::util::iter_join(", ", inert.config.relay.listen.addrs()),
            ));
        }

        Ok(Self {
            runtime,
            memquota,
            client,
            chanmgr,
            keymgr: inert.keymgr,
            or_listeners,
            advertised_addresses: inert.config.relay.advertise,
        })
    }

    /// Run the actual relay.
    ///
    /// This only returns if something has gone wrong.
    /// Otherwise it runs forever.
    pub(crate) async fn run(self) -> anyhow::Result<void::Void> {
        let mut task_handles = JoinSet::new();

        // Channel housekeeping task.
        task_handles.spawn({
            let mut t = crate::tasks::ChannelHouseKeepingTask::new(&self.chanmgr);
            async move {
                t.start()
                    .await
                    .context("Failed to run channel house keeping task")
            }
        });

        // Listen for new Tor (OR) connections.
        task_handles.spawn({
            let runtime = self.runtime.clone();
            let chanmgr = Arc::clone(&self.chanmgr);
            async {
                // TODO: Should we give all tasks a `start` method?
                crate::tasks::listeners::or_listener(
                    runtime,
                    chanmgr,
                    self.or_listeners,
                    self.advertised_addresses,
                )
                .await
                .context("Failed to run OR listener task")
            }
        });

        // Launch client tasks.
        //
        // We need to hold on to these handles until the relay stops, otherwise dropping these
        // handles would stop the background tasks.
        //
        // These are `tor_rtcompat::scheduler::TaskHandle`s, which don't notify us if they
        // stop/crash.
        //
        // TODO: Whose responsibility is it to ensure that these background tasks don't crash?
        // Should we have a way of monitoring these tasks? Or should the circuit manager re-launch
        // crashed tasks?
        let _client_task_handles = self.client.launch_background_tasks();

        // TODO: More tasks will be spawned here.

        // Now that background tasks are started, bootstrap the client.
        self.client
            .bootstrap()
            .await
            .context("Failed to bootstrap the relay's client")?;

        // We block until facism is erradicated or a task ends which means the relay will shutdown
        // and facism will have one more chance.
        let void = task_handles
            .join_next()
            .await
            .context("Relay task set is empty")?
            .context("Relay task join failed")?
            .context("Relay task stopped unexpectedly")?;

        // We can never get here since a `Void` cannot be constructed.
        void::unreachable(void);
    }
}
