//! Entry point of a Tor relay that is the [`TorRelay`] objects

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use anyhow::Context;
use tokio::task::JoinSet;
use tracing::debug;
#[cfg(unix)]
use tracing::warn;

use fs_mistrust::Mistrust;
use tor_basic_utils::iter_join;
use tor_cell::relaycell::RelayCmd;
use tor_chanmgr::{ChanMgr, ChanMgrConfig, Dormancy};
use tor_config_path::CfgPathResolver;
use tor_dircommon::authority::AuthorityContacts;
use tor_dircommon::config::{DirTolerance, DownloadScheduleConfig};
use tor_dirmgr::DirMgrConfig;
use tor_dirserver::mirror::DirMirror;
use tor_keymgr::{ArtiNativeKeystore, KeyMgr, KeyMgrBuilder};
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::params::NetParameters;
use tor_persist::state_dir::StateDirectory;
use tor_persist::{FsStateMgr, StateMgr};
use tor_proto::relay::{CircuitIncomingStreamReceiver, CreateRequestHandler};
use tor_rtcompat::{NetStreamProvider, Runtime};

use crate::client::RelayClient;
use crate::config::TorRelayConfig;
use crate::stream::RequestFilter;
use crate::tasks::channel::build_circ_net_params;
use crate::tasks::crypto::InitKeyMaterial;

use futures::channel::mpsc;

// TODO(relay): this is in the client module, but not client-specific
use tor_proto::client::stream::DataStream;

/// An initialized but unbootstrapped relay.
///
/// This intentionally does not have access to the runtime to prevent it from doing network io.
///
/// The idea is that we can build up the relay's components in an `InertTorRelay` without a runtime,
/// and then call `init()` on it and provide a runtime to turn it into a network-capable relay.
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

    /// Key manager.
    keymgr: KeyMgr,
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
        let init_key_material = crate::tasks::crypto::init_keys(&runtime, &self.keymgr)
            .context("Failed to generate keys")?;

        TorRelay::init(runtime, self, init_key_material).await
    }

    /// Create the [key manager](KeyMgr).
    fn create_keymgr(state_path: &Path, mistrust: &Mistrust) -> anyhow::Result<KeyMgr> {
        let key_store_dir = state_path.join("keystore");

        let persistent_store = ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, mistrust)
            .context("Failed to construct the native keystore")?;

        // Should only log fs paths at debug level or lower,
        // unless they're part of a diagnostic message.
        debug!("Using relay keystore from {key_store_dir:?}");

        let keymgr = KeyMgrBuilder::default()
            .primary_store(Box::new(persistent_store))
            .build()
            .context("Failed to build the 'KeyMgr'")?;

        // TODO: support C-tor keystore

        Ok(keymgr)
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

    /// The directory authorities that were either configured or the compiled-in defaults.
    ///
    /// We keep a copy here so we can pass it to the descriptor publisher task. These are not
    /// exposed by a [`tor_dirmgr::DirProvider`] hence why we keep that copy from the config.
    authorities: AuthorityContacts,

    /// The directory mirror object, used for handling BEGIN_DIR.
    dir_mirror: DirMirror,

    /// Channel manager, used by circuits etc.
    chanmgr: Arc<ChanMgr<R>>,

    /// Handles CREATE* requests on channels.
    ///
    /// Given to the [`ChanMgr`],
    /// which gives it to each channel.
    /// We can access this handler directly to update consensus parameters or keys.
    create_request_handler: Arc<CreateRequestHandler>,

    /// The receiver for the [`Stream`](futures::Stream)s of `IncomingStream` of all circuits.
    ///
    /// Receives one [`Stream`](futures::Stream) (of tor streams) per circuit.
    /// Each of these is handled in a new task.
    circuit_stream_rx: CircuitIncomingStreamReceiver,

    /// See [`InertTorRelay::keymgr`].
    keymgr: KeyMgr,

    /// Listening OR ports.
    or_listeners: Vec<<R as NetStreamProvider<SocketAddr>>::Listener>,
}

impl<R: Runtime> TorRelay<R> {
    /// Create a new Tor relay with the given [`runtime`][tor_rtcompat].
    ///
    /// We use this to initialize components, open sockets, etc.
    /// Doing work with these components should happen in [`TorRelay::run()`].
    ///
    /// Expected to be called from [`InertTorRelay::init()`].
    async fn init(
        runtime: R,
        inert: InertTorRelay,
        init_key_material: InitKeyMaterial,
    ) -> anyhow::Result<Self> {
        let memquota = MemoryQuotaTracker::new(&runtime, inert.config.system.memory.clone())
            .context("Failed to initialize memquota tracker")?;

        // Init the channel manager.
        let config = ChanMgrConfig::new(inert.config.channel.clone())
            .with_my_addrs(inert.config.relay.advertise.all_addr())
            .with_auth_material(Arc::new(init_key_material.chan_auth_keys));
        let chanmgr = Arc::new(
            ChanMgr::new(
                runtime.clone(),
                config,
                Dormancy::Active,
                // TODO: It seems wrong to start with the compiled-in defaults when we might have
                // a newer network status on disk that would provide a better initial value,
                // but `TorClient` does this too so let's not worry about it.
                &NetParameters::default(),
                memquota.clone(),
            )
            .context("Failed to build chan manager")?,
        );

        let authorities = inert.dirmgr_config.authorities().clone();

        // Init the relay's client.
        let client = RelayClient::new(
            runtime.clone(),
            Arc::clone(&chanmgr),
            &inert.config,
            &inert.config,
            inert.dirmgr_config,
            inert.state_mgr,
        )
        .context("Failed to construct the relay's client")?;

        // Circuit-related network status parameters.
        let circ_net_params = build_circ_net_params(client.dirmgr().params().as_ref().as_ref())
            .context("Failed to build circuit parameters for CREATE* request handler")?;

        // TODO(relay): add exit configuration, and update this to reject BEGIN and RESOLVE
        // if we are not configured to run as an exit
        let allow_incoming = &[RelayCmd::BEGIN, RelayCmd::BEGIN_DIR, RelayCmd::RESOLVE];

        // A handler that will process CREATE* requests on channels.
        let (create_request_handler, circuit_stream_rx) = CreateRequestHandler::new(
            Arc::downgrade(&chanmgr) as Weak<_>,
            circ_net_params,
            init_key_material.ntor_keys,
            Box::new(|| Box::new(RequestFilter::default()) as Box<_>),
            allow_incoming,
        );
        let create_request_handler = Arc::new(create_request_handler);

        // Configure the channel manager to handle CREATE* requests.
        //
        // We do this once, and can later update its network parameters and keys using the
        // `Arc` handle that we store.
        // The `ChanMgr` will hold an `Arc<CreateRequestHandler>` and
        // the `CreateRequestHandler` will hold a `Weak<ChanMgr>`.
        //
        // We could technically do something fancier by creating the `ChanMgr` and handler
        // inside an `Arc::new_cyclic()` and pass the handler as part of the `ChanMgrConfig`,
        // but the code becomes a mess.
        chanmgr
            .set_create_request_handler(Arc::clone(&create_request_handler))
            .context("Failed to set the CREATE* request handler")?;

        // We don't use any custom options on the listening socket.
        let listen_options = Default::default();

        // An iterator of `listen()` futures with some extra error handling.
        let or_listeners = inert.config.relay.listen.addrs().map(async |addr| {
            match runtime.listen(addr, &listen_options).await {
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
                iter_join(", ", inert.config.relay.listen.addrs()),
            ));
        }

        // TODO DIRMIRROR: Need a config for the DirMirror and should be same as our
        // TorRelay one.
        let path: PathBuf = PathBuf::from("/dev/null");
        let dir_mirror_authorities: AuthorityContacts = Default::default();
        let schedule: DownloadScheduleConfig = Default::default();
        let tolerance: DirTolerance = Default::default();

        let dir_mirror = DirMirror::new(path, dir_mirror_authorities, schedule, tolerance);

        Ok(Self {
            runtime,
            memquota,
            client,
            authorities,
            dir_mirror,
            chanmgr,
            create_request_handler,
            keymgr: inert.keymgr,
            or_listeners,
            circuit_stream_rx,
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

        // Update the CREATE* request handler when there are new network parameters.
        task_handles.spawn({
            let create_request_handler = Arc::clone(&self.create_request_handler);
            let dir_provider = Arc::clone(self.client.dirmgr());
            async {
                crate::tasks::channel::update_create_request_handler_netparams(
                    create_request_handler,
                    dir_provider as Arc<_>,
                )
                .await
                .context("Failed to run create request handler update task")
            }
        });

        // Listen for new Tor (OR) connections.
        task_handles.spawn({
            let runtime = self.runtime.clone();
            let chanmgr = Arc::clone(&self.chanmgr);
            async {
                // TODO: Should we give all tasks a `start` method?
                crate::tasks::listeners::or_listener(runtime, chanmgr, self.or_listeners)
                    .await
                    .context("Failed to run OR listener task")
            }
        });

        // TODO DIRMIRROR: The buffer size here was picked mostly arbitrarily
        // (on my new and not-very-busy relay, I noticed bursts of ~5000 BEGIN_DIR requests per second,
        // but I'm not sure how representative this is).
        //
        // We may be able to make this buffer even smaller, assuming the consumer (i.e. DirMirror)
        // reads from it quickly enough (presumably it will read from this in a loop,
        // dispatching each request to a new task?)
        #[allow(clippy::disallowed_methods)]
        let (begin_dir_tx, begin_dir_rx) = mpsc::channel::<tor_proto::Result<DataStream>>(4096);

        // Spawn a directory mirror server task, if we are a dir cache.
        task_handles.spawn(async {
            // TODO DIRMIRROR: it would be nicer if serve() returned
            // Result<Void, _> to statically prove that it indeed never
            // returns with a non-error.
            // Plus, if we do that, we can simplify this invocation,
            // because we won't need the anyhow! error below.
            self.dir_mirror.serve(begin_dir_rx).await?;
            Err(anyhow::anyhow!("dir mirror exited"))
        });

        let runtime = self.runtime.clone();
        // Listen for new Tor streams
        task_handles.spawn(
            // TODO: Should we give all tasks a `start` method?
            crate::stream::handle_incoming_streams(runtime, begin_dir_tx, self.circuit_stream_rx),
        );

        // Channel used to ask the descriptor publisher to rebuild and re-publish the descriptor.
        let (desc_command_tx, desc_command_rx) = crate::tasks::descriptor::new_command_channel();
        let (crypto_command_tx, crypto_command_rx) = crate::tasks::crypto::new_command_channel();

        // Start the crypto task.
        task_handles.spawn({
            let reactor = crate::tasks::crypto::Reactor::new(
                self.runtime.clone(),
                self.chanmgr.clone(),
                self.create_request_handler.clone(),
                self.keymgr,
                self.client.dirmgr().clone(),
                desc_command_tx,
                crypto_command_rx,
            )?;
            async {
                reactor
                    .run()
                    .await
                    .context("Failed to run key rotation task")
            }
        });

        // Build and publish the relay's own descriptor.
        task_handles.spawn({
            let netdir = Arc::clone(self.client.dirmgr()) as Arc<_>;
            let authorities = self.authorities;
            async move {
                crate::tasks::RelayDescriptorPublisherTask::new(
                    &self.runtime,
                    netdir,
                    authorities,
                    crypto_command_tx,
                    desc_command_rx,
                )
                .context("Failed to create descriptor publisher task")?
                .start()
                .await
                .context("Failed to run descriptor publisher task")
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
