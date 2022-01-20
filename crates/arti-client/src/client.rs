//! A general interface for Tor client usage.
//!
//! To construct a client, run the `TorClient::bootstrap()` method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! `TorClient::connect()`.
use crate::address::IntoTorAddr;

use crate::config::{ClientAddrConfig, StreamTimeoutConfig, TorClientConfig};
use tor_circmgr::{DirInfo, IsolationToken, StreamIsolationBuilder, TargetPort};
use tor_config::MutCfg;
use tor_dirmgr::DirEvent;
use tor_persist::{FsStateMgr, StateMgr};
use tor_proto::circuit::ClientCirc;
use tor_proto::stream::{DataStream, IpVersionPreference, StreamParameters};
use tor_rtcompat::{Runtime, SleepProviderExt};

use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::{status, Error, Result};
#[cfg(feature = "async-std")]
use tor_rtcompat::async_std::AsyncStdRuntime;
#[cfg(feature = "tokio")]
use tor_rtcompat::tokio::TokioRuntimeHandle;
use tracing::{debug, error, info, warn};

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
    /// to the `stream_token` which comes from `connect_prefs` (or a passed-in `ConnectPrefs`).
    /// (ie, both must be the same to share a circuit).
    client_isolation: IsolationToken,
    /// Connection preferences.  Starts out as `Default`,  Inherited by our clones.
    connect_prefs: ConnectPrefs,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<tor_dirmgr::DirMgr<R>>,
    /// Location on disk where we store persistent data.
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
}

/// Preferences for how to route a stream over the Tor network.
#[derive(Debug, Clone, Default)]
pub struct ConnectPrefs {
    /// What kind of IPv6/IPv4 we'd prefer, and how strongly.
    ip_ver_pref: IpVersionPreference,
    /// Id of the isolation group the connection should be part of
    isolation_group: Option<IsolationToken>,
    /// Whether to return the stream optimistically.
    optimistic_stream: bool,
}

impl ConnectPrefs {
    /// Construct a new ConnectPrefs.
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

    /// Indicate which other connections might use the same circuit
    /// as this one.
    ///
    /// By default all connections made on all clones of a `TorClient` may share connections.
    /// Connections made with a particular `isolation_group` may share circuits with each other.
    ///
    /// This connection preference is orthogonal to isolation established by
    /// [`TorClient::isolated_client`].  Connections made with an `isolated_client` (and its
    /// clones) will not share circuits with the original client, even if the same
    /// `isolation_group` is specified via the `ConnectionPrefs` in force.
    pub fn set_isolation_group(&mut self, isolation_group: IsolationToken) -> &mut Self {
        self.isolation_group = Some(isolation_group);
        self
    }

    /// Return a token to describe which connections might use
    /// the same circuit as this one.
    fn isolation_group(&self) -> Option<IsolationToken> {
        self.isolation_group
    }

    // TODO: Add some way to be IPFlexible, and require exit to support both.
}

#[cfg(feature = "tokio")]
impl TorClient<TokioRuntimeHandle> {
    /// Bootstrap a connection to the Tor network, using the current Tokio runtime.
    ///
    /// Returns a client once there is enough directory material to
    /// connect safely over the Tor network.
    ///
    /// This is a convenience wrapper around [`TorClient::bootstrap`].
    ///
    /// # Panics
    ///
    /// Panics if called outside of the context of a Tokio runtime.
    pub async fn bootstrap_with_tokio(
        config: TorClientConfig,
    ) -> Result<TorClient<TokioRuntimeHandle>> {
        let rt = tor_rtcompat::tokio::current_runtime().expect("called outside of Tokio runtime");
        Self::bootstrap(rt, config).await
    }
}

#[cfg(feature = "async-std")]
impl TorClient<AsyncStdRuntime> {
    /// Bootstrap a connection to the Tor network, using the current async-std runtime.
    ///
    /// Returns a client once there is enough directory material to
    /// connect safely over the Tor network.
    ///
    /// This is a convenience wrapper around [`TorClient::bootstrap`].
    pub async fn bootstrap_with_async_std(
        config: TorClientConfig,
    ) -> Result<TorClient<AsyncStdRuntime>> {
        // FIXME(eta): not actually possible for this to fail
        let rt =
            tor_rtcompat::async_std::current_runtime().expect("failed to get async-std runtime");
        Self::bootstrap(rt, config).await
    }
}

impl<R: Runtime> TorClient<R> {
    /// Bootstrap a connection to the Tor network, using the provided `config` and `runtime` (a
    /// [`tor_rtcompat`] [`Runtime`](tor_rtcompat::Runtime)).
    ///
    /// Returns a client once there is enough directory material to
    /// connect safely over the Tor network.
    pub async fn bootstrap(runtime: R, config: TorClientConfig) -> Result<TorClient<R>> {
        let circ_cfg = config.get_circmgr_config()?;
        let dir_cfg = config.get_dirmgr_config()?;
        let statemgr = FsStateMgr::from_path(config.storage.expand_state_dir()?)?;
        if statemgr.try_lock()?.held() {
            debug!("It appears we have the lock on our state files.");
        } else {
            info!(
                "Another process has the lock on our state files. We'll proceed in read-only mode."
            );
        }
        let addr_cfg = config.address_filter.clone();
        let timeout_cfg = config.stream_timeouts.clone();

        let (status_sender, status_receiver) = postage::watch::channel();
        let status_receiver = status::BootstrapEvents {
            inner: status_receiver,
        };
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(runtime.clone()));
        let circmgr =
            tor_circmgr::CircMgr::new(circ_cfg, statemgr.clone(), &runtime, Arc::clone(&chanmgr))?;
        let dirmgr = tor_dirmgr::DirMgr::bootstrap_from_config(
            dir_cfg,
            runtime.clone(),
            Arc::clone(&circmgr),
        )
        .await?;

        // TODO: This happens too late.  We need to create dirmgr and get its
        // event stream, and only THEN get its status.

        let conn_status = chanmgr.bootstrap_events();
        let dir_status = dirmgr.bootstrap_events();
        runtime.spawn(status::report_status(
            status_sender,
            conn_status,
            dir_status,
        ))?;

        circmgr.update_network_parameters(dirmgr.netdir().params());

        // Launch a daemon task to inform the circmgr about new
        // network parameters.
        runtime.spawn(keep_circmgr_params_updated(
            dirmgr.events(),
            Arc::downgrade(&circmgr),
            Arc::downgrade(&dirmgr),
        ))?;

        runtime.spawn(update_persistent_state(
            runtime.clone(),
            Arc::downgrade(&circmgr),
            statemgr.clone(),
        ))?;

        runtime.spawn(continually_launch_timeout_testing_circuits(
            runtime.clone(),
            Arc::downgrade(&circmgr),
            Arc::downgrade(&dirmgr),
        ))?;

        runtime.spawn(continually_preemptively_build_circuits(
            runtime.clone(),
            Arc::downgrade(&circmgr),
            Arc::downgrade(&dirmgr),
        ))?;

        let client_isolation = IsolationToken::new();

        Ok(TorClient {
            runtime,
            client_isolation,
            connect_prefs: Default::default(),
            circmgr,
            dirmgr,
            statemgr,
            addrcfg: Arc::new(addr_cfg.into()),
            timeoutcfg: Arc::new(timeout_cfg.into()),
            reconfigure_lock: Arc::new(Mutex::new(())),
            status_receiver,
        })
    }

    /// Change the configuration of this TorClient to `new_config`.
    ///
    /// The `how` describes whether to perform an all-or-nothing
    /// reconfiguration: either all of the configuration changes will be
    /// applied, or none will. If you have disabled all-or-nothing changes, then
    /// only fatal errors will be reported in this function's return value.
    ///
    /// This function applies its changes to **all** TorClient instances derived
    /// from the same call to [`TorClient::bootstrap`]: even ones whose circuits
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
    ) -> Result<()> {
        // We need to hold this lock while we're reconfiguring the client: even
        // though the individual fields have their own synchronization, we can't
        // safely let two threads change them at once.  If we did, then we'd
        // introduce time-of-check/time-of-use bugs in checking our configuration,
        // deciding how to change it, then applying the changes.
        let _guard = self.reconfigure_lock.lock().expect("Poisoned lock");

        match how {
            tor_config::Reconfigure::AllOrNothing => {
                // We have to check before we make any changes.
                self.reconfigure(new_config, tor_config::Reconfigure::CheckAllOrNothing)?;
            }
            tor_config::Reconfigure::CheckAllOrNothing => {}
            tor_config::Reconfigure::WarnOnFailures => {}
            _ => {}
        }

        let circ_cfg = new_config.get_circmgr_config()?;
        let dir_cfg = new_config.get_dirmgr_config()?;
        let state_cfg = new_config.storage.expand_state_dir()?;
        let addr_cfg = &new_config.address_filter;
        let timeout_cfg = &new_config.stream_timeouts;

        if state_cfg != self.statemgr.path() {
            how.cannot_change("storage.state_dir")?;
        }

        self.circmgr.reconfigure(&circ_cfg, how)?;
        self.dirmgr.reconfigure(&dir_cfg, how)?;

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

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    pub async fn connect<A: IntoTorAddr>(&self, target: A) -> Result<DataStream> {
        self.connect_with_prefs(target, &self.connect_prefs).await
    }

    /// Launch an anonymized connection to the provided address and
    /// port over the Tor network, with explicit connection preferences.
    ///
    /// Note that because Tor prefers to do DNS resolution on the remote
    /// side of the network, this function takes its address as a string.
    pub async fn connect_with_prefs<A: IntoTorAddr>(
        &self,
        target: A,
        prefs: &ConnectPrefs,
    ) -> Result<DataStream> {
        let addr = target.into_tor_addr()?;
        addr.enforce_config(&self.addrcfg.get())?;
        let (addr, port) = addr.into_string_and_port();

        let exit_ports = [prefs.wrap_target_port(port)];
        let circ = self.get_or_launch_exit_circ(&exit_ports, prefs).await?;
        info!("Got a circuit for {}:{}", addr, port);

        let stream_future = circ.begin_stream(&addr, port, Some(prefs.stream_parameters()));
        // This timeout is needless but harmless for optimistic streams.
        let stream = self
            .runtime
            .timeout(self.timeoutcfg.get().connect_timeout, stream_future)
            .await??;

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
    //
    // This function is private just because we're not sure we want to provide this API.
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/250#note_2771238
    fn set_connect_prefs(&mut self, connect_prefs: ConnectPrefs) {
        self.connect_prefs = connect_prefs;
    }

    /// Provides a new handle on this client, but with adjusted default preferences.
    ///
    /// Connections made with e.g. [`connect`](TorClient::connect) on the returned handle will use
    /// `connect_prefs`.  This is a convenience wrapper for `clone` and `set_connect_prefs`.
    #[must_use]
    pub fn clone_with_prefs(&self, connect_prefs: ConnectPrefs) -> Self {
        let mut result = self.clone();
        result.set_connect_prefs(connect_prefs);
        result
    }

    /// On success, return a list of IP addresses.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        self.resolve_with_prefs(hostname, &self.connect_prefs).await
    }

    /// On success, return a list of IP addresses, but use prefs.
    pub async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &ConnectPrefs,
    ) -> Result<Vec<IpAddr>> {
        let addr = (hostname, 0).into_tor_addr()?;
        addr.enforce_config(&self.addrcfg.get())?;

        let circ = self.get_or_launch_exit_circ(&[], prefs).await?;

        let resolve_future = circ.resolve(hostname);
        let addrs = self
            .runtime
            .timeout(self.timeoutcfg.get().resolve_timeout, resolve_future)
            .await??;

        Ok(addrs)
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    pub async fn resolve_ptr(&self, addr: IpAddr) -> Result<Vec<String>> {
        self.resolve_ptr_with_prefs(addr, &self.connect_prefs).await
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    pub async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &ConnectPrefs,
    ) -> Result<Vec<String>> {
        let circ = self.get_or_launch_exit_circ(&[], prefs).await?;

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .runtime
            .timeout(
                self.timeoutcfg.get().resolve_ptr_timeout,
                resolve_ptr_future,
            )
            .await??;

        Ok(hostnames)
    }

    /// Return a reference to this this client's directory manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn dirmgr(&self) -> Arc<tor_dirmgr::DirMgr<R>> {
        Arc::clone(&self.dirmgr)
    }

    /// Return a reference to this this client's circuit manager.
    ///
    /// This function is unstable. It is only enabled if the crate was
    /// built with the `experimental-api` feature.
    #[cfg(feature = "experimental-api")]
    pub fn circmgr(&self) -> Arc<tor_circmgr::CircMgr<R>> {
        Arc::clone(&self.circmgr)
    }

    /// Get or launch an exit-suitable circuit with a given set of
    /// exit ports.
    async fn get_or_launch_exit_circ(
        &self,
        exit_ports: &[TargetPort],
        prefs: &ConnectPrefs,
    ) -> Result<ClientCirc> {
        let dir = self.dirmgr.netdir();

        let isolation = {
            let mut b = StreamIsolationBuilder::new();
            // Always consider our client_isolation.
            b.owner_token(self.client_isolation);
            // Consider stream isolation too, if it's set.
            if let Some(tok) = prefs.isolation_group() {
                b.stream_token(tok);
            }
            // Failure should be impossible with this builder.
            b.build().expect("Failed to construct StreamIsolation")
        };

        let circ = self
            .circmgr
            .get_or_launch_exit(dir.as_ref().into(), exit_ports, isolation)
            .await
            .map_err(|_| Error::Internal("Unable to launch circuit"))?;
        drop(dir); // This decreases the refcount on the netdir.

        Ok(circ)
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
    //
    // TODO(nickm): by the time the `TorClient` is visible to the user, this
    // status is always true.  That will change with #293, however, and will
    // also change as BootstrapStatus becomes more complex with #96.
    pub fn bootstrap_events(&self) -> status::BootstrapEvents {
        self.status_receiver.clone()
    }
}

/// Whenever a [`DirEvent::NewConsensus`] arrives on `events`, update
/// `circmgr` with the consensus parameters from `dirmgr`.
///
/// Exit when `events` is closed, or one of `circmgr` or `dirmgr` becomes
/// dangling.
///
/// This is a daemon task: it runs indefinitely in the background.
async fn keep_circmgr_params_updated<R: Runtime>(
    mut events: impl futures::Stream<Item = DirEvent> + Unpin,
    circmgr: Weak<tor_circmgr::CircMgr<R>>,
    dirmgr: Weak<tor_dirmgr::DirMgr<R>>,
) {
    use DirEvent::*;
    while let Some(event) = events.next().await {
        match event {
            NewConsensus => {
                if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                    cm.update_network_parameters(dm.netdir().params());
                    cm.update_network(&dm.netdir());
                } else {
                    debug!("Circmgr or dirmgr has disappeared; task exiting.");
                    break;
                }
            }
            NewDescriptors => {
                if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
                    cm.update_network(&dm.netdir());
                } else {
                    debug!("Circmgr or dirmgr has disappeared; task exiting.");
                    break;
                }
            }
            _ => {
                // Nothing we recognize.
            }
        }
    }
}

/// Run forever, periodically telling `circmgr` to update its persistent
/// state.
///
/// Exit when we notice that `circmgr` has been dropped.
///
/// This is a daemon task: it runs indefinitely in the background.
async fn update_persistent_state<R: Runtime>(
    runtime: R,
    circmgr: Weak<tor_circmgr::CircMgr<R>>,
    statemgr: FsStateMgr,
) {
    // TODO: Consider moving this function into tor-circmgr after we have more
    // experience with the state system.

    loop {
        if let Some(circmgr) = Weak::upgrade(&circmgr) {
            use tor_persist::LockStatus::*;

            match statemgr.try_lock() {
                Err(e) => {
                    error!("Problem with state lock file: {}", e);
                    break;
                }
                Ok(NewlyAcquired) => {
                    info!("We now own the lock on our state files.");
                    if let Err(e) = circmgr.upgrade_to_owned_persistent_state() {
                        error!("Unable to upgrade to owned state files: {}", e);
                        break;
                    }
                }
                Ok(AlreadyHeld) => {
                    if let Err(e) = circmgr.store_persistent_state() {
                        error!("Unable to flush circmgr state: {}", e);
                        break;
                    }
                }
                Ok(NoLock) => {
                    if let Err(e) = circmgr.reload_persistent_state() {
                        error!("Unable to reload circmgr state: {}", e);
                        break;
                    }
                }
            }
        } else {
            debug!("Circmgr has disappeared; task exiting.");
            return;
        }
        // TODO(nickm): This delay is probably too small.
        //
        // Also, we probably don't even want a fixed delay here.  Instead,
        // we should be updating more frequently when the data is volatile
        // or has important info to save, and not at all when there are no
        // changes.
        runtime.sleep(Duration::from_secs(60)).await;
    }

    error!("State update task is exiting prematurely.");
}

/// Run indefinitely, launching circuits as needed to get a good
/// estimate for our circuit build timeouts.
///
/// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
///
/// This is a daemon task: it runs indefinitely in the background.
///
/// # Note
///
/// I'd prefer this to be handled entirely within the tor-circmgr crate;
/// see [`tor_circmgr::CircMgr::launch_timeout_testing_circuit_if_appropriate`]
/// for more information.
async fn continually_launch_timeout_testing_circuits<R: Runtime>(
    rt: R,
    circmgr: Weak<tor_circmgr::CircMgr<R>>,
    dirmgr: Weak<tor_dirmgr::DirMgr<R>>,
) {
    while let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
        let netdir = dm.netdir();
        if let Err(e) = cm.launch_timeout_testing_circuit_if_appropriate(&netdir) {
            warn!("Problem launching a timeout testing circuit: {}", e);
        }
        let delay = netdir
            .params()
            .cbt_testing_delay
            .try_into()
            .expect("Out-of-bounds value from BoundedInt32");

        drop((cm, dm));
        rt.sleep(delay).await;
    }
}

/// Run indefinitely, launching circuits where the preemptive circuit
/// predictor thinks it'd be a good idea to have them.
///
/// Exit when we notice that `circmgr` or `dirmgr` has been dropped.
///
/// This is a daemon task: it runs indefinitely in the background.
///
/// # Note
///
/// This would be better handled entirely within `tor-circmgr`, like
/// other daemon tasks.
async fn continually_preemptively_build_circuits<R: Runtime>(
    rt: R,
    circmgr: Weak<tor_circmgr::CircMgr<R>>,
    dirmgr: Weak<tor_dirmgr::DirMgr<R>>,
) {
    while let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
        let netdir = dm.netdir();
        cm.launch_circuits_preemptively(DirInfo::Directory(&netdir))
            .await;
        rt.sleep(Duration::from_secs(10)).await;
    }
}

impl<R: Runtime> Drop for TorClient<R> {
    // TODO: Consider moving this into tor-circmgr after we have more
    // experience with the state system.
    fn drop(&mut self) {
        match self.circmgr.store_persistent_state() {
            Ok(()) => info!("Flushed persistent state at exit."),
            Err(tor_circmgr::Error::State(tor_persist::Error::NoLock)) => {
                debug!("Lock not held; no state to flush.");
            }
            Err(e) => error!("Unable to flush state on client exit: {}", e),
        }
    }
}
