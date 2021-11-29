//! A general interface for Tor client usage.
//!
//! To construct a client, run the `TorClient::bootstrap()` method.
//! Once the client is bootstrapped, you can make anonymous
//! connections ("streams") over the Tor network using
//! `TorClient::connect()`.
use crate::address::IntoTorAddr;

use crate::config::{ClientAddrConfig, TorClientConfig};
use tor_circmgr::{IsolationToken, StreamIsolationBuilder, TargetPort};
use tor_dirmgr::DirEvent;
use tor_persist::{FsStateMgr, StateMgr};
use tor_proto::circuit::ClientCirc;
use tor_proto::stream::{DataStream, IpVersionPreference, StreamParameters};
use tor_rtcompat::{Runtime, SleepProviderExt};

use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::{Error, Result};
use tracing::{debug, error, info, warn};

/// An active client session on the Tor network.
///
/// While it's running, it will fetch directory information, build
/// circuits, and make connections for you.
///
/// Cloning this object makes a new reference to the same underlying
/// handles: it's usually better to clone the `TorClient` than it is to
/// create a new one.
#[derive(Clone)]
pub struct TorClient<R: Runtime> {
    /// Asynchronous runtime object.
    runtime: R,
    /// Default isolation token for streams through this client.
    client_isolation: IsolationToken,
    /// Circuit manager for keeping our circuits up to date and building
    /// them on-demand.
    circmgr: Arc<tor_circmgr::CircMgr<R>>,
    /// Directory manager for keeping our directory material up to date.
    dirmgr: Arc<tor_dirmgr::DirMgr<R>>,
    /// Client address configuration
    addrcfg: ClientAddrConfig,
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

impl<R: Runtime> TorClient<R> {
    /// Bootstrap a network connection configured by `dir_cfg` and `circ_cfg`.
    ///
    /// Return a client once there is enough directory material to
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
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(runtime.clone()));
        let circmgr =
            tor_circmgr::CircMgr::new(circ_cfg, statemgr.clone(), &runtime, Arc::clone(&chanmgr))?;
        let dirmgr = tor_dirmgr::DirMgr::bootstrap_from_config(
            dir_cfg,
            runtime.clone(),
            Arc::clone(&circmgr),
        )
        .await?;

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
            statemgr,
        ))?;

        runtime.spawn(continually_launch_timeout_testing_circuits(
            runtime.clone(),
            Arc::downgrade(&circmgr),
            Arc::downgrade(&dirmgr),
        ))?;

        let client_isolation = IsolationToken::new();

        Ok(TorClient {
            runtime,
            client_isolation,
            circmgr,
            dirmgr,
            addrcfg: addr_cfg,
        })
    }

    /// Return a new isolated `TorClient` instance.
    ///
    /// The two `TorClient`s will share some internal state, but their
    /// streams will never share circuits with one another.
    ///
    /// Use this function when you want separate parts of your program to
    /// each have a TorClient handle, but where you don't want their
    /// activities to be linkable to one another over the Tor network.
    ///
    /// Calling this function is usually preferable to creating a
    /// completely separate TorClient instance, since it can share its
    /// internals with the existing `TorClient`.
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
    pub async fn connect<A: IntoTorAddr>(
        &self,
        target: A,
        flags: Option<ConnectPrefs>,
    ) -> Result<DataStream> {
        let addr = target.into_tor_addr()?;
        addr.enforce_config(&self.addrcfg)?;
        let (addr, port) = addr.into_string_and_port();

        let flags = flags.unwrap_or_default();
        let exit_ports = [flags.wrap_target_port(port)];
        let circ = self.get_or_launch_exit_circ(&exit_ports, &flags).await?;
        info!("Got a circuit for {}:{}", addr, port);

        // TODO: make this configurable.
        let stream_timeout = Duration::new(10, 0);

        let stream_future = circ.begin_stream(&addr, port, Some(flags.stream_parameters()));
        // This timeout is needless but harmless for optimistic streams.
        let stream = self
            .runtime
            .timeout(stream_timeout, stream_future)
            .await??;

        Ok(stream)
    }

    /// On success, return a list of IP addresses.
    pub async fn resolve(
        &self,
        hostname: &str,
        flags: Option<ConnectPrefs>,
    ) -> Result<Vec<IpAddr>> {
        let addr = (hostname, 0).into_tor_addr()?;
        addr.enforce_config(&self.addrcfg)?;

        let flags = flags.unwrap_or_default();
        let circ = self.get_or_launch_exit_circ(&[], &flags).await?;

        // TODO: make this configurable.
        let resolve_timeout = Duration::new(10, 0);

        let resolve_future = circ.resolve(hostname);
        let addrs = self
            .runtime
            .timeout(resolve_timeout, resolve_future)
            .await??;

        Ok(addrs)
    }

    /// Perform a remote DNS reverse lookup with the provided IP address.
    ///
    /// On success, return a list of hostnames.
    pub async fn resolve_ptr(
        &self,
        addr: IpAddr,
        flags: Option<ConnectPrefs>,
    ) -> Result<Vec<String>> {
        let flags = flags.unwrap_or_default();
        let circ = self.get_or_launch_exit_circ(&[], &flags).await?;

        // TODO: make this configurable.
        let resolve_ptr_timeout = Duration::new(10, 0);

        let resolve_ptr_future = circ.resolve_ptr(addr);
        let hostnames = self
            .runtime
            .timeout(resolve_ptr_timeout, resolve_ptr_future)
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
        flags: &ConnectPrefs,
    ) -> Result<Arc<ClientCirc>> {
        let dir = self.dirmgr.netdir();

        let isolation = {
            let mut b = StreamIsolationBuilder::new();
            // Always consider our client_isolation.
            b.owner_token(self.client_isolation);
            // Consider stream isolation too, if it's set.
            if let Some(tok) = flags.isolation_group() {
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
        // XXXX This delay is probably too small.
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
    loop {
        let delay;
        if let (Some(cm), Some(dm)) = (Weak::upgrade(&circmgr), Weak::upgrade(&dirmgr)) {
            let netdir = dm.netdir();
            if let Err(e) = cm.launch_timeout_testing_circuit_if_appropriate(&netdir) {
                warn!("Problem launching a timeout testing circuit: {}", e);
            }
            delay = netdir
                .params()
                .cbt_testing_delay
                .try_into()
                .expect("Out-of-bounds value from BoundedInt32");
        } else {
            break;
        };

        rt.sleep(delay).await;
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
