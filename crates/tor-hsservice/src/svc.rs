//! Principal types for onion services.
mod netdir;

use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::Stream;
use tor_circmgr::hspool::HsCircPool;
use tor_config::ReconfigureError;
use tor_error::Bug;
use tor_keymgr::KeyMgr;
use tor_llcrypto::pk::curve25519;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::ipt_mgr::IptManager;
use crate::ipt_set::IptsManagerView;
use crate::svc::publish::Publisher;
use crate::OnionServiceConfig;
use crate::OnionServiceStatus;
use crate::RendRequest;
use crate::StartupError;

pub(crate) mod ipt_establish;
pub(crate) mod publish;
pub(crate) mod rend_handshake;

/// Convenience alias for link specifiers of an intro point
pub(crate) type LinkSpecs = Vec<tor_linkspec::EncodedLinkSpec>;

/// Convenient type alias for an ntor public key
// TODO HSS maybe this should be `tor_proto::crypto::handshake::ntor::NtorPublicKey`?
type NtorPublicKey = curve25519::PublicKey;

/// A handle to an instance of an onion service.
//
// TODO HSS: Write more.
//
// (APIs should return Arc<OnionService>)
pub struct OnionService {
    /// The mutable implementation details of this onion service.
    inner: Mutex<SvcInner>,
}

/// Implementation details for an onion service.
struct SvcInner {
    /// Configuration information about this service.
    config_tx: postage::watch::Sender<Arc<OnionServiceConfig>>,

    /// A keymgr used to look up our keys and store new medium-term keys.
    //
    // TODO HSS: Do we actually need this in this structure?
    keymgr: Arc<KeyMgr>,

    /// A oneshot that will be dropped when this object is dropped.
    shutdown_tx: oneshot::Sender<void::Void>,

    /// Handles that we'll take ownership of when launching the service.
    ///
    /// (TODO HSS: Having to consume this may indicate a design problem.)
    unlaunched: Option<(
        mpsc::Receiver<RendRequest>,
        Box<dyn Launchable + Send + Sync>,
    )>,
}

/// Objects and handles needed to launch an onion service.
struct ForLaunch<R: Runtime> {
    /// An unlaunched handle for the HsDesc publisher.
    ///
    /// This publisher is responsible for determining when we need to upload a
    /// new set of HsDescs, building them, and publishing them at the correct
    /// HsDirs.
    publisher: Publisher<R, publish::Real<R>>,

    /// Our handler for the introduction point manager.
    ///
    /// This manager is responsible for selecting introduction points,
    /// maintaining our connections to them, and telling the publisher which ones
    /// are publicly available.
    ipt_mgr: IptManager<R, crate::ipt_mgr::Real<R>>,

    /// A handle used by the ipt manager to send Ipts to the publisher.
    ///
    ///
    ipt_mgr_view: IptsManagerView,
}

/// Private trait used to type-erase `ForLaunch<R>`, so that we don't need to
/// parameterize OnionService on `<R>`.
trait Launchable: Send + Sync {
    /// Launch
    fn launch(self: Box<Self>) -> Result<(), StartupError>;
}

impl<R: Runtime> Launchable for ForLaunch<R> {
    fn launch(self: Box<Self>) -> Result<(), StartupError> {
        self.ipt_mgr.launch_background_tasks(self.ipt_mgr_view)?;
        self.publisher.launch()?;
        Ok(())
    }
}

impl OnionService {
    /// Create (but do not launch) a new onion service.
    pub fn new<R, S>(
        runtime: R,
        config: OnionServiceConfig,
        netdir_provider: Arc<dyn NetDirProvider>,
        circ_pool: Arc<HsCircPool<R>>,
        keymgr: Arc<KeyMgr>,
        statemgr: S,
    ) -> Result<Arc<Self>, StartupError>
    where
        R: Runtime,
        S: tor_persist::StateMgr + Send + Sync + 'static,
    {
        let nickname = config.name.clone();
        // TODO HSS: Maybe, adjust tor_persist::fs to handle subdirectories, and
        // use onion/{nickname}?
        let storage_key = format!("onion_svc_{nickname}");
        // TODO HSS-IPT-PERSIST: Use this handle, and use a real struct type instead.
        let storage_handle: Arc<dyn tor_persist::StorageHandle<()>> =
            statemgr.create_handle(storage_key);

        let (rend_req_tx, rend_req_rx) = mpsc::channel(32);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (config_tx, config_rx) = postage::watch::channel_with(Arc::new(config));

        // TODO HSS: How do I give ipt_mgr_view to ipt_mgr?  Does IptManager even take
        //          one of these?
        let (ipt_mgr_view, publisher_view) = crate::ipt_set::ipts_channel(None);

        let ipt_mgr = IptManager::new(
            runtime.clone(),
            netdir_provider.clone(),
            nickname.clone(),
            config_rx.clone(),
            rend_req_tx,
            shutdown_rx,
            crate::ipt_mgr::Real {
                circ_pool: circ_pool.clone(),
            },
        )?;

        // TODO HSS Why does this not need a keymgr?
        let publisher: Publisher<R, publish::Real<R>> = Publisher::new(
            runtime,
            nickname,
            netdir_provider,
            circ_pool,
            publisher_view,
            config_rx,
            Arc::clone(&keymgr),
        );

        // TODO HSS: we need to actually do something with: shutdown_tx,
        // rend_req_rx.  The latter may need to be refactored to actually work
        // with svc::rend_handshake, if it doesn't already.

        Ok(Arc::new(OnionService {
            inner: Mutex::new(SvcInner {
                config_tx,
                shutdown_tx,
                keymgr,
                unlaunched: Some((
                    rend_req_rx,
                    Box::new(ForLaunch {
                        publisher,
                        ipt_mgr,
                        ipt_mgr_view,
                    }),
                )),
            }),
        }))
    }

    /// Change the configuration of this onion service.
    ///
    /// (Not everything can be changed here. At the very least we'll need to say
    /// that the identity of a service is fixed. We might want to make the
    /// storage  backing this, and the anonymity status, unchangeable.)
    pub fn reconfigure(&self, new_config: ()) -> Result<(), ReconfigureError> {
        todo!() // TODO hss
    }

    /// Tell this onion service about some new short-term keys it can use.
    pub fn add_keys(&self, keys: ()) -> Result<(), Bug> {
        todo!() // TODO hss
    }

    /// Return the current status of this onion service.
    pub fn status(&self) -> OnionServiceStatus {
        todo!() // TODO hss
    }

    // TODO hss let's also have a function that gives you a stream of Status
    // changes?  Or use a publish-based watcher?

    /// Tell this onion service to begin running, and return a
    /// stream of rendezvous requests on the service.
    ///
    /// You can turn the resulting stream into a stream of [`StreamRequest`](crate::StreamRequest)
    /// using the [`handle_rend_requests`](crate::handle_rend_requests) helper function
    pub fn launch(self: &Arc<Self>) -> Result<impl Stream<Item = RendRequest>, StartupError> {
        let (rend_req_rx, launch) = {
            let mut inner = self.inner.lock().expect("poisoned lock");
            inner
                .unlaunched
                .take()
                .ok_or(StartupError::AlreadyLaunched)?
        };

        launch.launch()?;

        // TODO HSS:  This needs to launch at least the following tasks:
        //
        // - If we decide to use separate disk-based key provisioning, a task to
        //   monitor our keys directory.
        // - If we own our identity key, a task to generate per-period sub-keys as
        //   needed.

        Ok(rend_req_rx)
    }

    /// Tell this onion service to stop running.
    ///
    /// It can be restarted with launch().
    ///
    /// You can also shut down an onion service completely by dropping the last
    /// Clone of it.
    pub fn stop(&self) {
        todo!() // TODO hss
    }
}
