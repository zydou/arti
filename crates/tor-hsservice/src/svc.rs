//! Principal types for onion services.

mod netdir;

use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use futures::channel::oneshot;
use tor_circmgr::hspool::HsCircPool;
use tor_config::ReconfigureError;
use tor_error::Bug;
use tor_keymgr::KeyMgr;
use tor_llcrypto::pk::curve25519;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::ipt_mgr::IptManager;
use crate::svc::publish::Publisher;
use crate::OnionServiceConfig;
use crate::OnionServiceStatus;
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
//
// NOTE: This might not need to be parameterized on Runtime; if we can avoid it
// without too much trouble,  we should.
pub struct OnionService<R: Runtime> {
    /// The mutable implementation details of this onion service.
    inner: Mutex<SvcInner<R>>,
}

/// Implementation details for an onion service.
struct SvcInner<R: Runtime> {
    /// Configuration information about this service.
    ///
    /// TODO HSS: Should this be an `Arc<OnionServiceConfig>` or even a
    /// postage::watch thing?  That seems to be what `IptManager `expects.
    config: OnionServiceConfig,

    /// A netdir provider to use in finding our directories and choosing our
    /// introduction points.
    netdir_provider: Arc<dyn NetDirProvider>,

    /// A keymgr used to look up our keys and store new medium-term keys.
    keymgr: Arc<KeyMgr>,

    /// A circuit pool to use in making circuits to our introduction points,
    /// HsDirs, and rendezvous points.
    //
    // TODO hss: Maybe we can make a trait that only gives a minimal "build a
    // circuit" API from CircMgr, so that we can have this be a dyn reference
    // too?
    circmgr: Arc<HsCircPool<R>>,
}

impl<R: Runtime> OnionService<R> {
    /// Create (but do not launch) a new onion service.
    #[allow(unreachable_code, clippy::diverging_sub_expression)] // TODO HSS remove
    pub fn new(
        runtime: R,
        config: OnionServiceConfig,
        netdir_provider: Arc<dyn NetDirProvider>,
        circ_pool: Arc<HsCircPool<R>>,
        keymgr: Arc<KeyMgr>,
    ) -> Self {
        let nickname = config.name.clone();

        let (rend_req_tx, rend_req_rx) = mpsc::channel(32);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (config_tx, config_rx) = postage::watch::channel_with(config.clone());

        // TODO HSS: How do I give ipt_mgr_view to ipt_mgr?  Does IptManager even take
        //          one of these?
        let (ipt_mgr_view, publisher_view) = crate::ipt_set::ipts_channel(None);

        let ipt_mgr = IptManager::new(
            runtime.clone(),
            netdir_provider.clone(),
            nickname,
            Arc::new(config.clone()),
            rend_req_tx,
            shutdown_rx,
            crate::ipt_mgr::Real {
                circ_pool: circ_pool.clone(),
            },
        )
        .expect("TODO HSS");

        let hs_id = {
            todo!() // TODO HSS Look up HsId by KeyMgr based on nickname.
        };

        // TODO HSS Publisher::new is async; we'd prefer a separate new/launch,
        // perhaps?  Or we could make OnionService::new async and have it
        // implicitly launch?

        // TODO HSS Why does this not need a keymgr?
        let publisher_future = Publisher::new(
            runtime,
            hs_id,
            netdir_provider.clone(),
            circ_pool,
            config,
            publisher_view,
            config_rx,
        );

        // TODO HSS: we need to actually do something with: shutdown_tx,
        // rend_req_rx.  The latter may need to be refactored to actually work
        // with svc::rend_handshake, if it doesn't already.

        OnionService {
            inner: Mutex::new(SvcInner {
                config,
                netdir_provider,
                keymgr,
                circmgr: circ_pool,
            }),
        }

        // TODO HSS: CONVERGENCE NOTES:
        //   - Converge on one way to handle sharing config and config
        //     changes.
        //   - Converge on how to actually send IptSet from manager to
        //     publisher.
        //   - Converge on convention for new() vs launch()
        //   - Converge on relationship between RendRequest and
        //     IntroRequest.
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

    /// Tell this onion service to begin running.
    //
    // TODO HSS: Probably return an `impl Stream<RendRequest>`.
    pub fn launch(&self) -> Result<(), StartupError> {
        todo!() // TODO hss

        // This needs to launch at least the following tasks:
        //
        // - If we decide to use separate disk-based key provisioning, a task to
        //   monitor our keys directory.
        // - If we own our identity key, a task to generate per-period sub-keys as
        //   needed.
        // - A task to make sure that we have enough introduction point circuits
        //   at all times, and launch new ones as needed.
        // - A task to see whether we have an up-to-date descriptor uploaded for
        //   each supported time period to every HsDir listed for us in the
        //   current directory, and if not, regenerate and upload our descriptor
        //   as needed.
        // - A task to receive introduction requests from our introduction
        //   points, decide whether to answer them, and if so launch a new
        //   rendezvous task to:
        //    - finish the cryptographic handshake
        //    - build a circuit to the rendezvous point
        //    - Send the RENDEZVOUS1 reply
        //    - Add a virtual hop to the rendezvous circuit
        //    - Launch a new task to handle BEGIN requests on the rendezvous
        //      circuit, using our StreamHandler.
    }

    /// Tell  this onion service to stop running.  
    ///
    /// It can be restarted with launch().
    ///
    /// You can also shut down an onion service completely by dropping the last
    /// Clone of it.
    pub fn stop(&self) {
        todo!() // TODO hss
    }
}
