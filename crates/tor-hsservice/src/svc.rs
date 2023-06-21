use std::sync::Arc;

use tor_circmgr::CircMgr;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::{OnionServiceStatus, Result};

/// A handle to an instance of an onion service.
//
// TODO hss: We might want to wrap this in an Arc<Mutex<>>, and have an inner
// structure that contains these elements.  Or we might want to refactor this in
// some other way.
pub struct OnionService<R: Runtime> {
    /// Needs some kind of configuration about: what is our identity (if we know
    /// it), is this anonymous, do we store persistent info and if so where and
    /// how, etc.
    ///
    /// Authorized client public keys might be here, or they might be in a
    /// separate structure.
    config: (),
    /// A netdir provider to use in finding our directories and choosing our
    /// introduction points.
    netdir_provider: Arc<dyn NetDirProvider>,
    /// A circuit manager to use in making circuits to our introduction points,
    /// HsDirs, and rendezvous points.
    // TODO hss: Maybe we can make a trait that only gives a minimal "build a
    // circuit" API from CircMgr, so that we can have this be a dyn reference
    // too?
    circmgr: Arc<CircMgr<R>>,
    /// Private keys in actual use for this onion service.
    ///
    /// TODO hss: This will need heavy refactoring.
    ///
    /// TODO hss: There's a separate blinded ID, certificate, and signing key
    /// for each active time period.
    keys: (),
    /// Status for each active introduction point for this onion service.
    intro_points: Vec<()>,
    /// Status for our onion service descriptor
    descriptor_status: (),

    /// Object that handles incoming streams from the client.
    stream_handler: Arc<dyn crate::StreamHandler>,
}

impl<R: Runtime> OnionService<R> {
    /// Create (but do not launch) a new onion service.
    pub fn new(config: (), netdir_provider: (), circmgr: ()) -> Self {
        todo!(); // TODO hss
    }

    /// Change the configuration of this onion service.
    ///
    /// (Not everything can be changed here. At the very least we'll need to say
    /// that the identity of a service is fixed. We might want to make the
    /// storage  backing this, and the anonymity status, unchangeable.)
    pub fn reconfigure(&self, new_config: ()) -> Result<()> {
        todo!() // TODO hss
    }

    /// Tell this onion service about some new short-term keys it can use.
    pub fn add_keys(&self, keys: ()) -> Result<()> {
        todo!() // TODO hss
    }

    /// Return the current status of this onion service.
    pub fn status(&self) -> OnionServiceStatus {
        todo!() // TODO hss
    }
    // TODO hss let's also have a function that gives you a stream of Status
    // changes?  Or use a publish-based watcher?

    /// Tell this onion service to begin running.
    pub fn launch(&self) -> Result<()> {
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
    pub fn stop(&self) -> Result<()> {
        todo!() // TODO hss
    }
}
