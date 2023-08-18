//! Principal types for onion services.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use tor_circmgr::hspool::HsCircPool;
use tor_config::ReconfigureError;
use tor_error::Bug;
use tor_hscrypto::pk::HsBlindIdKey;
use tor_keymgr::KeyMgr;
use tor_linkspec::RelayIds;
use tor_llcrypto::pk::curve25519;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::OnionServiceStatus;
use crate::StartupError;

mod ipt_establish;
mod publish;
pub(crate) mod rend_handshake;

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
    /// TODO HSS: Authorized client public keys might be here, or they might be in a
    /// separate structure.
    config: crate::OnionServiceConfig,

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

    /// Authentication information for descriptor encryption.
    ///
    /// (Our protocol defines two kinds of client authentication: in the first
    /// type, we encrypt the descriptor to client public keys.  In the second,
    /// we require authentictaion as part of the `INTRODUCE2` message. Only the
    /// first type has ever been implemented.)
    encryption_auth: Option<DescEncryptionAuth>,

    /// Private keys in actual use for this onion service.
    //
    // TODO hss: This will need heavy refactoring.
    //
    // TODO hss: There's a separate blinded ID, certificate, and signing key
    // for each active time period.
    keys: (),

    /// Status for each active introduction point for this onion service.
    //
    // TODO HSS: This might want to be a generational arena, and might want to be
    // use a different map for each descriptor epoch. Feel free to refactor!
    intro_points: Vec<IntroPointState>,

    /// Status for our onion service descriptor
    desc_status: DescUploadHistory,
}

/// Information about encryption-based authentication.

struct DescEncryptionAuth {
    /// A list of the public keys for which we should encrypt our
    /// descriptor.
    //
    // TODO HSS: maybe this should instead be a place to find the keys, so that
    // we can reload them on change?
    //
    // TODO HSS: maybe this should instead be part of our configuration
    keys: Vec<curve25519::PublicKey>,
}

/// Current history and status for our descriptor uploads.
///
// TODO HSS: Remember, there are *multiple simultaneous variants* of our
// descriptor. we will probably need to make this structure different.
struct DescUploadHistory {
    /// When did we last rebuild our descriptors?
    last_rebuilt: Instant,

    /// Each current descriptor that we need to try to maintain and upload.
    descriptors: HashMap<HsBlindIdKey, String>,

    /// Status of uploading each descriptor to each HsDir.
    //
    // Note that is possible that multiple descriptors will need to be uploaded
    // to the same HsDir.  When this happens, we MUST use separate circuits to
    // uplaod them.
    target_status: HashMap<HsBlindIdKey, HashMap<RelayIds, RetryState>>,
}

/// State of uploading a single descriptor
struct RetryState {
    // TODO HSS: implement this as needed.
}

/// State of a current introduction point.
struct IntroPointState {
    // TODO HSS: use diziet's structures  from `hssvc-ipt-algorithms.md` once those are more settled.
}

/// Identifier for a single introduction point of an onion point.
//
// TODO HSS maybe use a nicer type, like a generational arena index.
#[derive(Debug, Clone)]
pub(crate) struct IntroPointId(RelayIds);

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
