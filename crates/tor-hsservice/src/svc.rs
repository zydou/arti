//! Principal types for onion services.
pub(crate) mod netdir;

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs_mistrust::Mistrust;
use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::Stream;
use postage::broadcast;
use safelog::sensitive;
use tor_async_utils::PostageWatchSenderExt as _;
use tor_circmgr::hspool::HsCircPool;
use tor_config::{Reconfigure, ReconfigureError};
use tor_hscrypto::pk::HsId;
use tor_hscrypto::pk::HsIdKey;
use tor_hscrypto::pk::HsIdKeypair;
use tor_keymgr::KeyMgr;
use tor_keymgr::KeystoreSelector;
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::pk::ed25519;
use tor_netdir::NetDirProvider;
use tor_persist::StateMgr;
use tor_rtcompat::Runtime;
use tracing::{info, warn};

use crate::ipt_mgr::{IptManager, IptStorageHandle};
use crate::ipt_set::{IptSetStorageHandle, IptsManagerView};
use crate::status::{OnionServiceStatus, OnionServiceStatusStream, StatusSender};
use crate::svc::publish::Publisher;
use crate::HsIdKeypairSpecifier;
use crate::HsIdPublicKeySpecifier;
use crate::HsNickname;
use crate::OnionServiceConfig;
use crate::RendRequest;
use crate::StartupError;

pub(crate) mod ipt_establish;
pub(crate) mod publish;
pub(crate) mod rend_handshake;

/// Convenience alias for link specifiers of an intro point
pub(crate) type LinkSpecs = Vec<tor_linkspec::EncodedLinkSpec>;

/// Convenient type alias for an ntor public key
// TODO (#1022) maybe this should be
// `tor_proto::crypto::handshake::ntor::NtorPublicKey`,
// or a unified OnionKey type.
type NtorPublicKey = curve25519::PublicKey;

/// A handle to a running instance of an onion service.
//
// TODO (#1228): Write more.
// TODO (#1247): Choose a better name for this struct
//
// (APIs should return Arc<OnionService>)
#[must_use = "a hidden service object will terminate the service when dropped"]
pub struct RunningOnionService {
    /// The mutable implementation details of this onion service.
    inner: Mutex<SvcInner>,
    /// The current state.
    state: OnionServiceState,
}

/// Implementation details for an onion service.
struct SvcInner {
    /// Configuration information about this service.
    config_tx: postage::watch::Sender<Arc<OnionServiceConfig>>,

    /// A oneshot that will be dropped when this object is dropped.
    _shutdown_tx: postage::broadcast::Sender<void::Void>,

    /// Postage sender, used to tell subscribers about changes in the status of
    /// this onion service.
    status_tx: StatusSender,

    /// Handles that we'll take ownership of when launching the service.
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

/// Return value from one call to the main loop iteration
///
/// Used by the publisher reactor and by the [`IptManager`].
#[derive(PartialEq)]
#[must_use]
pub(crate) enum ShutdownStatus {
    /// We should continue to operate this component
    Continue,
    /// We should shut down: the service, or maybe the whole process, is shutting down
    Terminate,
}

impl From<oneshot::Canceled> for ShutdownStatus {
    fn from(_: oneshot::Canceled) -> ShutdownStatus {
        ShutdownStatus::Terminate
    }
}

/// A handle to an instance of an onion service.
//
// TODO (#1228): Write more.
// TODO (#1247): Choose a better name for this struct
//
pub struct OnionService {
    /// The current configuration.
    config: OnionServiceConfig,
    /// The current state.
    state: OnionServiceState,
}

/// The state of an instance of an onion service.
//
// TODO (#1228): Write more.
// TODO (#1247): Choose a better name for this struct
pub struct OnionServiceState {
    /// The nickname of this service.
    nickname: HsNickname,
    /// The key manager, used for accessing the underlying key stores.
    keymgr: Arc<KeyMgr>,
    /// The location on disk where the persistent data is stored.
    state_dir: PathBuf,
    /// The [`Mistrust`] configuration used with `state_dir`.
    state_mistrust: Mistrust,
    /// The state manager.
    state_mgr: Box<dyn OnionServiceStateMgr>,
}

impl OnionServiceState {
    /// Return the onion address of this service.
    ///
    /// Returns `None` if the HsId of the service could not be found in any of the configured
    /// keystores.
    //
    // TODO: instead of duplicating RunningOnionService::onion_name, maybe we should make this a
    // method on an ArtiHss type, and make both OnionService and RunningOnionService deref to
    // ArtiHss.
    pub fn onion_name(&self) -> Option<HsId> {
        let hsid_spec = HsIdPublicKeySpecifier::new(self.nickname.clone());
        self.keymgr
            .get::<HsIdKey>(&hsid_spec)
            .ok()?
            .map(|hsid| hsid.id())
    }
}

impl<S: StateMgr + Send + Sync + 'static> OnionServiceStateMgr for S {
    fn try_lock(&self) -> Result<(), StartupError> {
        use tor_persist::LockStatus as LS;
        match self.try_lock().map_err(StartupError::LoadState)? {
            LS::NoLock => Err(StartupError::StateLocked),
            LS::AlreadyHeld => Ok(()),
            LS::NewlyAcquired => Ok(()),
        }
    }

    fn ipt_storage_handle(&self, nickname: &HsNickname) -> Arc<IptStorageHandle> {
        self.clone().create_handle(format!("hs_ipts_{}", nickname))
    }

    fn ipt_set_storage_handle(&self, nickname: &HsNickname) -> Arc<IptSetStorageHandle> {
        self.clone()
            .create_handle(format!("hs_iptpub_{}", nickname))
    }
}

/// Private trait used to type-erase `OnionServiceState<S>`, so that we don't need to
/// parameterize OnionService and RunningOnionService on `<S>`.
pub(crate) trait OnionServiceStateMgr: Send + Sync {
    /// Try to become a read-write state manager if possible, without
    /// blocking.
    ///
    /// Returns an `Err` if the lock cannot be acquired.
    fn try_lock(&self) -> Result<(), StartupError>;

    /// Make a new [`StorageHandle`](tor_persist::StorageHandle) for IPT `RelayRecord` storage.
    fn ipt_storage_handle(&self, nickname: &HsNickname) -> Arc<IptStorageHandle>;

    /// Make a new [`StorageHandle`](tor_persist::StorageHandle) for `IptRecord` storage.
    fn ipt_set_storage_handle(&self, nickname: &HsNickname) -> Arc<IptSetStorageHandle>;
}

impl OnionService {
    /// Create (but do not launch) a new onion service.
    // TODO (#1228): document.
    //
    // TODO (#1228): Document how we handle the case where somebody tries to launch two
    // onion services with the same nickname?  They will conflict by trying to
    // use the same state and the same keys.  Do we stop it here, or in
    // arti_client?
    pub fn new<S: StateMgr + Send + Sync + 'static>(
        config: OnionServiceConfig,
        keymgr: Arc<KeyMgr>,
        state_mgr: S,
        state_dir: &Path,
        state_mistrust: &Mistrust,
    ) -> Result<Self, StartupError> {
        let nickname = config.nickname.clone();
        // TODO (#1194): add a config option for specifying whether to expect the KS_hsid to be stored
        // offline
        //let offline_hsid = config.offline_hsid;
        let offline_hsid = false;

        maybe_generate_hsid(&keymgr, &nickname, offline_hsid)?;

        Ok(OnionService {
            config,
            state: OnionServiceState {
                nickname,
                keymgr,
                state_mgr: Box::new(state_mgr),
                state_dir: state_dir.into(),
                state_mistrust: state_mistrust.clone(),
            },
        })
    }

    /// Tell this onion service to begin running, and return a
    /// [`RunningOnionService`] and its stream of rendezvous requests.
    ///
    /// You can turn the resulting stream into a stream of [`StreamRequest`](crate::StreamRequest)
    /// using the [`handle_rend_requests`](crate::handle_rend_requests) helper function.
    ///
    /// Once the `RunningOnionService` is dropped, the onion service will stop
    /// publishing, and stop accepting new introduction requests.  Existing
    /// streams and rendezvous circuits will remain open.
    pub fn launch<R>(
        self,
        runtime: R,
        netdir_provider: Arc<dyn NetDirProvider>,
        circ_pool: Arc<HsCircPool<R>>,
    ) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>), StartupError>
    where
        R: Runtime,
    {
        let OnionService { config, state } = self;

        let nickname = state.nickname.clone();

        state.state_mgr.try_lock()?;

        // We pass the "cooked" handle, with the storage key embedded, to ipt_set,
        // since the ipt_set code doesn't otherwise have access to the HS nickname.
        let iptpub_storage_handle = state.state_mgr.ipt_set_storage_handle(&state.nickname);

        let (rend_req_tx, rend_req_rx) = mpsc::channel(32);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(0);
        let (config_tx, config_rx) = postage::watch::channel_with(Arc::new(config));

        let (ipt_mgr_view, publisher_view) =
            crate::ipt_set::ipts_channel(&runtime, iptpub_storage_handle)?;

        let ipt_mgr = IptManager::new(
            runtime.clone(),
            netdir_provider.clone(),
            nickname.clone(),
            config_rx.clone(),
            rend_req_tx,
            shutdown_rx.clone(),
            &*state.state_mgr,
            crate::ipt_mgr::Real {
                circ_pool: circ_pool.clone(),
            },
            state.keymgr.clone(),
            &state.state_dir,
            &state.state_mistrust,
        )?;

        let status_tx = StatusSender::new(OnionServiceStatus::new_shutdown());

        let publisher: Publisher<R, publish::Real<R>> = Publisher::new(
            runtime,
            nickname.clone(),
            netdir_provider,
            circ_pool,
            publisher_view,
            config_rx,
            status_tx.clone().into(),
            Arc::clone(&state.keymgr),
        );

        // TODO (#1083): We should pass a copy of this to the publisher and/or the
        // IptMgr, and they should adjust it as needed.
        let status_tx = StatusSender::new(OnionServiceStatus::new_shutdown());

        let svc = Arc::new(RunningOnionService {
            state,
            inner: Mutex::new(SvcInner {
                config_tx,
                _shutdown_tx: shutdown_tx,
                status_tx,
                unlaunched: Some((
                    rend_req_rx,
                    Box::new(ForLaunch {
                        publisher,
                        ipt_mgr,
                        ipt_mgr_view,
                    }),
                )),
            }),
        });

        let stream = svc.launch()?;
        Ok((svc, stream))
    }
}

impl RunningOnionService {
    /// Change the configuration of this onion service.
    ///
    /// (Not everything can be changed here. At the very least we'll need to say
    /// that the identity of a service is fixed. We might want to make the
    /// storage  backing this, and the anonymity status, unchangeable.)
    pub fn reconfigure(
        &self,
        new_config: OnionServiceConfig,
        how: Reconfigure,
    ) -> Result<(), ReconfigureError> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.config_tx.try_maybe_send(|cur_config| {
            let new_config = cur_config.for_transition_to(new_config, how)?;
            Ok(match how {
                // We're only checking, so return the current configuration.
                tor_config::Reconfigure::CheckAllOrNothing => Arc::clone(cur_config),
                // We're replacing the configuration, and we didn't get an error.
                _ => Arc::new(new_config),
            })
        })

        // TODO (#1153, #1209): We need to make sure that the various tasks listening on
        // config_rx actually enforce the configuration, not only on new
        // connections, but existing ones.
    }

    /*
    /// Tell this onion service about some new short-term keys it can use.
    pub fn add_keys(&self, keys: ()) -> Result<(), Bug> {
        todo!() // TODO #1194
    }
    */

    /// Return the current status of this onion service.
    pub fn status(&self) -> OnionServiceStatus {
        self.inner.lock().expect("poisoned lock").status_tx.get()
    }

    /// Return a stream of events that will receive notifications of changes in
    /// this onion service's status.
    pub fn status_events(&self) -> OnionServiceStatusStream {
        self.inner
            .lock()
            .expect("poisoned lock")
            .status_tx
            .subscribe()
    }

    /// Tell this onion service to begin running, and return a
    /// stream of rendezvous requests on the service.
    ///
    /// You can turn the resulting stream into a stream of [`StreamRequest`](crate::StreamRequest)
    /// using the [`handle_rend_requests`](crate::handle_rend_requests) helper function
    fn launch(self: &Arc<Self>) -> Result<impl Stream<Item = RendRequest>, StartupError> {
        let (rend_req_rx, launch) = {
            let mut inner = self.inner.lock().expect("poisoned lock");
            inner
                .unlaunched
                .take()
                .ok_or(StartupError::AlreadyLaunched)?
        };

        // TODO (#1083): Set status to Bootstrapping.
        match launch.launch() {
            Ok(()) => {}
            Err(e) => {
                // TODO (#1083): Set status to Shutdown, record error.
                return Err(e);
            }
        }

        // This needs to launch at least the following tasks:
        //
        // TODO (#1194) If we decide to use separate disk-based key
        // provisioning, we need a task to monitor our keys directory.

        Ok(rend_req_rx)
    }

    /*
    /// Tell this onion service to stop running.
    ///
    /// It can be restarted with launch().
    ///
    /// You can also shut down an onion service completely by dropping the last
    /// Clone of it.
    pub fn pause(&self) {
        todo!() // TODO (#1231)
    }
    */
}

impl Deref for OnionService {
    type Target = OnionServiceState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl Deref for RunningOnionService {
    type Target = OnionServiceState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

/// Generate the identity key of the service, unless it already exists or `offline_hsid` is `true`.
fn maybe_generate_hsid(
    keymgr: &Arc<KeyMgr>,
    nickname: &HsNickname,
    offline_hsid: bool,
) -> Result<(), StartupError> {
    let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
    let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

    let has_hsid_kp = keymgr
        .get::<HsIdKeypair>(&hsid_spec)
        .map_err(|cause| StartupError::Keystore {
            action: "read",
            cause,
        })?
        .is_some();

    let has_hsid_pub = keymgr
        .get::<HsIdKey>(&pub_hsid_spec)
        .map_err(|cause| StartupError::Keystore {
            action: "read",
            cause,
        })?
        .is_some();

    // If KS_hs_id is missing (and not stored offline), generate a new keypair.
    //
    // TODO (#1230): if the hsid is missing but the service key directory exists, should we remove
    // any preexisting keys from it?
    if !offline_hsid {
        if !has_hsid_kp && has_hsid_pub {
            // The hsid keypair is missing, but the hsid public key is not, so we can't
            // generate a fresh keypair. We also cannot proceed, because the hsid is not
            // supposed to be offline
            warn!("offline_hsid is false, but KS_hs_id missing!");

            return Err(StartupError::KeystoreCorrupted);
        }

        // TODO HSS: make the selector configurable
        let keystore_sel = KeystoreSelector::Default;
        let mut rng = rand::thread_rng();

        // NOTE: KeyMgr::generate will generate a new hsid keypair and corresponding public
        // key.
        let generated = keymgr
            .generate_with_derived::<HsIdKeypair, ed25519::PublicKey>(
                &hsid_spec,
                &pub_hsid_spec,
                keystore_sel,
                |sk| *sk.public(),
                &mut rng,
                false, /* overwrite */
            )
            .map_err(|cause| StartupError::Keystore {
                action: "generate key",
                cause,
            })?
            .is_some();

        let pk = keymgr
            .get::<HsIdKey>(&pub_hsid_spec)
            .map_err(|cause| StartupError::Keystore {
                action: "read",
                cause,
            })?
            .ok_or(StartupError::KeystoreCorrupted)?;

        let hsid: HsId = pk.id();
        if generated {
            info!(
                "Generated a new identity for service {nickname}: {}",
                sensitive(hsid)
            );
        } else {
            // TODO: We may want to downgrade this to trace once we have a CLI
            // for extracting it.
            info!(
                "Using existing identity for service {nickname}: {}",
                sensitive(hsid)
            );
        }
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod test {
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
    use super::*;

    use std::fmt::Display;

    use fs_mistrust::Mistrust;

    use tor_basic_utils::test_rng::testing_rng;
    use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder};

    use crate::config::OnionServiceConfigBuilder;
    use crate::ipt_set::IptSetStorageHandle;
    use crate::test_temp_dir::{TestTempDir, TestTempDirGuard};
    use crate::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier};

    /// The nickname of the test service.
    const TEST_SVC_NICKNAME: &str = "test-svc";

    /// Make a fresh `KeyMgr` (containing no keys) using files in `temp_dir`
    pub(crate) fn create_keymgr(temp_dir: &TestTempDir) -> TestTempDirGuard<Arc<KeyMgr>> {
        temp_dir.used_by("keystore", |keystore_dir| {
            let keystore = ArtiNativeKeystore::from_path_and_mistrust(
                keystore_dir,
                &Mistrust::new_dangerously_trust_everyone(),
            )
            .unwrap();

            Arc::new(
                KeyMgrBuilder::default()
                    .default_store(Box::new(keystore))
                    .build()
                    .unwrap(),
            )
        })
    }

    pub(crate) fn create_storage_handles(
    ) -> (tor_persist::TestingStateMgr, Arc<IptSetStorageHandle>) {
        create_storage_handles_from_state_mgr(tor_persist::TestingStateMgr::new(), &"dummy")
    }

    pub(crate) fn create_storage_handles_from_state_mgr<S>(
        state_mgr: S,
        nick: &dyn Display,
    ) -> (S, Arc<IptSetStorageHandle>)
    where
        S: tor_persist::StateMgr + Send + Sync + 'static,
    {
        match state_mgr.try_lock() {
            Ok(tor_persist::LockStatus::NewlyAcquired) => {}
            other => panic!("{:?}", other),
        }
        let iptpub_state_handle = state_mgr.clone().create_handle(format!("hs_iptpub_{nick}"));
        (state_mgr, iptpub_state_handle)
    }

    macro_rules! maybe_generate_hsid {
        ($keymgr:expr, $offline_hsid:expr) => {{
            let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
            let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
            let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

            assert!($keymgr.get::<HsIdKey>(&pub_hsid_spec).unwrap().is_none());
            assert!($keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().is_none());

            maybe_generate_hsid(&$keymgr, &nickname, $offline_hsid).unwrap();
        }};
    }

    /// Create a test hsid keypair.
    fn create_hsid() -> (HsIdKeypair, HsIdKey) {
        let mut rng = testing_rng();
        let keypair = ed25519::Keypair::generate(&mut rng);

        let id_pub = HsIdKey::from(keypair.verifying_key());
        let id_keypair = HsIdKeypair::from(ed25519::ExpandedKeypair::from(&keypair));

        (id_keypair, id_pub)
    }

    #[test]
    fn generate_hsid() {
        let temp_dir = test_temp_dir!();
        let keymgr = create_keymgr(&temp_dir);

        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname);

        maybe_generate_hsid!(keymgr, false /* offline_hsid */);

        let hsid_public = keymgr.get::<HsIdKey>(&pub_hsid_spec).unwrap().unwrap();
        let hsid_keypair = keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().unwrap();

        let keypair: ed25519::ExpandedKeypair = hsid_keypair.into();
        assert_eq!(hsid_public.as_ref(), keypair.public());
    }

    #[test]
    fn hsid_keypair_already_exists() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

        for hsid_pub_missing in [false, true] {
            let keymgr = create_keymgr(&temp_dir);

            // Insert the preexisting hsid keypair.
            let (existing_hsid_keypair, existing_hsid_public) = create_hsid();
            let existing_keypair: ed25519::ExpandedKeypair = existing_hsid_keypair.into();
            // Expanded keypairs are not clone, so we have to extract the private key bytes here to use
            // them in an assertion that comes after the insert()
            let existing_keypair_secret = existing_keypair.to_secret_key_bytes();

            let existing_hsid_keypair = HsIdKeypair::from(existing_keypair);

            keymgr
                .insert(existing_hsid_keypair, &hsid_spec, KeystoreSelector::Default)
                .unwrap();

            // Maybe the public key already exists too (in which case maybe_generate_hsid
            // doesn't need to insert it into the keystore).
            if hsid_pub_missing {
                keymgr
                    .insert(
                        existing_hsid_public.clone(),
                        &pub_hsid_spec,
                        KeystoreSelector::Default,
                    )
                    .unwrap();
            }
            maybe_generate_hsid(&keymgr, &nickname, false /* offline_hsid */).unwrap();

            let hsid_public = keymgr.get::<HsIdKey>(&pub_hsid_spec).unwrap().unwrap();
            let hsid_keypair = keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().unwrap();

            let keypair: ed25519::ExpandedKeypair = hsid_keypair.into();

            // The keypair was not overwritten. The public key matches the existing keypair.
            assert_eq!(hsid_public.as_ref(), existing_hsid_public.as_ref());
            assert_eq!(keypair.to_secret_key_bytes(), existing_keypair_secret);
        }
    }

    #[test]
    fn generate_hsid_offline_hsid() {
        let temp_dir = test_temp_dir!();
        let keymgr = create_keymgr(&temp_dir);

        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

        maybe_generate_hsid!(keymgr, true /* offline_hsid */);

        assert!(keymgr.get::<HsIdKey>(&pub_hsid_spec).unwrap().is_none());
        assert!(keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().is_none());
    }

    #[test]
    fn generate_hsid_missing_keypair() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

        let keymgr = create_keymgr(&temp_dir);

        let (_hsid_keypair, hsid_public) = create_hsid();

        keymgr
            .insert(hsid_public, &pub_hsid_spec, KeystoreSelector::Default)
            .unwrap();

        // We're running with an online hsid, but the keypair is missing! The public part
        // of the key exists in the keystore, so we can't generate a new keypair.
        assert!(maybe_generate_hsid(&keymgr, &nickname, false /* offline_hsid */).is_err());
    }

    #[test]
    fn generate_hsid_corrupt_keystore() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

        let keymgr = create_keymgr(&temp_dir);

        let (hsid_keypair, _hsid_public) = create_hsid();
        let (_hsid_keypair, hsid_public) = create_hsid();

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Default)
            .unwrap();

        // Insert a mismatched public key
        keymgr
            .insert(hsid_public, &pub_hsid_spec, KeystoreSelector::Default)
            .unwrap();

        assert!(maybe_generate_hsid(&keymgr, &nickname, false /* offline_hsid */).is_err());
    }

    #[test]
    fn onion_name() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = create_keymgr(&temp_dir);

        let (hsid_keypair, hsid_public) = create_hsid();

        // Insert the hsid into the keystore
        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Default)
            .unwrap();

        let config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .unwrap();

        let service = OnionService::new(
            config,
            Arc::clone(&*keymgr),
            tor_persist::TestingStateMgr::new(),
            temp_dir.as_path_untracked(),
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
        )
        .unwrap();

        let hsid = HsId::from(hsid_public);
        assert_eq!(service.onion_name().unwrap(), hsid);
    }
}
