#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

// TODO #1645 (either remove this, or decide to have it everywhere)
#![cfg_attr(
    not(all(feature = "full", feature = "experimental")),
    allow(unused, unreachable_pub)
)]

#[macro_use] // SerdeStringOrTransparent
mod time_store;

mod internal_prelude;

mod anon_level;
pub mod config;
mod err;
mod helpers;
mod ipt_establish;
mod ipt_lid;
mod ipt_mgr;
mod ipt_set;
mod keys;
mod pow;
mod publish;
mod rend_handshake;
mod replay;
mod req;
pub mod status;
mod timeout_track;

// rustdoc doctests can't use crate-public APIs, so are broken if provided for private items.
// So we export the whole module again under this name.
// Supports the Example in timeout_track.rs's module-level docs.
//
// Any out-of-crate user needs to write this ludicrous name in their code,
// so we don't need to put any warnings in the docs for the individual items.)
//
// (`#[doc(hidden)] pub mod timeout_track;` would work for the test but it would
// completely suppress the actual documentation, which is not what we want.)
#[doc(hidden)]
pub mod timeout_track_for_doctests_unstable_no_semver_guarantees {
    pub use crate::timeout_track::*;
}
#[doc(hidden)]
pub mod time_store_for_doctests_unstable_no_semver_guarantees {
    pub use crate::time_store::*;
}

use std::pin::Pin;

use internal_prelude::*;

// ---------- public exports ----------

pub use anon_level::Anonymity;
pub use config::OnionServiceConfig;
pub use err::{ClientError, EstablishSessionError, FatalError, IntroRequestError, StartupError};
pub use ipt_mgr::IptError;
use keys::HsTimePeriodKeySpecifier;
pub use keys::{
    BlindIdKeypairSpecifier, BlindIdPublicKeySpecifier, DescSigningKeypairSpecifier,
    HsIdKeypairSpecifier, HsIdPublicKeySpecifier,
};
use pow::{NewPowManager, PowManager};
pub use publish::UploadError as DescUploadError;
pub use req::{RendRequest, StreamRequest};
pub use tor_hscrypto::pk::HsId;
use tor_keymgr::KeystoreEntry;
pub use tor_persist::hsnickname::{HsNickname, InvalidNickname};

pub use helpers::handle_rend_requests;

#[cfg(feature = "onion-service-cli-extra")]
use tor_netdir::NetDir;

//---------- top-level service implementation (types and methods) ----------

/// Convenience alias for link specifiers of an intro point
pub(crate) type LinkSpecs = Vec<tor_linkspec::EncodedLinkSpec>;

/// Convenient type alias for an ntor public key
// TODO (#1022) maybe this should be
// `tor_proto::crypto::handshake::ntor::NtorPublicKey`,
// or a unified OnionKey type.
pub(crate) type NtorPublicKey = curve25519::PublicKey;

/// A handle to a running instance of an onion service.
//
/// To construct a `RunningOnionService`, use [`OnionServiceBuilder`]
/// to build an [`OnionService`], and then call its
/// [``.launch()``](OnionService::launch) method.
//
// (APIs should return Arc<OnionService>)
#[must_use = "a hidden service object will terminate the service when dropped"]
pub struct RunningOnionService {
    /// The mutable implementation details of this onion service.
    inner: Mutex<SvcInner>,
    /// The nickname of this service.
    nickname: HsNickname,
    /// The key manager, used for accessing the underlying key stores.
    keymgr: Arc<KeyMgr>,
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
    #[allow(clippy::type_complexity)]
    unlaunched: Option<(
        Pin<Box<dyn Stream<Item = RendRequest> + Send + Sync>>,
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

    /// Proof-of-work manager.
    pow_manager: Arc<PowManager<R>>,
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
        self.pow_manager.launch()?;

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
///
/// To construct an `OnionService`, use [`OnionServiceBuilder`].
/// It will not start handling requests until you call its
/// [``.launch()``](OnionService::launch) method.
///
/// Note: the identity key (HsId) of the service is not generated until
/// [``.launch()``](OnionService::launch) is called.
#[derive(Builder)]
#[builder(build_fn(private, name = "build_unvalidated", error = "FatalError"))]
pub struct OnionService {
    /// The current configuration.
    config: OnionServiceConfig,
    /// The key manager, used for accessing the underlying key stores.
    keymgr: Arc<KeyMgr>,
    /// The location on disk where the persistent data is stored.
    state_dir: StateDirectory,
}

impl OnionService {
    /// Create an [`OnionServiceBuilder`].
    pub fn builder() -> OnionServiceBuilder {
        OnionServiceBuilder::default()
    }

    /// Tell this onion service to begin running, and return a
    /// [`RunningOnionService`] and its stream of rendezvous requests.
    ///
    /// You can turn the resulting stream into a stream of [`StreamRequest`]
    /// using the [`handle_rend_requests`] helper function.
    ///
    /// Once the `RunningOnionService` is dropped, the onion service will stop
    /// publishing, and stop accepting new introduction requests.  Existing
    /// streams and rendezvous circuits will remain open.
    pub fn launch<R>(
        self,
        runtime: R,
        netdir_provider: Arc<dyn NetDirProvider>,
        circ_pool: Arc<HsCircPool<R>>,
        path_resolver: Arc<tor_config_path::CfgPathResolver>,
    ) -> Result<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>), StartupError>
    where
        R: Runtime,
    {
        let OnionService {
            config,
            keymgr,
            state_dir,
        } = self;

        let nickname = config.nickname.clone();

        // TODO (#1194): add a config option for specifying whether to expect the KS_hsid to be stored
        // offline
        //let offline_hsid = config.offline_hsid;
        let offline_hsid = false;

        // TODO (#1106): make this configurable
        let selector = KeystoreSelector::Primary;
        maybe_generate_hsid(&keymgr, &config.nickname, offline_hsid, selector)?;

        if config.restricted_discovery.enabled {
            info!(
                nickname=%nickname,
                "Launching onion service in restricted discovery mode"
            );
        } else {
            info!(
                nickname=%nickname,
                "Launching onion service"
            );
        }

        let state_handle = state_dir
            .acquire_instance(&config.nickname)
            .map_err(StartupError::StateDirectoryInaccessible)?;

        // We pass the "cooked" handle, with the storage key embedded, to ipt_set,
        // since the ipt_set code doesn't otherwise have access to the HS nickname.
        let iptpub_storage_handle = state_handle
            .storage_handle("iptpub")
            .map_err(StartupError::StateDirectoryInaccessible)?;

        let status_tx = StatusSender::new(OnionServiceStatus::new_shutdown());
        let (config_tx, config_rx) = postage::watch::channel_with(Arc::new(config));

        let pow_manager_storage_handle = state_handle
            .storage_handle("pow_manager")
            .map_err(StartupError::StateDirectoryInaccessible)?;
        let pow_nonce_dir = state_handle
            .raw_subdir("pow_nonces")
            .map_err(StartupError::StateDirectoryInaccessible)?;
        let NewPowManager {
            pow_manager,
            rend_req_tx,
            rend_req_rx,
            publisher_update_rx,
        } = PowManager::new(
            runtime.clone(),
            nickname.clone(),
            pow_nonce_dir,
            keymgr.clone(),
            pow_manager_storage_handle,
            netdir_provider.clone(),
            status_tx.clone().into(),
            config_rx.clone(),
        )?;

        let (shutdown_tx, shutdown_rx) = broadcast::channel(0);

        let (ipt_mgr_view, publisher_view) =
            crate::ipt_set::ipts_channel(&runtime, iptpub_storage_handle)?;

        let ipt_mgr = IptManager::new(
            runtime.clone(),
            netdir_provider.clone(),
            nickname.clone(),
            config_rx.clone(),
            rend_req_tx,
            shutdown_rx.clone(),
            &state_handle,
            crate::ipt_mgr::Real {
                circ_pool: circ_pool.clone(),
            },
            keymgr.clone(),
            status_tx.clone().into(),
        )?;

        let publisher: Publisher<R, publish::Real<R>> = Publisher::new(
            runtime,
            nickname.clone(),
            netdir_provider,
            circ_pool,
            publisher_view,
            config_rx,
            status_tx.clone().into(),
            Arc::clone(&keymgr),
            path_resolver,
            pow_manager.clone(),
            publisher_update_rx,
        );

        let svc = Arc::new(RunningOnionService {
            nickname,
            keymgr,
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
                        pow_manager,
                    }),
                )),
            }),
        });

        let stream = svc.launch()?;
        Ok((svc, stream))
    }

    /// Return the onion address of this service.
    ///
    /// Clients must know the service's onion address in order to discover or
    /// connect to it.
    ///
    /// Returns `None` if the HsId of the service could not be found in any of the configured
    /// keystores.
    pub fn onion_address(&self) -> Option<HsId> {
        onion_address(&self.keymgr, &self.config.nickname)
    }

    /// Return the onion address of this service.
    ///
    /// See [`onion_address`](Self::onion_address)
    #[deprecated = "Use the new onion_address method instead"]
    pub fn onion_name(&self) -> Option<HsId> {
        self.onion_address()
    }

    /// Generate an identity key (KP_hs_id) for this service.
    ///
    /// If the keystore specified by `selector` contains an entry for the identity key
    /// of this service, it will be returned. Otherwise, a new key will be generated.
    ///
    /// Most users do not need to call this function: on [`launch`](`OnionService::launch`),
    /// the service will automatically generate its identity key if needed.
    /// You should only use this function if you need to know the KP_hs_id of the service
    /// before launching it.
    ///
    /// The `selector` argument is used for choosing the keystore in which to generate the keypair.
    /// While most users will want to write to the [`Primary`](KeystoreSelector::Primary), if you
    /// have configured this `TorClient` with a non-default keystore and wish to generate the
    /// keypair in it, you can do so by calling this function with a [KeystoreSelector::Id]
    /// specifying the keystore ID of your keystore.
    ///
    // Note: the selector argument exists for future-proofing reasons. We don't currently support
    // configuring custom or non-default keystores (see #1106).
    pub fn generate_identity_key(&self, selector: KeystoreSelector) -> Result<HsId, StartupError> {
        // TODO (#1194): add a config option for specifying whether to expect the KS_hsid to be stored
        // offline
        //let offline_hsid = config.offline_hsid;
        let offline_hsid = false;

        maybe_generate_hsid(&self.keymgr, &self.config.nickname, offline_hsid, selector)
    }

    /// List the no-longer-relevant keys of this service.
    ///
    /// Returns the [`KeystoreEntry`]s associated with time periods that are not
    /// "relevant" according to the specified [`NetDir`],
    /// (i.e. the keys associated with time periods
    /// the service is not publishing descriptors for).
    // TODO: unittest
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn list_expired_keys(&self, netdir: &NetDir) -> tor_keymgr::Result<Vec<KeystoreEntry>> {
        list_expired_keys_for_service(
            &netdir.hs_all_time_periods(),
            self.config.nickname(),
            &self.keymgr,
        )
    }
}

impl OnionServiceBuilder {
    /// Build the [`OnionService`]
    pub fn build(&self) -> Result<OnionService, StartupError> {
        let svc = self.build_unvalidated()?;
        Ok(svc)
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
    /// You can turn the resulting stream into a stream of [`StreamRequest`]
    /// using the [`handle_rend_requests`] helper function.
    fn launch(self: &Arc<Self>) -> Result<impl Stream<Item = RendRequest> + use<>, StartupError> {
        let (rend_req_rx, launch) = {
            let mut inner = self.inner.lock().expect("poisoned lock");
            inner
                .unlaunched
                .take()
                .ok_or(StartupError::AlreadyLaunched)?
        };

        match launch.launch() {
            Ok(()) => {}
            Err(e) => {
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

    /// Return the onion address of this service.
    ///
    /// Clients must know the service's onion address in order to discover or
    /// connect to it.
    ///
    /// Returns `None` if the HsId of the service could not be found in any of the configured
    /// keystores.
    pub fn onion_address(&self) -> Option<HsId> {
        onion_address(&self.keymgr, &self.nickname)
    }

    /// Return the onion address of this service.
    ///
    /// See [`onion_address`](Self::onion_address)
    #[deprecated = "Use the new onion_address method instead"]
    pub fn onion_name(&self) -> Option<HsId> {
        self.onion_address()
    }
}

/// Generate the identity key of the service, unless it already exists or `offline_hsid` is `true`.
//
// TODO (#1194): we don't support offline_hsid yet.
fn maybe_generate_hsid(
    keymgr: &Arc<KeyMgr>,
    nickname: &HsNickname,
    offline_hsid: bool,
    selector: KeystoreSelector,
) -> Result<HsId, StartupError> {
    if offline_hsid {
        unimplemented!("offline hsid mode");
    }

    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

    let kp = keymgr
        .get::<HsIdKey>(&hsid_spec)
        .map_err(|cause| StartupError::Keystore {
            action: "read",
            cause,
        })?;

    let mut rng = tor_llcrypto::rng::CautiousRng;
    let (hsid, generated) = match kp {
        Some(kp) => (kp.id(), false),
        None => {
            // Note: there is a race here. If the HsId is generated through some other means
            // (e.g. via the CLI) at some point between the time we looked up the keypair and
            // now, we will return an error.
            let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
            let kp = keymgr
                .generate::<HsIdKeypair>(&hsid_spec, selector, &mut rng, false /* overwrite */)
                .map_err(|cause| StartupError::Keystore {
                    action: "generate",
                    cause,
                })?;

            (HsIdKey::from(&kp).id(), true)
        }
    };

    if generated {
        info!(
            "Generated a new identity for service {nickname}: {}",
            hsid.display_redacted()
        );
    } else {
        // TODO: We may want to downgrade this to trace once we have a CLI
        // for extracting it.
        info!(
            "Using existing identity for service {nickname}: {}",
            hsid.display_redacted()
        );
    }

    Ok(hsid)
}

/// Return the onion address of this service.
///
/// Clients must know the service's onion address in order to discover or
/// connect to it.
///
/// Returns `None` if the HsId of the service could not be found in any of the configured
/// keystores.
//
// TODO: instead of duplicating RunningOnionService::onion_address, maybe we should make this a
// method on an ArtiHss type, and make both OnionService and RunningOnionService deref to
// ArtiHss.
fn onion_address(keymgr: &KeyMgr, nickname: &HsNickname) -> Option<HsId> {
    let hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

    keymgr
        .get::<HsIdKey>(&hsid_spec)
        .ok()?
        .map(|hsid| hsid.id())
}

/// Return a list of the protocols[supported](tor_protover::doc_supported)
/// by this crate, running as a hidden service.
pub fn supported_hsservice_protocols() -> tor_protover::Protocols {
    use tor_protover::named::*;
    // WARNING: REMOVING ELEMENTS FROM THIS LIST CAN BE DANGEROUS!
    // SEE [`tor_protover::doc_changing`]
    [
        //
        HSINTRO_V3,
        HSINTRO_RATELIM,
        HSREND_V3,
        HSDIR_V3,
    ]
    .into_iter()
    .collect()
}

/// Returns all the keys (as [`KeystoreEntry`]) of the service
/// identified by `nickname` that are expired according to the
/// provided [`HsDirParams`].
fn list_expired_keys_for_service<'a>(
    relevant_periods: &[HsDirParams],
    nickname: &HsNickname,
    keymgr: &'a KeyMgr,
) -> tor_keymgr::Result<Vec<KeystoreEntry<'a>>> {
    let arti_pat = tor_keymgr::KeyPathPattern::Arti(format!("hss/{}/*", nickname));
    let possibly_relevant_keys = keymgr.list_matching(&arti_pat)?;
    let mut expired_keys = Vec::new();

    for entry in possibly_relevant_keys {
        let key_path = entry.key_path();
        let mut append_if_expired = |spec: &dyn HsTimePeriodKeySpecifier| {
            if spec.nickname() != nickname {
                return Err(internal!(
                    "keymgr gave us key {spec:?} that doesn't match our pattern {arti_pat:?}"
                )
                .into());
            }
            let is_expired = relevant_periods
                .iter()
                .all(|p| &p.time_period() != spec.period());

            if is_expired {
                expired_keys.push(entry.clone());
            }

            tor_keymgr::Result::Ok(())
        };

        macro_rules! append_if_expired {
            ($K:ty) => {{
                if let Ok(spec) = <$K>::try_from(key_path) {
                    append_if_expired(&spec)?;
                }
            }};
        }

        append_if_expired!(BlindIdPublicKeySpecifier);
        append_if_expired!(BlindIdKeypairSpecifier);
        append_if_expired!(DescSigningKeypairSpecifier);
    }

    Ok(expired_keys)
}

#[cfg(test)]
pub(crate) mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
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
    use std::path::Path;

    use fs_mistrust::Mistrust;
    use test_temp_dir::{TestTempDir, TestTempDirGuard, test_temp_dir};

    use tor_basic_utils::test_rng::testing_rng;
    use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder};
    use tor_llcrypto::pk::ed25519;
    use tor_persist::state_dir::InstanceStateHandle;

    use crate::config::OnionServiceConfigBuilder;
    use crate::ipt_set::IptSetStorageHandle;
    use crate::{HsIdKeypairSpecifier, HsIdPublicKeySpecifier};

    /// The nickname of the test service.
    const TEST_SVC_NICKNAME: &str = "test-svc";

    #[test]
    fn protocols() {
        let pr = supported_hsservice_protocols();
        let expected = "HSIntro=4-5 HSRend=2 HSDir=2".parse().unwrap();
        assert_eq!(pr, expected);
    }

    /// Make a fresh `KeyMgr` (containing no keys) using files in `temp_dir`
    pub(crate) fn create_keymgr(temp_dir: &TestTempDir) -> TestTempDirGuard<Arc<KeyMgr>> {
        temp_dir.subdir_used_by("keystore", |keystore_dir| {
            let keystore = ArtiNativeKeystore::from_path_and_mistrust(
                keystore_dir,
                &Mistrust::new_dangerously_trust_everyone(),
            )
            .unwrap();

            Arc::new(
                KeyMgrBuilder::default()
                    .primary_store(Box::new(keystore))
                    .build()
                    .unwrap(),
            )
        })
    }

    #[allow(clippy::let_and_return)] // clearer and more regular
    pub(crate) fn mk_state_instance(dir: &Path, nick: impl Display) -> InstanceStateHandle {
        let nick = HsNickname::new(nick.to_string()).unwrap();
        let mistrust = fs_mistrust::Mistrust::new_dangerously_trust_everyone();
        let state_dir = StateDirectory::new(dir, &mistrust).unwrap();
        let instance = state_dir.acquire_instance(&nick).unwrap();
        instance
    }

    pub(crate) fn create_storage_handles(
        dir: &Path,
    ) -> (
        tor_persist::state_dir::InstanceStateHandle,
        IptSetStorageHandle,
    ) {
        let nick = HsNickname::try_from("allium".to_owned()).unwrap();
        create_storage_handles_from_state_dir(dir, &nick)
    }

    pub(crate) fn create_storage_handles_from_state_dir(
        state_dir: &Path,
        nick: &HsNickname,
    ) -> (
        tor_persist::state_dir::InstanceStateHandle,
        IptSetStorageHandle,
    ) {
        let instance = mk_state_instance(state_dir, nick);
        let iptpub_state_handle = instance.storage_handle("iptpub").unwrap();
        (instance, iptpub_state_handle)
    }

    macro_rules! maybe_generate_hsid {
        ($keymgr:expr, $offline_hsid:expr) => {{
            let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
            let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
            let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

            assert!($keymgr.get::<HsIdKey>(&pub_hsid_spec).unwrap().is_none());
            assert!($keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().is_none());

            maybe_generate_hsid(&$keymgr, &nickname, $offline_hsid, Default::default()).unwrap();
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

        assert!(keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().is_none());
        maybe_generate_hsid!(keymgr, false /* offline_hsid */);
        assert!(keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().is_some());
    }

    #[test]
    fn hsid_keypair_already_exists() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = create_keymgr(&temp_dir);

        // Insert the preexisting hsid keypair.
        let (existing_hsid_keypair, existing_hsid_public) = create_hsid();
        let existing_keypair: ed25519::ExpandedKeypair = existing_hsid_keypair.into();
        let existing_hsid_keypair = HsIdKeypair::from(existing_keypair);

        keymgr
            .insert(
                existing_hsid_keypair,
                &hsid_spec,
                KeystoreSelector::Primary,
                true,
            )
            .unwrap();

        maybe_generate_hsid(
            &keymgr,
            &nickname,
            false, /* offline_hsid */
            Default::default(),
        )
        .unwrap();

        let keypair = keymgr.get::<HsIdKeypair>(&hsid_spec).unwrap().unwrap();
        let pk: HsIdKey = (&keypair).into();

        assert_eq!(pk.as_ref(), existing_hsid_public.as_ref());
    }

    #[test]
    #[ignore] // TODO (#1194): Revisit when we add support for offline hsid mode
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
    #[ignore] // TODO (#1194): Revisit when we add support for offline hsid mode
    fn generate_hsid_corrupt_keystore() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let pub_hsid_spec = HsIdPublicKeySpecifier::new(nickname.clone());

        let keymgr = create_keymgr(&temp_dir);

        let (hsid_keypair, _hsid_public) = create_hsid();
        let (_hsid_keypair, hsid_public) = create_hsid();

        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        // Insert a mismatched public key
        keymgr
            .insert(hsid_public, &pub_hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        assert!(
            maybe_generate_hsid(
                &keymgr,
                &nickname,
                false, /* offline_hsid */
                Default::default()
            )
            .is_err()
        );
    }

    #[test]
    fn onion_address() {
        let temp_dir = test_temp_dir!();
        let nickname = HsNickname::try_from(TEST_SVC_NICKNAME.to_string()).unwrap();
        let hsid_spec = HsIdKeypairSpecifier::new(nickname.clone());
        let keymgr = create_keymgr(&temp_dir);

        let (hsid_keypair, hsid_public) = create_hsid();

        // Insert the hsid into the keystore
        keymgr
            .insert(hsid_keypair, &hsid_spec, KeystoreSelector::Primary, true)
            .unwrap();

        let config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .unwrap();

        let state_dir = StateDirectory::new(
            temp_dir.as_path_untracked(),
            &fs_mistrust::Mistrust::new_dangerously_trust_everyone(),
        )
        .unwrap();

        let service = OnionService::builder()
            .config(config)
            .keymgr(Arc::clone(&*keymgr))
            .state_dir(state_dir)
            .build()
            .unwrap();

        let hsid = HsId::from(hsid_public);
        assert_eq!(service.onion_address().unwrap(), hsid);

        drop(temp_dir); // prove that this is still live
    }
}
