#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
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
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod connect;
mod err;
mod isol_map;
mod keys;
mod proto_oneshot;
mod relay_info;
mod state;

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use futures::stream::BoxStream;
use futures::task::SpawnExt as _;
use futures::StreamExt as _;

use educe::Educe;
use tracing::debug;

use tor_circmgr::hspool::HsCircPool;
use tor_circmgr::isolation::StreamIsolation;
use tor_error::{internal, Bug};
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDir;
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

pub use err::FailedAttemptError;
pub use err::{ConnError, DescriptorError, DescriptorErrorDetail, StartupError};
pub use keys::{
    HsClientDescEncKeypairSpecifier, HsClientSecretKeys, HsClientSecretKeysBuilder,
    HsClientNickname,
};
pub use relay_info::InvalidTarget;
pub use state::HsClientConnectorConfig;

use err::{rend_pt_identity_for_error, IntroPtIndex, RendPtIdentityForError};
use state::{Config, MockableConnectorData, Services};

/// An object that negotiates connections with onion services
///
/// This can be used by multiple requests on behalf of different clients,
/// with potentially different HS client authentication (`KS_hsc_*`)
/// and potentially different circuit isolation.
///
/// The principal entrypoint is
/// [`get_or_launch_connection()`](HsClientConnector::get_or_launch_connection).
///
/// This object is handle-like: it is fairly cheap to clone,
///  and contains `Arc`s internally.
#[derive(Educe)]
#[educe(Clone)]
pub struct HsClientConnector<R: Runtime, D: state::MockableConnectorData = connect::Data> {
    /// The runtime
    runtime: R,
    /// A [`HsCircPool`] that we use to build circuits to HsDirs, introduction
    /// points, and rendezvous points.
    circpool: Arc<HsCircPool<R>>,
    /// Information we are remembering about different onion services.
    services: Arc<Mutex<state::Services<D>>>,
    /// For mocking in tests of `state.rs`
    mock_for_state: D::MockGlobalState,
}

impl<R: Runtime> HsClientConnector<R, connect::Data> {
    /// Create a new `HsClientConnector`
    ///
    /// `housekeeping_prompt` should yield "occasionally",
    /// perhaps every few hours or maybe daily.
    ///
    /// In Arti we arrange for this to happen when we have a new consensus.
    ///
    /// Housekeeping events shouldn't arrive while we're dormant,
    /// since the housekeeping might involve processing that ought to be deferred.
    // This ^ is why we don't have a separate "launch background tasks" method.
    // It is fine for this background task to be launched pre-bootstrap, since it willp
    // do nothing until it gets events.
    pub fn new(
        runtime: R,
        circpool: Arc<HsCircPool<R>>,
        config: &impl HsClientConnectorConfig,
        housekeeping_prompt: BoxStream<'static, ()>,
    ) -> Result<Self, StartupError> {
        let config = Config {
            retry: config.as_ref().clone(),
        };
        let connector = HsClientConnector {
            runtime,
            circpool,
            services: Arc::new(Mutex::new(Services::new(config))),
            mock_for_state: (),
        };
        connector.spawn_housekeeping_task(housekeeping_prompt)?;
        Ok(connector)
    }

    /// Connect to a hidden service
    ///
    /// On success, this function will return an open
    /// rendezvous circuit with an authenticated connection to the onion service
    /// whose identity is `hs_id`.  If such a circuit already exists, and its isolation
    /// is compatible with `isolation`, that circuit may be returned; otherwise,
    /// a new circuit will be created.
    ///
    /// Once a circuit is returned, the caller can use it to open new streams to the
    /// onion service. To do so, call [`ClientCirc::begin_stream`] on it.
    ///
    /// Each HS connection request must provide the appropriate
    /// client authentication keys to use -
    /// or [`default`](HsClientSecretKeys::default) if client auth is not required.
    //
    // This returns an explicit `impl Future` so that we can write the `Send` bound.
    // Without this, it is possible for `Services::get_or_launch_connection`
    // to not return a `Send` future.
    // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1034#note_2881718
    pub fn get_or_launch_circuit<'r>(
        &'r self,
        netdir: &'r Arc<NetDir>,
        hs_id: HsId,
        secret_keys: HsClientSecretKeys,
        isolation: StreamIsolation,
    ) -> impl Future<Output = Result<Arc<ClientCirc>, ConnError>> + Send + Sync + 'r {
        // As in tor-circmgr,  we take `StreamIsolation`, to ensure that callers in
        // arti-client pass us the final overall isolation,
        // including the per-TorClient isolation.
        // But internally we need a Box<dyn Isolation> since we need .join().
        let isolation = Box::new(isolation);
        Services::get_or_launch_connection(self, netdir, hs_id, isolation, secret_keys)
    }

    /// A deprecated alias for `get_or_launch_circuit`.
    ///
    /// We renamed it to be
    /// more clear about what exactly it is launching.
    #[deprecated(since = "0.5.1", note = "Use get_or_launch_circuit instead.")]
    pub fn get_or_launch_connection<'r>(
        &'r self,
        netdir: &'r Arc<NetDir>,
        hs_id: HsId,
        secret_keys: HsClientSecretKeys,
        isolation: StreamIsolation,
    ) -> impl Future<Output = Result<Arc<ClientCirc>, ConnError>> + Send + Sync + 'r {
        self.get_or_launch_circuit(netdir, hs_id, secret_keys, isolation)
    }
}

impl<R: Runtime, D: MockableConnectorData> HsClientConnector<R, D> {
    /// Lock the `Services` table and return the guard
    ///
    /// Convenience method
    fn services(&self) -> Result<MutexGuard<Services<D>>, Bug> {
        self.services
            .lock()
            .map_err(|_| internal!("HS connector poisoned"))
    }

    /// Spawn a task which watches `prompt` and calls [`Services::run_housekeeping`]
    fn spawn_housekeeping_task(
        &self,
        mut prompt: BoxStream<'static, ()>,
    ) -> Result<(), StartupError> {
        self.runtime
            .spawn({
                let connector = self.clone();
                let runtime = self.runtime.clone();
                async move {
                    while let Some(()) = prompt.next().await {
                        let Ok(mut services) = connector.services() else {
                            break;
                        };

                        // (Currently) this is "expire old data".
                        services.run_housekeeping(runtime.now());
                    }
                    debug!("HS connector housekeeping task exiting (EOF on prompt stream)");
                }
            })
            .map_err(|cause| StartupError::Spawn {
                spawning: "housekeeping task",
                cause: cause.into(),
            })
    }
}
