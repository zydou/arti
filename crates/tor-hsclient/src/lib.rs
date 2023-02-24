#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO hs: Add complete suite of warnings here.

mod connect;
mod err;
mod keys;
mod state;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use tor_circmgr::isolation::Isolation;
use tor_circmgr::{CircMgr, OnionConnectError, OnionServiceConnector};
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDirProvider;
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

pub use err::{HsClientConnError, StartupError};
pub use keys::{HsClientSecretKeys, HsClientSecretKeysBuilder};

use state::Services;

/// An object that negotiates connections with onion services
#[derive(Clone)]
pub struct HsClientConnector<R: Runtime> {
    /// The runtime
    runtime: R,
    /// A [`CircMgr`] that we use to build circuits to HsDirs, introduction
    /// points, and rendezvous points.
    //
    // TODO hs: currently this is a circular set of Arc, since the CircMgr will
    // have to hold an Arc<OnionServiceConnector>.  We should make one Weak.
    // A. We should probably abolish this instead, see comments for OnionServiceConnector -Diziet
    //
    // TODO hs: Maybe we can make a trait that only gives a minimal "build a
    // circuit" API from CircMgr, so that we can have this be a dyn reference
    // too?
    circmgr: Arc<CircMgr<R>>,
    /// A [`NetDirProvider`] that we use to pick rendezvous points.
    //
    // TODO hs: Should this be weak too?   A. No, it's a downward reference. -Diziet
    netdir_provider: Arc<dyn NetDirProvider>,
    /// Information we are remembering about different onion services.
    //
    // TODO hs: if we implement cache isolation or state isolation, we might
    // need multiple instances of this.
    services: Arc<Mutex<state::Services>>,
}

impl<R: Runtime> HsClientConnector<R> {
    /// Create a new `HsClientConnector`
    pub fn new(
        runtime: R,
        circmgr: Arc<CircMgr<R>>,
        netdir_provider: Arc<dyn NetDirProvider>,
        // TODO HS: there should be a config here, we will probably need it at some point
        // TODO HS: needs a parameter which lets us periodically expire old HS data/circuits
    ) -> Result<Self, StartupError> {
        Ok(HsClientConnector {
            runtime,
            circmgr,
            netdir_provider,
            services: Arc::new(Mutex::new(Services::default())),
        })
    }

    /// Connect to a hidden service
    pub async fn get_or_launch_connection(
        &self,
        hs_id: HsId,
        secret_keys: HsClientSecretKeys,
        isolation: Box<dyn Isolation>,
    ) -> Result<ClientCirc, HsClientConnError> {
        Services::get_or_launch_connection(self, hs_id, isolation, secret_keys).await
    }
}

#[async_trait]
impl<R: Runtime> OnionServiceConnector for HsClientConnector<R> {
    #[allow(dead_code, unused_variables)] // TODO hs implement this function or remove this trait
    async fn create_connection(
        &self,
        service_id: HsId,
    ) -> Result<ClientCirc, OnionConnectError> {
        todo!() // TODO hs
    }
}
