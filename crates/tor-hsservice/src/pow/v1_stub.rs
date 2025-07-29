//! Stub; `v1` proof of work scheme has been disabled at compile time

use std::marker::PhantomData;
use std::sync::Arc;

use futures::channel::mpsc;
use serde::{Deserialize, Serialize};
use tor_hscrypto::time::TimePeriod;
use tor_keymgr::KeyMgr;
use tor_netdir::NetDirProvider;
use tor_persist::{
    hsnickname::HsNickname,
    state_dir::{InstanceRawSubdir, StorageHandle},
};
use tor_rtcompat::Runtime;

use crate::{OnionServiceConfig, RendRequest, StartupError, status::StatusSender};

use super::NewPowManager;

#[derive(Clone)]
/// Stub for PoW management code, does nothing.
pub(crate) struct PowManager<R> {
    /// We hold this here so that the channel isn't closed
    publisher_update_tx: mpsc::Sender<TimePeriod>,
    /// PhantomData since our stub doesn't actually care about what runtime we use.
    runtime: PhantomData<R>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PowManagerStateRecord;

impl<R: Runtime> PowManager<R> {
    pub(crate) fn new(
        _runtime: R,
        _nickname: HsNickname,
        _instance_dir: InstanceRawSubdir,
        _keymgr: Arc<KeyMgr>,
        _storage_handle: StorageHandle<PowManagerStateRecord>,
        _netdir_provider: Arc<dyn NetDirProvider>,
        _status_tx: StatusSender,
        _config_rx: postage::watch::Receiver<Arc<OnionServiceConfig>>,
    ) -> Result<NewPowManager<R>, StartupError> {
        let (rend_req_tx, rend_req_rx) = super::make_rend_queue();
        let (publisher_update_tx, publisher_update_rx) = mpsc::channel(1);

        Ok(NewPowManager {
            pow_manager: Arc::new(PowManager {
                publisher_update_tx,
                runtime: PhantomData,
            }),
            rend_req_tx,
            rend_req_rx: Box::pin(rend_req_rx),
            publisher_update_rx,
        })
    }

    pub(crate) fn launch(self: Arc<Self>) -> Result<(), StartupError> {
        Ok(())
    }
}
