//! Stub; `v1` proof of work scheme has been disabled at compile time

use std::marker::PhantomData;
use std::sync::Arc;

use futures::channel::mpsc;
use tor_hscrypto::time::TimePeriod;
use tor_keymgr::KeyMgr;
use tor_persist::{hsnickname::HsNickname, state_dir::InstanceRawSubdir};
use tor_rtcompat::Runtime;

use crate::{RendRequest, StartupError};

use super::NewPowManager;

#[derive(Clone)]
/// Stub for PoW management code, does nothing.
pub(crate) struct PowManager<R> {
    /// We hold this here so that the channel isn't closed
    publisher_update_tx: mpsc::Sender<TimePeriod>,
    /// PhantomData since our stub doesn't actually care about what runtime we use.
    runtime: PhantomData<R>,
}

impl<R: Runtime> PowManager<R> {
    pub(crate) fn new(
        _runtime: R,
        _nickname: HsNickname,
        _instance_dir: InstanceRawSubdir,
        _keymgr: Arc<KeyMgr>,
    ) -> NewPowManager<R> {
        let (rend_req_tx, rend_req_rx) = super::make_rend_queue();
        let (publisher_update_tx, publisher_update_rx) = mpsc::channel(1);

        NewPowManager {
            pow_manager: Arc::new(PowManager {
                publisher_update_tx,
                runtime: PhantomData,
            }),
            rend_req_tx,
            rend_req_rx: Box::pin(rend_req_rx),
            publisher_update_rx,
        }
    }

    pub(crate) fn launch(self: Arc<Self>) -> Result<(), StartupError> {
        Ok(())
    }
}
