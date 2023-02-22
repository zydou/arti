#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO hs: Add complete suite of warnings here.
#![allow(dead_code, unused_variables)] // TODO hs remove.

mod keys;
mod state;

use async_trait::async_trait;
use std::sync::Arc;
use tor_hscrypto::pk::HsId;
use tor_proto::circuit::ClientCirc;

use tor_circmgr::{CircMgr, OnionConnectError, OnionServiceConnector};
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

/// An object that negotiates connections with onion services
pub struct HsClientConnector<R: Runtime> {
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
    state: state::StateMap,
    /// A collection of private keys to be used with various onion services.
    //
    // TODO hs: we might even want multiple instances of this, depending on how
    // we decide to do isolation.
    keys: keys::Keys,
}

impl<R: Runtime> HsClientConnector<R> {
    // TODO hs: Need a way to manage the set of keys.

    // TODO hs: need a constructor here.

    // TODO hs: need a function to clear our StateMap, or to create a new
    // isolated StateMap.
    //
    // TODO hs: Also, we need to expose that function from `TorClient`, possibly
    // in the existing isolation API, possibly in something new.
}

#[async_trait]
impl<R: Runtime> OnionServiceConnector for HsClientConnector<R> {
    async fn create_connection(
        &self,
        service_id: HsId,
    ) -> Result<ClientCirc, OnionConnectError> {
        todo!() // TODO hs

        // This function must do the following, retrying as appropriate.
        //  - Look up the onion descriptor in the state.
        //  - Download the onion descriptor if one isn't there.
        //  - In parallel:
        //    - Pick a rendezvous point from the netdirprovider and launch a
        //      rendezvous circuit to it. Then send ESTABLISH_INTRO.
        //    - Pick a number of introduction points (1 or more) and try to
        //      launch circuits to them.
        //  - On a circuit to an introduction point, send an INTRODUCE1 cell.
        //  - Wait for a RENDEZVOUS2 cell on the rendezvous circuit
        //  - Add a virtual hop to the rendezvous circuit.
        //  - Return the rendezvous circuit.
    }
}
