//! Main implementation of the connection functionality

//use std::time::SystemTime;

use std::sync::Arc;

use async_trait::async_trait;

use tor_hscrypto::pk::HsId;
use tor_netdir::NetDir;
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

use crate::state::MockableConnectorData;
use crate::{ConnError, HsClientConnector, HsClientSecretKeys};

/// Information about a hidden service, including our connection history
#[allow(dead_code, unused_variables)] // TODO hs remove.
#[derive(Default, Debug)]
// This type is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
pub struct Data {
    //    /// A time when we should check whether this descriptor is still the latest.
    //    desc_fresh_until: SystemTime,
    //    /// A time when we should expire this entry completely.
    //    expires: SystemTime,
    /// The latest known onion service descriptor for this service.
    desc: (), // TODO hs: use actual onion service descriptor type.
    /// Information about the latest status of trying to connect to this service
    /// through each of its introduction points.
    ///
    ipts: (), // TODO hs: make this type real, use `RetryDelay`, etc.
}

/// Actually make a HS connection, updating our recorded state as necessary
///
/// `connector` is provided only for obtaining the runtime and netdir (and `mock_for_state`).
/// Obviously, `connect` is not supposed to go looking in `services`.
///
/// This function handles all necessary retrying of fallible operations,
/// (and, therefore, must also limit the total work done for a particular call).
#[allow(dead_code, unused_variables)] // TODO hs remove.
pub(crate) async fn connect(
    connector: &HsClientConnector<impl Runtime>,
    netdir: Arc<NetDir>,
    hsid: HsId,
    data: &mut Data,
    secret_keys: HsClientSecretKeys,
) -> Result<ClientCirc, ConnError> {
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
    todo!()
}

#[async_trait]
impl MockableConnectorData for Data {
    type ClientCirc = ClientCirc;
    type MockGlobalState = ();

    async fn connect<R: Runtime>(
        connector: &HsClientConnector<R>,
        netdir: Arc<NetDir>,
        hsid: HsId,
        data: &mut Self,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Self::ClientCirc, ConnError> {
        connect(connector, netdir, hsid, data, secret_keys).await
    }

    fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool {
        !circuit.is_closing()
    }
}
