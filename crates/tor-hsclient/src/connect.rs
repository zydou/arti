//! Main implementation of the connection functionality

//use std::time::SystemTime;

use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

use crate::{HsClientConnError, HsClientConnector, HsClientSecretKeys};

/// Information about a hidden service, including our connection history
#[allow(dead_code, unused_variables)] // TODO hs remove.
#[derive(Default, Debug)]
pub(crate) struct Data {
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
#[allow(dead_code, unused_variables)] // TODO hs remove.
pub(crate) async fn connect(
    connector: &HsClientConnector<impl Runtime>,
    data: &mut Data,
    secret_keys: HsClientSecretKeys,
) -> Result<ClientCirc, HsClientConnError> {
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
