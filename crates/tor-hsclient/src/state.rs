//! Implement a cache for onion descriptors and the facility to remember a bit
//! about onion service history.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use tor_hscrypto::pk::BlindedOnionId;

/// Information about onion services and our history of connecting to them.
pub(crate) struct StateMap {
    /// A map from blinded onion identity to information about an onion service.
    ///
    /// If the map is to `None`, then a download is in progress for that state's
    /// descriptor.
    members: Mutex<HashMap<BlindedOnionId, Option<State>>>,
}

/// Information about our history of connecting to an onion service.
//
// TODO hs: We might need this to be an enum, if we want to represent "fetch
// pending" as something with a RetryDelay.  We might even want a RetryDelay
// associated with each HsDir for the service as well!
pub(crate) struct State {
    /// A time when we should check whether this descriptor is still the latest.
    desc_fresh_until: SystemTime,
    /// A time when we should expire this entry completely.
    expires: SystemTime,
    /// The latest known onion service descriptor for this service.
    desc: (), // TODO hs: use actual onion service descriptor type.
    /// Information about the latest status of trying to connect to this service
    /// through each of its introduction points.
    ///
    ipts: (), // TODO hs: make this type real, use `RetryDelay`, etc.
}

impl StateMap {
    // TODO hs: we need a way to make the entries here expire over time.
}
