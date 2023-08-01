//! Support for reporting the status of an onion service.

/// The current reported status of an onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceStatus {
    // TODO hss Should say how many intro points are active, how many descriptors
    // are updated, whether we're "healthy", etc.
    /// An ignored field to suppress warnings. TODO HSS remove this.
    _ignore: (),
}
