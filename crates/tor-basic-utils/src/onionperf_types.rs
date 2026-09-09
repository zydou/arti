//! Types representing events that are emitted to enable onionperf.
//!
//! These are intended to reflect the C Tor meanings of the similar events,
//! see [asynchronous events spec] for more details, as well as arti#173.
//!
//! [asynchronous events spec]: https://spec.torproject.org/control-spec/replies.html#asynchronous-events

// It would be nice to include various IDs in these enums,
// but doing so would create a circular dependency,
// as the crates that define those types depend on tor-basic-utils.
#[derive(Debug)]
#[non_exhaustive]
/// An event that is intended to be ingested by onionperf.
pub enum OnionperfEvent {
    /// A stream-related event (`STREAM` in C Tor)
    ///
    /// Note that this somewhat conflates SOCKS proxy streams and data streams,
    /// as C Tor does the same.
    ///
    /// These can be distinguished, as the data streams have a stream ID set in
    /// the emitted events, while the SOCKS streams do not.
    Stream(OnionperfStreamStatus),
    /// A circuit-related event (`CIRC` in C Tor).
    Circuit(OnionperfCircuitStatus),
    /// A guard-related event (`GUARD` in C Tor).
    Guard(OnionperfGuardStatus),
}

#[derive(Debug)]
#[non_exhaustive]
/// A stream status that is intended to be ingested by onionperf.
pub enum OnionperfStreamStatus {
    /// A stream was newly created (`NEW` in C Tor).
    New,
    /// A stream was closed (`CLOSED` in C Tor).
    Closed,
    /// A stream has failed and been closed due to an error (`FAILED` in C Tor).
    Failed,
}

#[derive(Debug)]
#[non_exhaustive]
/// A circuit status that is intended to be ingested by onionperf.
pub enum OnionperfCircuitStatus {
    /// A new circuit was built (`BUILT` in C Tor).
    Built,
    /// This tunnel is now usable (`LAUNCHED` in C Tor).
    Launched,
    /// This circuit was successfully extended by another hop (`EXTENDED` in C Tor).
    Extended,
    /// This circuit was closed, either cleanly or due to an error (`CLOSED` in C Tor).
    Closed,
    /// This tunnel was not successfully created (`FAILED` in C Tor).
    Failed,
}

#[derive(Debug)]
#[non_exhaustive]
/// A guard status that is intended to be ingested by onionperf.
pub enum OnionperfGuardStatus {
    /// A new guard has been added to the set of available guards (`NEW` in C Tor).
    New,
    /// This guard has been used successfully (`UP` in C Tor).
    Up,
    /// We attempted to use this guard but were not successful (`DOWN` in  C Tor).
    Down,
    /// This guard was removed from the set of available guards (`DROPPED` in C Tor).
    Dropped,
}
