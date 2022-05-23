//! The `TorEvent` and `TorEventKind` types.
use serde::{Deserialize, Serialize};

/// An event emitted by some Tor-related crate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub enum TorEvent {
    /// An event with no data, used for testing purposes.
    Empty,
}

/// An opaque type describing a variant of `TorEvent`.
///
/// Variants of this enum have the same name as variants of `TorEvent`, but no data. This
/// is useful for functions like `TorEventReceiver::subscribe`, which lets you choose which
/// variants you want to receive.
//
// Internally, these are indices into the `EVENT_SUBSCRIBERS` array.
// NOTE: Update EVENT_KIND_COUNT when adding new events!!
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(usize)]
#[non_exhaustive]
pub enum TorEventKind {
    /// Identifier for [`TorEvent::Empty`].
    Empty = 0,
}

impl TorEvent {
    /// Get the corresponding `TorEventKind` for this event.
    pub fn kind(&self) -> TorEventKind {
        match self {
            TorEvent::Empty => TorEventKind::Empty,
        }
    }
}
