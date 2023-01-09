//! Manipulate time periods (as used in the onion service system)

use std::time::{Duration, SystemTime};

/// A period of time as used in the onion service system.
///
/// These time periods are used to derive a different `BlindedOnionIdKey`
/// during each period from each `OnionIdKey`.
#[derive(Copy, Clone, Debug)]
pub struct TimePeriod {
    /// Index of the time periods that have passed since the unix epoch.
    interval_num: u64,
    /// The length of a time period, in seconds.
    length_in_sec: u32,
}

impl TimePeriod {
    /// Construct a time period of a given `length` that contains `when`.
    pub fn new(length: Duration, when: SystemTime) -> Self {
        // The algorithm here is specified in rend-spec-v3 section 2.2.1
        todo!() // TODO hs
    }
    /// Return the time period after this one.
    ///
    /// Return None if this is the last representable time period.
    pub fn next(&self) -> Option<Self> {
        todo!() // TODO hs
    }
    /// Return the time period after this one.
    ///
    /// Return None if this is the first representable time period.
    pub fn prev(&self) -> Option<Self> {
        todo!() // TODO hs
    }
    /// Return true if this time period contains `when`.
    pub fn contains(&self, when: SystemTime) -> bool {
        todo!() // TODO hs
    }
    /// Return a range representing the [`SystemTime`] values contained within
    /// this time period.
    ///
    /// Return None if this time period contains no times that can be
    /// represented as a `SystemTime`.
    pub fn range(&self) -> Option<std::ops::Range<SystemTime>> {
        todo!() // TODO hs
    }
}
