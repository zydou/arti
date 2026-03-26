//! Standard-library time functionality..

// If we've forbidden `now` elsewhere in our project, we enable it here.
// (And only here!)
#![allow(clippy::disallowed_methods)]

pub use std::time::Instant;

use std::time::SystemTime;

impl crate::SystemTimeExt for SystemTime {
    fn get() -> SystemTime {
        SystemTime::now()
    }
}

impl crate::InstantExt for Instant {
    fn get() -> crate::Instant {
        Instant::now()
    }
}
