//! Wasm-specific time functionality.

// If we've forbidden `now` elsewhere in our project, we enable it here.
#![allow(clippy::disallowed_methods)]

pub use web_time::Instant;

impl crate::SystemTimeExt for std::time::SystemTime {
    fn get() -> std::time::SystemTime {
        use web_time::web::SystemTimeExt as _;
        let now = web_time::SystemTime::now();
        now.to_std()
    }
}

impl crate::InstantExt for Instant {
    fn get() -> crate::Instant {
        Instant::now()
    }
}
