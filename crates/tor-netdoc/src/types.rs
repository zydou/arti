//! Various types that can occur in parsed network documents.
//!
//! NOTE: Several of these modules may eventually move elsewhere,
//! or become their own crates.

pub mod family;
pub(crate) mod misc;
pub mod policy;
pub mod version;

#[cfg(feature = "dangerous-expose-struct-fields")]
pub use misc::Nickname;
