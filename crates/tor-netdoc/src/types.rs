//! Various types that can occur in parsed network documents.
//!
//! Some of the types are parsing adapters: transparent newtypes
//! that can be used for type-driven parsing in netdocs.
//! These are needed (rather than using the underlying value type)
//! in cases where network documents have different syntaxes for the same thing.
//!
//! NOTE: Several of these modules may eventually move elsewhere,
//! or become their own crates.

pub mod family;
pub(crate) mod misc;
pub mod policy;
pub mod version;

pub use misc::Nickname;

pub use misc::{Fingerprint, Ignored};
