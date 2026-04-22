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
pub mod relay_flags;
pub mod version;

pub use misc::{ContactInfo, InvalidNickname, Nickname, NotPresent, NumericBoolean, Unknown};
pub use misc::{Hostname, InternetHost, InvalidHostname, InvalidInternetHost};

pub use misc::B64;
pub use misc::RsaSha1Signature;
pub use misc::{Base64Fingerprint, Fingerprint, Ignored, IgnoredItemOrObjectValue, SpFingerprint};
pub use misc::{Curve25519Public, Ed25519AlgorithmString, Ed25519IdentityLine, Ed25519Public};
pub use misc::{DigestName, IdentifiedDigest};
pub use misc::{Iso8601TimeNoSp, Iso8601TimeSp};

#[cfg(feature = "routerdesc")]
pub use misc::routerdesc;

mod parse2_encode;
pub use parse2_encode::raw_data_object;

use crate::NormalItemArgument;

/// We do not expect `[ ]` around IPv6 addresses when parsing this type
impl NormalItemArgument for std::net::IpAddr {}
impl NormalItemArgument for std::net::Ipv4Addr {}
impl NormalItemArgument for std::net::SocketAddr {}
impl NormalItemArgument for std::net::SocketAddrV4 {}
