//! Support for decoding and encoding RPC messages.
//!
//! Every message is either a Request (sent to Arti)
//! or a Response (received from Arti).

pub(crate) mod request;
pub(crate) mod response;

use serde::{Deserialize, Serialize};

/// An identifier for a request made to the Arti RPC system.
///
/// Every request must have an ID, chosen by the application that's sending it.
/// If these IDs are not distinct, the application can get confused about
/// which reply corresponds to which request.
///
/// The [`RpcConn`](crate::conn::RpcConn) type can generate unique IDs
/// for outbound requests as needed.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq, derive_more::From)]
#[serde(untagged)]
pub enum AnyRequestId {
    /// A numeric request ID.
    ///
    /// Note that values above `2^53-1` may not work with all
    /// JSON implementations.
    Number(u64),
    /// A string request ID.
    String(String),
}

/// An identifier for some object visible to the Arti RPC system.
///
/// A single object may have multiple underlying identifiers.
/// These identifiers should always be treated as opaque
/// from the application's perspective.
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Hash,
    Eq,
    PartialEq,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
)]
#[serde(transparent)]
pub struct ObjectId(pub String);
