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
pub(crate) enum AnyRequestId {
    Number(u64),
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
pub(crate) struct ObjectId(pub String);
