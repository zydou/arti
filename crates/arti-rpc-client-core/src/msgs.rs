//! Support for decoding and encoding RPC messages.
//!
//! Every message is either a Request (sent to Arti)
//! or a Response (received from Arti).

pub(crate) mod request;
pub(crate) mod response;

use std::ffi::NulError;

use serde::{Deserialize, Serialize};

use crate::util::Utf8CString;

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
#[non_exhaustive]
pub enum AnyRequestId {
    /// A numeric request ID.
    ///
    /// Note that values larger than `±2^53-1` may not work with all
    /// JSON implementations.
    Number(i64),
    /// A string request ID.
    String(String),
}

/// An identifier for some object visible to the Arti RPC system.
///
/// A single object may have multiple underlying identifiers.
/// These identifiers should always be treated as opaque
/// from the application's perspective.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq)]
#[serde(transparent)]
pub struct ObjectId(Utf8CString);

impl ObjectId {
    /// Return the global ID for an RPC connection.
    pub fn connection_id() -> Self {
        ObjectId(
            "connection"
                .to_string()
                .try_into()
                .expect("Surprising NULs in string"),
        )
    }
}

impl TryFrom<String> for ObjectId {
    type Error = NulError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(Utf8CString::try_from(value)?))
    }
}
impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl From<ObjectId> for String {
    fn from(v: ObjectId) -> String {
        v.as_ref().into()
    }
}
