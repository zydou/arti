//! Object type for our RPC system.

use downcast_rs::DowncastSync;
use serde::{Deserialize, Serialize};

/// An object in our RPC system to which methods can be addressed.
pub trait Object: DowncastSync {
    /// Return true if this object should be given an identifier that allows it
    /// to be used outside of the session that generated it.
    ///
    /// Currently, the only use for such IDs in arti is identifying stream
    /// contexts in when opening a SOCKS connection: When an application opens a
    /// stream, it needs to declare what RPC context (like a `TorClient`) it's
    /// using, which requires that some identifier for that context exist
    /// outside of the RPC session that owns it.
    //
    // TODO RPC: It would be neat if this were automatically set to true if and
    // only if there were any "out-of-session psuedomethods" defined on the
    // object.
    fn expose_outside_of_session(&self) -> bool {
        false
    }
}
downcast_rs::impl_downcast!(sync Object);

/// An identifier for an Object within the context of a Session.
///
/// These are opaque from the client's perspective.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Box<str>,
);

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T> From<T> for ObjectId
where
    T: Into<Box<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// Declare that one or more space-separated types should be considered as
/// RPC objects.
///
/// # Example
///
/// ```
/// use tor_rpcbase as rpc;
///
/// #[derive(serde::Deserialize)]
/// struct Houseplant {
///    oxygen_per_sec: f64,
///    benign_neglect: u8
/// }
///
/// rpc::decl_object!{Houseplant}
/// ```
#[macro_export]
macro_rules! decl_object {
    {$($id:ident)*}
    =>
    {
        $(
            $crate::impl_const_type_id!{$id}
            impl $crate::Object for $id {}
        )*
    }
}
