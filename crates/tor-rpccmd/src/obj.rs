use downcast_rs::DowncastSync;
use serde::{Deserialize, Serialize};

use crate::typeid::GetConstTypeId_;

pub trait Object: GetConstTypeId_ + DowncastSync {}
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
/// use tor_rpccmd as rpc;
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
        )*
    }
}
