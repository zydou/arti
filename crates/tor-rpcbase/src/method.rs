//! Method type for the RPC system.

use downcast_rs::Downcast;

/// The parameters and method name associated with a given Request.
///
/// We use [`typetag`] here so that we define `Method`s in other crates.
///
/// See [`decl_method!`](crate::decl_method) for a template to declare one of these.
///
/// # Note
///
/// In order to comply with our spec, all Methods' data must be represented as a json
/// object.
//
// TODO RPC: Possible issue here is that, if this trait is public, anybody outside
// of Arti can use this trait to add new methods to the RPC engine. Should we
// care?
#[typetag::deserialize(tag = "method", content = "params")]
pub trait Method: std::fmt::Debug + Send + Downcast {}
downcast_rs::impl_downcast!(Method);

/// Declare that one or more space-separated types should be considered as
/// RPC methods.
///
/// # Example
///
/// ```
/// use tor_rpcbase as rpc;
///
/// #[derive(Debug, serde::Deserialize)]
/// struct Castigate {
///    severity: f64,
///    offenses: Vec<String>,
///    accomplice: Option<rpc::ObjectId>,
/// }
///
/// #[typetag::deserialize]
/// impl rpc::Method for Castigate {}
///
/// rpc::decl_method!{Castigate}
/// ```
#[macro_export]
macro_rules! decl_method {
    {$($id:ident)*}
    =>
    {
        $(
            $crate::impl_const_type_id!{$id}
        )*
    }
}
