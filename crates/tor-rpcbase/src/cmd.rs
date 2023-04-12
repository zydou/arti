//! Command type for the RPC system.

use downcast_rs::Downcast;

/// The parameters and method name associated with a given Request.
///
/// We use [`typetag`] here so that we define `Command`s in other crates.
///
/// See [`decl_command!`](crate::decl_command) for a template to declare one of these.
///
/// # Note
///
/// In order to comply with our spec, all Commands' data must be represented as a json
/// object.
//
// TODO RPC: Possible issue here is that, if this trait is public, anybody outside
// of Arti can use this trait to add new commands to the RPC engine. Should we
// care?
#[typetag::deserialize(tag = "method", content = "params")]
pub trait Command: std::fmt::Debug + Send + Downcast {}
downcast_rs::impl_downcast!(Command);

/// Declare that one or more space-separated types should be considered as
/// RPC commands.
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
/// impl rpc::Command for Castigate {}
///
/// rpc::decl_command!{Castigate}
/// ```
#[macro_export]
macro_rules! decl_command {
    {$($id:ident)*}
    =>
    {
        $(
            $crate::impl_const_type_id!{$id}
        )*
    }
}
