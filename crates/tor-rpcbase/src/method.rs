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
pub trait DynMethod: std::fmt::Debug + Send + Downcast {}
downcast_rs::impl_downcast!(DynMethod);

/// A typed method, used to ensure that all implementations of a method have the
/// same success and updates types.
///
/// Prefer to implement this trait, rather than `DynMethod`. (`DynMethod`
/// represents a type-erased method, with statically-unknown `Output` and
/// `Update` types.)
pub trait Method: DynMethod {
    /// A type returned by this method on success.
    type Output: serde::Serialize + Send + 'static;
    /// A type sent by this method on updates.
    ///
    /// If this method will never send updates, use the uninhabited
    /// [`NoUpdates`] type.
    type Update: serde::Serialize + Send + 'static;
}

/// An uninhabited type, used to indicate that a given method will never send
/// updates.
#[derive(serde::Serialize)]
#[allow(clippy::exhaustive_enums)]
pub enum NoUpdates {}

/// Declare that one or more space-separated types should be considered as RPC
/// methods.
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
/// rpc::decl_method!{ "x-example:castigate" => Castigate}
///
/// impl rpc::Method for Castigate {
///     type Output = String;
///     type Update = rpc::NoUpdates;
/// }
/// ```
///
/// # Limitations
///
/// For now you'll need to import the `typetag` crate; unfortunately, it doesn't
/// yet behave well when used where it is not in scope as `typetag`.
#[macro_export]
macro_rules! decl_method {
    {$($name:expr => $id:ident),* $(,)?}
    =>
    {
        $(
            $crate::impl_const_type_id!{$id}
            #[typetag::deserialize(name = $name)]
            impl $crate::DynMethod for $id {}
        )*
    }
}
