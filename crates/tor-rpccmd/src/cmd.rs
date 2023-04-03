use downcast_rs::Downcast;

use crate::typeid::GetConstTypeId_;

/// The parameters and method name associated with a given Request.
///
/// We use [`typetag`] here so that we define `Command`s in other crates.
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
pub trait Command: GetConstTypeId_ + std::fmt::Debug + Send + Downcast {}
downcast_rs::impl_downcast!(Command);
