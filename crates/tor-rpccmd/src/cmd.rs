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
#[typetag::deserialize(tag = "method", content = "data")]
pub trait Command: std::fmt::Debug + Send {
    // TODO RPC: this will need some kind of "run this command" trait.
}
