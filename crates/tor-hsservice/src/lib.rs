#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// TODO hs: Add complete suite of warnings here.
#![allow(dead_code, unused_variables)] // TODO hs remove.

mod err;
mod keys;
mod status;
mod streamproxy;
mod svc;

use async_trait::async_trait;

pub use err::Error;
pub use status::OnionServiceStatus;
pub use svc::OnionService;

/// A Result type describing an onion service operation.
pub type Result<T> = std::result::Result<T, Error>;

/// An object that knows how to handle stream requests.
#[async_trait]
pub trait StreamHandler {
    /// Handle an incoming stream request on a given onion service.
    //
    // TODO hs: the `circ_info` argument should have data about the circuit on
    // which the request arrived. If the client authenticated, it might tell us
    // who they are.  Or it might have information about how many requests
    // (and/or failed requests) we've gotten on the circuit.
    //
    // TODO hs: The `circ_info` argument should at a minimum include the
    // circuit; ideally in a form that we can get a weak reference to it, and
    // use it in the key of a `PtrWeakKeyHashMap`.  (Or we could stick the info
    // in the circuit itself somehow, and access it as a Box<dyn Any>, but
    // that's a bit sketchy type-wise.)
    //
    // TODO hs: the `stream` argument should be an IncomingStream from
    // tor-proto, but that branch is not yet merged as of this writing.
    async fn handle_request(&self, circ_info: &(), stream: ());
}

mod mgr {
    // TODO hs: Do we want to have the notion of a collection of onion services,
    // running in tandem?  Or is that a higher-level crate, possibly a part of
    // TorClient?
}
