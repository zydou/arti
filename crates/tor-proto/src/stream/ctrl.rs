//! Common types for `StreamCtrl` traits and objects, used to provide a
//! shareable handle for controlling a string.

use std::sync::Arc;

use crate::circuit::ClientCirc;

/// An object that lets the owner "control" a client stream.
///
/// In some cases, this may be the stream itself; in others, it will be a handle
/// to the shared parts of the stream. (For data streams, it's not convenient to
/// make the actual `AsyncRead` and `AsyncWrite` types shared, since all the methods
/// on those traits take `&mut self`.)
//
// TODO RPC: Does this also apply to relay-side streams?  (I say no-nickm)
// Does it apply to RESOLVE streams? (I say yes; they are streams-nickm)
// Which methods from DataStreamCtrl does it make sense to move here?
pub trait ClientStreamCtrl {
    /// Return the circuit that this stream is attached to, if that circuit
    /// object is still present.
    ///
    /// (If the circuit object itself is not present, the stream is necessarily
    /// closed.)
    fn circuit(&self) -> Option<Arc<ClientCirc>>;
}
