//! Common types for `StreamCtrl` traits and objects, used to provide a
//! shareable handle for controlling a string.

use std::sync::Arc;

use crate::client::ClientTunnel;

/// An object that lets the owner "control" a client stream.
///
/// In some cases, this may be the stream itself; in others, it will be a handle
/// to the shared parts of the stream. (For data streams, it's not convenient to
/// make the actual `AsyncRead` and `AsyncWrite` types shared, since all the methods
/// on those traits take `&mut self`.)
///
/// This applies to client streams only.
pub trait ClientStreamCtrl {
    /// Return the circuit that this stream is attached to, if that circuit
    /// object is still present.
    ///
    /// (If the circuit object itself is not present, the stream is necessarily
    /// closed.)
    fn tunnel(&self) -> Option<Arc<ClientTunnel>>;
}
