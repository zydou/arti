//! Features for manual invocation of Tor's cryptographic circuit handshakes.
//!
//! These features are used to implement onion services, by giving the onion
//! service code more direct control over the lower-level pieces of the protocol.

// Here we re-export some key types from our cryptographic code, for use when we
// implement our onion handshake.
//
// TODO hs: it might be neat, someday,  to clean this all up so that the types
// and functions in hs_ntor are all methods on a set of related traits.  But
// that can wait IMO until we have a second circuit creation mechanism for use
// with ntor.

pub use crate::crypto::handshake::hs_ntor;
pub use crate::crypto::handshake::KeyGenerator;

/// The relay protocol to use when extending a circuit manually with
/// [`Circuit::extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
//
// NOTE: These correspond internally to implementations of
// crate::crypto::cell::ClientLayer.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum RelayProtocol {
    /// A variation of Tor's original protocol, using AES-256 and SHA-3.
    HsV3,
}

/// What role we are playing in a handshake.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum HandshakeRole {
    /// We are the party initiating the handshake.
    Initiator,
    /// We are the party responding to the handshake.
    Responder,
}
