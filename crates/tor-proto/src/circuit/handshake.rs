//! Features for manual invocation of Tor's cryptographic circuit handshakes.
//!
//! These features are used to implement onion services, by giving the onion
//! service code more direct control over the lower-level pieces of the protocol.

// Here we re-export some key types from our cryptographic code, for use when we
// implement our onion handshake.
//
// TODO: it might be neat, someday,  to clean this all up so that the types
// and functions in hs_ntor are all methods on a set of related traits.  But
// that can wait IMO until we have a second circuit creation mechanism for use
// with onion services.

use tor_cell::relaycell::RelayCellFormat;

use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    ClientLayer, CryptInit, InboundClientLayer, OutboundClientLayer, Tor1Hsv3RelayCrypto,
};
use crate::Result;

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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandshakeRole {
    /// We are the party initiating the handshake.
    Initiator,
    /// We are the party responding to the handshake.
    Responder,
}

/// A set of type-erased cryptographic layers to use for a single hop at a
/// client.
pub(crate) struct BoxedClientLayer {
    /// The outbound cryptographic layer to use for this hop
    pub(crate) fwd: Box<dyn OutboundClientLayer + Send>,
    /// The inbound cryptogarphic layer to use for this hop
    pub(crate) back: Box<dyn InboundClientLayer + Send>,
    /// A circuit binding key for this hop.
    pub(crate) binding: Option<CircuitBinding>,
}

impl RelayProtocol {
    /// Construct the cell-crypto layers that are needed for a given set of
    /// circuit hop parameters.
    pub(crate) fn construct_layers(
        self,
        role: HandshakeRole,
        keygen: impl KeyGenerator,
    ) -> Result<BoxedClientLayer> {
        match self {
            RelayProtocol::HsV3 => {
                let seed_needed = Tor1Hsv3RelayCrypto::seed_len();
                let seed = keygen.expand(seed_needed)?;
                // XXX
                let format = RelayCellFormat::V0;
                let layer = Tor1Hsv3RelayCrypto::initialize(format, &seed)?;
                let (fwd, back, binding) = layer.split();
                let (fwd, back) = match role {
                    HandshakeRole::Initiator => (fwd, back),
                    HandshakeRole::Responder => (back, fwd),
                };
                Ok(BoxedClientLayer {
                    fwd: Box::new(fwd),
                    back: Box::new(back),
                    binding: Some(binding),
                })
            }
        }
    }
}
