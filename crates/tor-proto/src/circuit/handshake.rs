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

use tor_cell::relaycell::{RelayCellFormat, RelayCellFormatV0};
use tor_error::internal;

use crate::crypto::binding::CircuitBinding;
use crate::crypto::cell::{
    ClientLayer, CryptInit, InboundClientLayer, OutboundClientLayer, Tor1Hsv3RelayCrypto,
    Tor1RelayCrypto,
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

/// Internal counterpart of RelayProtocol; includes variants that can't be
/// negotiated from [`extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
#[derive(Copy, Clone, Debug)]
pub(crate) enum RelayCryptLayerProtocol {
    /// The original cell Tor encryption format, using AES-128 and SHA-1.
    Tor1(RelayCellFormat),
    /// A variation of Tor's original cell Tor encryption format, using AES-256
    /// and SHA3-256.
    HsV3(RelayCellFormat),
}

impl From<RelayProtocol> for RelayCryptLayerProtocol {
    fn from(value: RelayProtocol) -> Self {
        match value {
            RelayProtocol::HsV3 => RelayCryptLayerProtocol::HsV3(RelayCellFormat::V0),
        }
    }
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

impl RelayCryptLayerProtocol {
    /// Construct the cell-crypto layers that are needed for a given set of
    /// circuit hop parameters.
    pub(crate) fn construct_layers(
        self,
        role: HandshakeRole,
        keygen: impl KeyGenerator,
    ) -> Result<BoxedClientLayer> {
        use RelayCellFormat::*;
        use RelayCryptLayerProtocol::*;

        let swap = role == HandshakeRole::Responder;
        let layer = match self {
            Tor1(V0) => construct::<Tor1RelayCrypto<RelayCellFormatV0>, _>(keygen, swap)?,
            HsV3(V0) => construct::<Tor1Hsv3RelayCrypto<RelayCellFormatV0>, _>(keygen, swap)?,
            _ => return Err(internal!("cell format not implemented").into()),
        };

        Ok(layer)
    }

    /// Return the cell format used by this protocol.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        match self {
            RelayCryptLayerProtocol::Tor1(v) => *v,
            RelayCryptLayerProtocol::HsV3(v) => *v,
        }
    }
}

/// Helper: Construct a BoxedClientLayer for a layer type L whose inbound and outbound
/// cryptographic states are the same type.
fn construct<L, F>(keygen: impl KeyGenerator, swap: bool) -> Result<BoxedClientLayer>
where
    L: CryptInit + ClientLayer<F, F>,
    F: OutboundClientLayer + InboundClientLayer + Send + 'static,
{
    let layer = L::construct(keygen)?;
    let (mut fwd, mut back, binding) = layer.split();
    if swap {
        std::mem::swap(&mut fwd, &mut back);
    }
    Ok(BoxedClientLayer {
        fwd: Box::new(fwd),
        back: Box::new(back),
        binding: Some(binding),
    })
}
