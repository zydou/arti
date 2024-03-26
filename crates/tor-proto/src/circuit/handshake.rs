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
#[cfg(feature = "hs-common")]
use crate::crypto::cell::Tor1Hsv3RelayCrypto;
use crate::crypto::cell::{
    ClientLayer, CryptInit, InboundClientLayer, OutboundClientLayer, Tor1RelayCrypto,
};

use crate::Result;

#[cfg(feature = "hs-common")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs-common")))]
pub use crate::crypto::handshake::hs_ntor;
pub use crate::crypto::handshake::KeyGenerator;

/// The relay protocol to use when extending a circuit manually with
/// [`Circuit::extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
//
// NOTE: These correspond internally to implementations of
// crate::crypto::cell::ClientLayer.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
#[cfg(feature = "hs-common")]
pub enum RelayProtocol {
    /// A variation of Tor's original protocol, using AES-256 and SHA-3.
    HsV3,
}

/// Internal counterpart of RelayProtocol; includes variants that can't be
/// negotiated from [`extend_virtual`](crate::circuit::ClientCirc::extend_virtual).
#[derive(Copy, Clone, Debug)]
pub(crate) enum RelayCryptLayerProtocol {
    /// The original Tor cell encryption protocol, using AES-128 and SHA-1.
    ///
    /// References:
    /// - <https://spec.torproject.org/tor-spec/relay-cells.html>
    /// - <https://spec.torproject.org/tor-spec/routing-relay-cells.html>
    Tor1(RelayCellFormat),
    /// A variation of Tor's original cell encryption protocol, using AES-256
    /// and SHA3-256.
    ///
    /// Reference:
    /// - <https://spec.torproject.org/rend-spec/encrypting-user-data.html>
    /// - <https://spec.torproject.org/rend-spec/introduction-protocol.html#INTRO-HANDSHAKE-REQS>
    #[cfg(feature = "hs-common")]
    HsV3(RelayCellFormat),
}

#[cfg(feature = "hs-common")]
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

        match self {
            Tor1(V0) => construct::<Tor1RelayCrypto<RelayCellFormatV0>, _>(keygen, role),
            Tor1(_) => Err(internal!("protocol not implemented").into()),
            #[cfg(feature = "hs-common")]
            HsV3(V0) => construct::<Tor1Hsv3RelayCrypto<RelayCellFormatV0>, _>(keygen, role),
            #[cfg(feature = "hs-common")]
            HsV3(_) => Err(internal!("protocol not implemented").into()),
        }
    }

    /// Return the cell format used by this protocol.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        match self {
            RelayCryptLayerProtocol::Tor1(v) => *v,
            #[cfg(feature = "hs-common")]
            RelayCryptLayerProtocol::HsV3(v) => *v,
        }
    }
}

/// Helper: Construct a BoxedClientLayer for a layer type L whose inbound and outbound
/// cryptographic states are the same type.
fn construct<L, F>(keygen: impl KeyGenerator, role: HandshakeRole) -> Result<BoxedClientLayer>
where
    L: CryptInit + ClientLayer<F, F>,
    F: OutboundClientLayer + InboundClientLayer + Send + 'static,
{
    let layer = L::construct(keygen)?;
    let (mut fwd, mut back, binding) = layer.split();
    if role == HandshakeRole::Responder {
        std::mem::swap(&mut fwd, &mut back);
    }
    Ok(BoxedClientLayer {
        fwd: Box::new(fwd),
        back: Box::new(back),
        binding: Some(binding),
    })
}
