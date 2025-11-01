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
use tor_error::internal;

use crate::crypto::binding::CircuitBinding;
#[cfg(feature = "counter-galois-onion")]
use crate::crypto::cell::CgoRelayCrypto;
#[cfg(feature = "hs-common")]
use crate::crypto::cell::Tor1Hsv3RelayCrypto;
use crate::crypto::cell::{
    ClientLayer, CryptInit, InboundClientLayer, InboundRelayLayer, OutboundClientLayer,
    OutboundRelayLayer, RelayLayer, Tor1RelayCrypto,
};

use crate::Result;

pub use crate::crypto::handshake::KeyGenerator;
#[cfg(feature = "hs-common")]
pub use crate::crypto::handshake::hs_ntor;

/// The relay protocol to use when extending a circuit manually with
/// [`Circuit::extend_virtual`](crate::client::circuit::ClientCirc::extend_virtual).
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
/// negotiated from [`extend_virtual`](crate::client::circuit::ClientCirc::extend_virtual).
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
    /// The counter galois onion cell encryption protocol.
    #[cfg(feature = "counter-galois-onion")]
    Cgo,
}

#[cfg(feature = "hs-common")]
impl From<RelayProtocol> for RelayCryptLayerProtocol {
    fn from(value: RelayProtocol) -> Self {
        match value {
            // TODO #1948
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
    /// Construct the client cell-crypto layers that are needed for a given set of
    /// circuit hop parameters.
    ///
    /// This returns layers for use in a client circuit,
    /// whether as the initiator or responder of an onion service request.
    pub(crate) fn construct_client_layers(
        self,
        role: HandshakeRole,
        keygen: impl KeyGenerator,
    ) -> Result<BoxedClientLayer> {
        use RelayCellFormat::*;
        use RelayCryptLayerProtocol::*;

        match self {
            Tor1(V0) => construct::<Tor1RelayCrypto, _, _, _, _>(keygen, role),
            Tor1(_) => Err(internal!("protocol not implemented").into()),
            #[cfg(feature = "hs-common")]
            HsV3(V0) => construct::<Tor1Hsv3RelayCrypto, _, _, _, _>(keygen, role),
            #[cfg(feature = "hs-common")]
            HsV3(_) => Err(internal!("protocol not implemented").into()),
            #[cfg(feature = "counter-galois-onion")]
            Cgo => construct::<CgoRelayCrypto, _, _, _, _>(keygen, role),
        }
    }

    /// Return the cell format used by this protocol.
    pub(crate) fn relay_cell_format(&self) -> RelayCellFormat {
        match self {
            RelayCryptLayerProtocol::Tor1(v) => *v,
            #[cfg(feature = "hs-common")]
            RelayCryptLayerProtocol::HsV3(v) => *v,
            #[cfg(feature = "counter-galois-onion")]
            RelayCryptLayerProtocol::Cgo => RelayCellFormat::V1,
        }
    }
}

/// Wrapper to make a relay layer behave as a client layer.
///
/// We use this wrapper to implement onion services,
/// which use relay layers to communicate with clients.
struct ResponderOutboundLayer<L: InboundRelayLayer>(L);
impl<L: InboundRelayLayer> OutboundClientLayer for ResponderOutboundLayer<L> {
    fn originate_for(
        &mut self,
        cmd: tor_cell::chancell::ChanCmd,
        cell: &mut crate::crypto::cell::RelayCellBody,
    ) -> tor_cell::relaycell::msg::SendmeTag {
        self.0.originate(cmd, cell)
    }

    fn encrypt_outbound(
        &mut self,
        cmd: tor_cell::chancell::ChanCmd,
        cell: &mut crate::crypto::cell::RelayCellBody,
    ) {
        self.0.encrypt_inbound(cmd, cell);
    }
}
/// Wrapper to make a relay layer behave as a client layer.
///
/// We use this wrapper to implement onion services,
/// which use relay layers to communicate with clients.
struct ResponderInboundLayer<L: OutboundRelayLayer>(L);
impl<L: OutboundRelayLayer> InboundClientLayer for ResponderInboundLayer<L> {
    fn decrypt_inbound(
        &mut self,
        cmd: tor_cell::chancell::ChanCmd,
        cell: &mut crate::crypto::cell::RelayCellBody,
    ) -> Option<tor_cell::relaycell::msg::SendmeTag> {
        self.0.decrypt_outbound(cmd, cell)
    }
}

/// Helper: Construct a BoxedClientLayer for a layer type L whose inbound and outbound
/// cryptographic states are the same type.
fn construct<L, FC, BC, FR, BR>(
    keygen: impl KeyGenerator,
    role: HandshakeRole,
) -> Result<BoxedClientLayer>
where
    L: CryptInit + ClientLayer<FC, BC> + RelayLayer<FR, BR>,
    FC: OutboundClientLayer + Send + 'static,
    BC: InboundClientLayer + Send + 'static,
    FR: OutboundRelayLayer + Send + 'static,
    BR: InboundRelayLayer + Send + 'static,
{
    let layer = L::construct(keygen)?;
    match role {
        HandshakeRole::Initiator => {
            let (fwd, back, binding) = layer.split_client_layer();
            Ok(BoxedClientLayer {
                fwd: Box::new(fwd),
                back: Box::new(back),
                binding: Some(binding),
            })
        }
        HandshakeRole::Responder => {
            let (fwd, back, binding) = layer.split_relay_layer();
            Ok(BoxedClientLayer {
                // We reverse the inbound and outbound layers before wrapping them,
                // since from the responder's perspective, _they_ are the origin
                // point of the circuit.
                fwd: Box::new(ResponderOutboundLayer(back)),
                back: Box::new(ResponderInboundLayer(fwd)),
                binding: Some(binding),
            })
        }
    }
}
