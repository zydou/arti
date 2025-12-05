//! Benchmark utilities for the `cell` module.
pub use super::ClientLayer;
pub use super::CryptInit;
pub use super::InboundClientCrypt;
pub use super::InboundClientLayer;
pub use super::InboundRelayLayer;
pub use super::OutboundClientCrypt;
pub use super::OutboundClientLayer;
pub use super::OutboundRelayLayer;
pub use super::RelayCellBody;
pub use super::RelayLayer;
#[cfg(feature = "counter-galois-onion")]
pub use super::cgo::bench_utils as cgo;
pub use super::tor1::bench_utils as tor1;
use super::*;

/// The channel command used as additional data for the cryptographic operations benchmarks.
pub const BENCH_CHAN_CMD: ChanCmd = ChanCmd::RELAY;

impl InboundClientCrypt {
    /// Helper method to add an inbound layer from a client layer pair.
    pub fn add_layer_from_pair<F, B>(&mut self, pair: impl ClientLayer<F, B>)
    where
        F: OutboundClientLayer,
        B: InboundClientLayer + Send + 'static,
    {
        let (_, inbound, _) = pair.split_client_layer();
        self.add_layer(Box::new(inbound));
    }
}

impl OutboundClientCrypt {
    /// Helper method to add an outbound layer from a client layer pair.
    pub fn add_layer_from_pair<F, B>(&mut self, pair: impl ClientLayer<F, B>)
    where
        F: OutboundClientLayer + Send + 'static,
        B: InboundClientLayer,
    {
        let (outbound, _, _) = pair.split_client_layer();
        self.add_layer(Box::new(outbound));
    }
}

/// Encrypts the given `RelayCellBody` in the inbound direction by all the relays in a circuit.
pub fn circuit_encrypt_inbound<F, B>(
    cmd: ChanCmd,
    cell: &mut RelayCellBody,
    relay_states: Vec<impl RelayLayer<F, B>>,
) where
    F: OutboundRelayLayer,
    B: InboundRelayLayer,
{
    for (i, state) in relay_states.into_iter().rev().enumerate() {
        let (_, mut inbound, _) = state.split_relay_layer();
        if i == 0 {
            inbound.originate(cmd, cell);
        } else {
            inbound.encrypt_inbound(cmd, cell);
        }
    }
}
