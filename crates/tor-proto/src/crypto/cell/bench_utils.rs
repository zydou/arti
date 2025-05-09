//! Benchmark utilities for the `cell` module.
#[cfg(feature = "counter-galois-onion")]
#[cfg_attr(docsrs, doc(cfg(feature = "counter-galois-onion")))]
pub use super::cgo::bench_utils as cgo;
pub use super::tor1::bench_utils as tor1;
use super::*;

/// Public wrapper around the `InboundClientLayer` trait object.
#[repr(transparent)]
pub struct InboundClientLayerWrapper(pub(in crate::crypto) Box<dyn InboundClientLayer + Send>);

/// Public wrapper around the `InboundClientCrypt` struct.
#[repr(transparent)]
pub struct InboundClientCryptWrapper(pub(in crate::crypto) InboundClientCrypt);

impl InboundClientCryptWrapper {
    /// Create a new `InboundClientCryptWrapper`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new layer to the `InboundClientCryptWrapper` based on a seed.
    pub fn add_layer(&mut self, crypt_state: impl Into<InboundClientLayerWrapper>) {
        let layer: InboundClientLayerWrapper = crypt_state.into();
        self.0.add_layer(layer.0);
    }

    /// Public wrapper around the `InboundClientCrypt::decrypt` method
    /// for benchmarking purposes.
    pub fn decrypt(&mut self, cell: &mut RelayBody) -> Result<()> {
        let cell = &mut cell.0;
        self.0.decrypt(ChanCmd::RELAY, cell)?;

        Ok(())
    }
}

impl Default for InboundClientCryptWrapper {
    fn default() -> Self {
        Self(InboundClientCrypt::new())
    }
}

/// Public wrapper around the `OutboundClientLayer` trait object.
#[repr(transparent)]
pub struct OutboundClientLayerWrapper(pub(in crate::crypto) Box<dyn OutboundClientLayer + Send>);

/// Public wrapper around the `OutboundClientCrypt` struct.
#[repr(transparent)]
pub struct OutboundClientCryptWrapper(pub(in crate::crypto) OutboundClientCrypt);

impl OutboundClientCryptWrapper {
    /// Create a new `OutboundClientCryptWrapper`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new layer to the `OutboundClientCryptWrapper` based on a seed.
    pub fn add_layer(&mut self, crypt_state: impl Into<OutboundClientLayerWrapper>) {
        let layer: OutboundClientLayerWrapper = crypt_state.into();
        self.0.add_layer(layer.0);
    }

    /// Public wrapper around the `OutboundClientCrypt::encrypt` method
    /// for benchmarking purposes.
    pub fn encrypt(&mut self, cell: &mut RelayBody, hop_num: u8) -> Result<()> {
        let cell = &mut cell.0;
        self.0.encrypt(ChanCmd::RELAY, cell, hop_num.into())?;

        Ok(())
    }
}

impl Default for OutboundClientCryptWrapper {
    fn default() -> Self {
        Self(OutboundClientCrypt::new())
    }
}

/// Public wrapper around the `RelayCellBody` struct.
#[repr(transparent)]
pub struct RelayBody(pub(in crate::crypto) RelayCellBody);

impl From<[u8; 509]> for RelayBody {
    fn from(body: [u8; 509]) -> Self {
        let body = Box::new(body);
        Self(body.into())
    }
}

/// Public trait to define the interface of a wrapper around a relay cryptographic state.
pub trait RelayCryptState {
    /// Public wrapper arroud the `InboundRelayLayer::originate` method.
    fn originate(&mut self, cell: &mut RelayBody);
    /// Public wrapper around the `InboundRelayLayer::encrypt_inbound` method.
    fn encrypt(&mut self, cell: &mut RelayBody);
    /// Public wrapper around the `OutboundRelayLayer::decrypt_outbound` method.
    fn decrypt(&mut self, cell: &mut RelayBody);
}

/// Encrypts the given `RelayCell` in the inbound direction by all the relays in a circuit.
pub fn circuit_encrypt_inbound(cell: &mut RelayBody, relay_states: &mut [impl RelayCryptState]) {
    for (i, state) in relay_states.iter_mut().rev().enumerate() {
        if i == 0 {
            state.originate(cell);
        } else {
            state.encrypt(cell);
        }
    }
}
