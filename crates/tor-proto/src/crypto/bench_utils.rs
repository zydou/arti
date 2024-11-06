//! Collection of benchmarking utilities for the `crypto` module.

use crate::crypto::handshake::ShakeKeyGenerator as KGen;
use crate::Result;
use cipher::{KeyIvInit, StreamCipher};
use digest::Digest;
use tor_bytes::SecretBuf;
use tor_cell::relaycell::RelayCellFormatTrait;

pub use super::cell::tor1::bench_utils::*;
use super::cell::{
    tor1::CryptStatePair, ClientLayer, CryptInit, InboundClientCrypt, OutboundClientCrypt,
    RelayCrypt,
};

/// Public wrapper around the `CryptStatePair` struct.
#[repr(transparent)]
pub struct HopCryptState<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait>(
    CryptStatePair<SC, D, RCF>,
);

/// Public wrapper around the `InboundClientCrypt` struct.
#[repr(transparent)]
pub struct InboundCryptWrapper(InboundClientCrypt);

/// Public wrapper around the `OutboundClientCrypt` struct.
#[repr(transparent)]
pub struct OutboundCryptWrapper(OutboundClientCrypt);

impl<SC: StreamCipher + KeyIvInit, D: Digest + Clone, RCF: RelayCellFormatTrait>
    HopCryptState<SC, D, RCF>
{
    /// Return a new `HopCryptState` based on a seed.
    pub fn construct(seed: SecretBuf) -> Result<Self> {
        Ok(Self(CryptStatePair::construct(KGen::new(seed))?))
    }
}

impl InboundCryptWrapper {
    /// Create a new `InboundClientCryptState`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new layer to the `InboundClientCrypt` based on a seed.
    pub fn add_layer_from_seed<
        SC: StreamCipher + KeyIvInit + Send + 'static,
        D: Digest + Clone + Send + 'static,
        RCF: RelayCellFormatTrait + Send + 'static,
    >(
        &mut self,
        seed: SecretBuf,
    ) -> Result<()> {
        let layer: CryptStatePair<SC, D, RCF> = CryptStatePair::construct(KGen::new(seed))?;
        let (_outbound, inbound, _binding) = layer.split();
        self.0.add_layer(Box::new(inbound));

        Ok(())
    }
}

impl Default for InboundCryptWrapper {
    fn default() -> Self {
        Self(InboundClientCrypt::new())
    }
}

impl OutboundCryptWrapper {
    /// Create a new `OutboundClientCryptState`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a new layer to the `OutboundClientCrypt` based on a seed.
    pub fn add_layer_from_seed<
        SC: StreamCipher + KeyIvInit + Send + 'static,
        D: Digest + Clone + Send + 'static,
        RCF: RelayCellFormatTrait + Send + 'static,
    >(
        &mut self,
        seed: SecretBuf,
    ) -> Result<()> {
        let layer: CryptStatePair<SC, D, RCF> = CryptStatePair::construct(KGen::new(seed))?;
        let (outbound, _inbound, _binding) = layer.split();
        self.0.add_layer(Box::new(outbound));

        Ok(())
    }
}

impl Default for OutboundCryptWrapper {
    fn default() -> Self {
        Self(OutboundClientCrypt::new())
    }
}

/// Encrypts the given `RelayCell` in the inbound direction.
pub fn encrypt_inbound<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait>(
    cell: &mut RelayBody,
    router_states: &mut [HopCryptState<SC, D, RCF>],
) {
    let cell = &mut cell.0;

    for (i, pair) in router_states.iter_mut().rev().enumerate() {
        let pair = &mut pair.0;
        if i == 0 {
            pair.originate(cell);
        }
        pair.encrypt_inbound(cell);
    }
}

/// Public wrapper around the `InboundClientCrypt::decrypt` method
/// for benchmarking purposes.
pub fn client_decrypt(cell: &mut RelayBody, cc_in: &mut InboundCryptWrapper) -> Result<()> {
    let cell = &mut cell.0;
    cc_in.0.decrypt(cell)?;

    Ok(())
}

/// Public wrapper around the `OutboundClientCrypt::encrypt` method
/// for benchmarking purposes.
pub fn client_encrypt(
    cell: &mut RelayBody,
    cc_out: &mut OutboundCryptWrapper,
    hop_num: u8,
) -> Result<()> {
    let cell = &mut cell.0;
    cc_out.0.encrypt(cell, hop_num.into())?;

    Ok(())
}
