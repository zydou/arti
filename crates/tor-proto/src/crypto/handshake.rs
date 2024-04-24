//! Circuit extension handshake for Tor.
//!
//! Tor circuit handshakes all implement a one-way-authenticated key
//! exchange, where a client that knows a public "onion key" for a
//! relay sends a "client onionskin" to extend to a relay, and receives a
//! "relay onionskin" in response.  When the handshake is successful,
//! both the client and relay share a set of session keys, and the
//! client knows that nobody _else_ shares those keys unless they
//! relay's private onion key.
//!
//! Currently, this module implements only the "ntor" handshake used
//! for circuits on today's Tor.
pub(crate) mod fast;
#[cfg(feature = "hs-common")]
pub mod hs_ntor;
pub(crate) mod ntor;
#[cfg(feature = "ntor_v3")]
pub(crate) mod ntor_v3;

use std::borrow::Borrow;

use crate::Result;
//use zeroize::Zeroizing;
use rand_core::{CryptoRng, RngCore};
use tor_bytes::SecretBuf;

/// A ClientHandshake is used to generate a client onionskin and
/// handle a relay onionskin.
pub(crate) trait ClientHandshake {
    /// The type for the onion key.
    type KeyType;
    /// The type for the state that the client holds while waiting for a reply.
    type StateType;
    /// A type that is returned and used to generate session keys.x
    type KeyGen;
    /// Type of extra data sent from client (without forward secrecy).
    type ClientAuxData: ?Sized;
    /// Type of extra data returned by server (without forward secrecy).
    type ServerAuxData;
    /// Generate a new client onionskin for a relay with a given onion key,
    /// including `client_aux_data` to be sent without forward secrecy.
    ///
    /// On success, return a state object that will be used to
    /// complete the handshake, along with the message to send.
    fn client1<R: RngCore + CryptoRng, M: Borrow<Self::ClientAuxData>>(
        rng: &mut R,
        key: &Self::KeyType,
        client_aux_data: &M,
    ) -> Result<(Self::StateType, Vec<u8>)>;
    /// Handle an onionskin from a relay, and produce aux data returned
    /// from the server, and a key generator.
    ///
    /// The state object must match the one that was used to make the
    /// client onionskin that the server is replying to.
    fn client2<T: AsRef<[u8]>>(
        state: Self::StateType,
        msg: T,
    ) -> Result<(Self::ServerAuxData, Self::KeyGen)>;
}

/// Trait for an object that handles incoming auxiliary data and
/// returns the server's auxiliary data to be included in the reply.
///
/// This is implemented for `FnMut(&H::ClientAuxData) -> Option<H::ServerAuxData>` automatically.
pub(crate) trait AuxDataReply<H>
where
    H: ServerHandshake + ?Sized,
{
    /// Given a list of extensions received from a client, decide
    /// what extensions to send in reply.
    ///
    /// Return None if the handshake should fail.
    fn reply(&mut self, msg: &H::ClientAuxData) -> Option<H::ServerAuxData>;
}

impl<F, H> AuxDataReply<H> for F
where
    H: ServerHandshake + ?Sized,
    F: FnMut(&H::ClientAuxData) -> Option<H::ServerAuxData>,
{
    fn reply(&mut self, msg: &H::ClientAuxData) -> Option<H::ServerAuxData> {
        self(msg)
    }
}

/// A ServerHandshake is used to handle a client onionskin and generate a
/// server onionskin.
pub(crate) trait ServerHandshake {
    /// The type for the onion key.  This is a private key type.
    type KeyType;
    /// The returned key generator type.
    type KeyGen;
    /// Type of extra data sent from client (without forward secrecy).
    type ClientAuxData: ?Sized;
    /// Type of extra data returned by server (without forward secrecy).
    type ServerAuxData;

    /// Perform the server handshake.  Take as input a strong PRNG in `rng`, a
    /// function for processing requested extensions, a slice of all our private
    /// onion keys, and the client's message.
    ///
    /// On success, return a key generator and a server handshake message
    /// to send in reply.
    #[allow(dead_code)] // TODO #1383 ????
    fn server<R: RngCore + CryptoRng, REPLY: AuxDataReply<Self>, T: AsRef<[u8]>>(
        rng: &mut R,
        reply_fn: &mut REPLY,
        key: &[Self::KeyType],
        msg: T,
    ) -> RelayHandshakeResult<(Self::KeyGen, Vec<u8>)>;
}

/// A KeyGenerator is returned by a handshake, and used to generate
/// session keys for the protocol.
///
/// Typically, it wraps a KDF function, and some seed key material.
///
/// It can only be used once.
#[allow(unreachable_pub)] // This is only exported depending on enabled features.
pub trait KeyGenerator {
    /// Consume the key
    fn expand(self, keylen: usize) -> Result<SecretBuf>;
}

/// Generates keys based on the KDF-TOR function.
///
/// This is deprecated and shouldn't be used for new keys.
pub(crate) struct TapKeyGenerator {
    /// Seed for the TAP KDF.
    seed: SecretBuf,
}

impl TapKeyGenerator {
    /// Create a key generator based on a provided seed
    pub(crate) fn new(seed: SecretBuf) -> Self {
        TapKeyGenerator { seed }
    }
}

impl KeyGenerator for TapKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        use crate::crypto::ll::kdf::{Kdf, LegacyKdf};
        LegacyKdf::new(1).derive(&self.seed[..], keylen)
    }
}

/// Generates keys based on SHAKE-256.
pub(crate) struct ShakeKeyGenerator {
    /// Seed for the key generator
    seed: SecretBuf,
}

impl ShakeKeyGenerator {
    /// Create a key generator based on a provided seed
    #[allow(dead_code)] // We'll construct these for v3 onion services
    pub(crate) fn new(seed: SecretBuf) -> Self {
        ShakeKeyGenerator { seed }
    }
}

impl KeyGenerator for ShakeKeyGenerator {
    fn expand(self, keylen: usize) -> Result<SecretBuf> {
        use crate::crypto::ll::kdf::{Kdf, ShakeKdf};
        ShakeKdf::new().derive(&self.seed[..], keylen)
    }
}

/// An error produced by a Relay's attempt to handle a client's onion handshake.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum RelayHandshakeError {
    /// An error in parsing  a handshake message.
    #[error("Problem decoding onion handshake")]
    Fmt(#[from] tor_bytes::Error),
    /// The client asked for a key we didn't have.
    #[error("Client asked for a key or ID that we don't have")]
    MissingKey,
    /// The client did something wrong with their handshake or cryptography.
    #[error("Bad handshake from client")]
    BadClientHandshake,
    /// An internal error.
    #[error("Internal error")]
    Internal(#[from] tor_error::Bug),
}

/// Type alias for results from a relay's attempt to handle a client's onion
/// handshake.
pub(crate) type RelayHandshakeResult<T> = std::result::Result<T, RelayHandshakeError>;
