//! Cryptographic traits for general use throughout Arti.

use subtle::Choice;

/// A simple trait to describe a keyed message authentication code.
///
/// Unlike RustCrypto's
/// [`crypto_mac::Mac`](https://docs.rs/crypto-mac/latest/crypto_mac/trait.Mac.html),
/// this trait does not support incremental processing.
pub trait ShortMac<const MAC_LEN: usize> {
    /// Calculate a message authentication code for `input` using this key.
    fn mac(&self, input: &[u8]) -> crate::util::ct::CtByteArray<MAC_LEN>;

    /// Check whether `mac` is a valid message authentication code for `input`
    /// using this key.
    fn validate(&self, input: &[u8], mac: &[u8; MAC_LEN]) -> Choice;
}
