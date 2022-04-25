//! Ciphers used to implement the Tor protocols.
//!
//! Fortunately, Tor has managed not to proliferate ciphers.  It only
//! uses AES, and (so far) only uses AES in counter mode.

/// Re-exports implementations of counter-mode AES.
///
/// These ciphers implement the `cipher::StreamCipher` trait, so use
/// the [`cipher`](https://docs.rs/cipher) crate to access them.
pub mod aes {
    // These implement StreamCipher.
    /// AES128 in counter mode as used by Tor.
    pub type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

    /// AES256 in counter mode as used by Tor.  
    pub type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
}
