//! Compatibility utilities for working with libraries that consume
//! older versions of rand_core.
//!
//! The dalek-crypto libraries are currently stuck on [`rand_core`]
//! 0.5.1, but everywhere else in Arti we want to use the latest
//! [`rand_core`] (0.6.2 as of this writing).  The extension trait in this
//! module lets us do so.
//!
//! # Example:
//!
//! As of May 2021, if you're using the current version of
//! [`x25519-dalek`], and the latest [`rand_core`], then you can't use
//! this code, because of the compatibility issue mentioned above.
//!
//! ```compile_fail
//! use rand_core::OsRng;
//! use x25519_dalek::EphemeralSecret;
//!
//! let my_secret = EphemeralSecret::new(OsRng);
//! ```
//!
//! But instead, you can wrap the random number generator using the
//! [`RngCompatExt`] extension trait.
//!
//! ```
//! use tor_llcrypto::util::rand_compat::RngCompatExt;
//! use rand_core::OsRng;
//! use x25519_dalek::EphemeralSecret;
//!
//! let my_secret = EphemeralSecret::new(OsRng.rng_compat());
//! ```
//!
//! The wrapped RNG can be used with the old version of the RngCode
//! trait, as well as the new one.

use old_rand_core::{CryptoRng as OldCryptoRng, Error as OldError, RngCore as OldRngCore};
use rand_core::{CryptoRng, Error, RngCore};

use std::convert::TryInto;

/// Extension trait for the _current_ versions of [`RngCore`]; adds a
/// compatibility-wrapper function.
pub trait RngCompatExt: RngCore {
    /// Wrapper type returned by this trait.
    type Wrapper: RngCore + OldRngCore;
    /// Return a version of this Rng that can be used with older versions
    /// of the rand_core and rand libraries, as well as the current version.
    fn rng_compat(self) -> Self::Wrapper;
}

impl<T: RngCore + Sized> RngCompatExt for T {
    type Wrapper = RngWrapper<T>;
    fn rng_compat(self) -> RngWrapper<Self> {
        self.into()
    }
}

/// A new-style Rng, wrapped for backward compatibility.
///
/// This object implements both the current (0.6.2) version of [`RngCore`],
/// as well as the version from 0.5.1 that the dalek-crypto functions expect.
///
/// To get an RngWrapper, use the [`RngCompatExt`] extension trait:
/// ```
/// use tor_llcrypto::util::rand_compat::RngCompatExt;
///
/// let mut wrapped_rng = rand::thread_rng().rng_compat();
/// ```
pub struct RngWrapper<T>(T);

impl<T: RngCore> From<T> for RngWrapper<T> {
    fn from(rng: T) -> RngWrapper<T> {
        RngWrapper(rng)
    }
}

impl<T: RngCore> OldRngCore for RngWrapper<T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), OldError> {
        self.0.try_fill_bytes(dest).map_err(|e| err_to_old(&e))
    }
}

impl<T: RngCore> RngCore for RngWrapper<T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<T: CryptoRng> OldCryptoRng for RngWrapper<T> {}
impl<T: CryptoRng> CryptoRng for RngWrapper<T> {}

/// Convert a new-ish Rng error into the error type that rng_core 0.5.1
/// would deliver.
fn err_to_old(e: &Error) -> OldError {
    use std::num::NonZeroU32;
    if let Some(code) = e.code() {
        code.into()
    } else {
        // CUSTOM_START is defined to be a nonzero value in rand_core,
        // so this conversion will succeed, so this unwrap can't panic.
        #[allow(clippy::unwrap_used)]
        let nz: NonZeroU32 = OldError::CUSTOM_START.try_into().unwrap();
        nz.into()
    }
}
