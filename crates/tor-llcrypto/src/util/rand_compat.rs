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
//! As of July 2022, if you're using the current version of
//! [`ed25519-dalek`], and the latest [`rand_core`], then you can't use
//! this code, because of the compatibility issue mentioned above.
//!
//! ```ignore
//! use rand_core::OsRng;
//! use ed25519_dalek::Keypair;
//!
//! let keypair = Keypair::generate(&mut OsRng);
//! ```
//!
//! (This used to be a problem for `x25519-dalek` too, but that crate has
//! been updated to a version that doesn't have this problem.)
//!
//! But instead, you can wrap the random number generator using the
//! [`RngCompatExt`] extension trait.
//!
//! ```ignore
//! use tor_llcrypto::util::rand_compat::RngCompatExt;
//! use rand_core::OsRng;
//! use ed25519_dalek::Keypair;
//!
//! let keypair = Keypair::generate(&mut OsRng.rng_compat());
//! ```
//!
//! The wrapped RNG can be used with the old version of the RngCore
//! trait, as well as the new one.

// TODO DALEK: We no longer need this module.

use old_rand_core::{CryptoRng as OldCryptoRng, Error as OldError, RngCore as OldRngCore};
use rand_core::{CryptoRng, Error, RngCore};

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

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    /// OR every byte of src into dest.
    ///
    /// Requires that they have the same length.
    fn or_into(dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        for i in 0..dst.len() {
            dst[i] |= src[i];
        }
    }

    /// AND every byte of src into dest.
    ///
    /// Requires that they have the same length.
    fn and_into(dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len());
        for i in 0..dst.len() {
            dst[i] &= src[i];
        }
    }

    #[test]
    fn test_wrapper_as_old() {
        let mut wrapped = testing_rng().rng_compat();

        let mut z64 = 0xffffffffffffffff_u64;
        let mut z32 = 0xffffffff_u32;
        let mut z17 = [0xff_u8; 17];
        let mut z17_try = [0xff_u8; 17];
        let mut o64 = 0_u64;
        let mut o32 = 0_u32;
        let mut o17 = [0_u8; 17];
        let mut o17_try = [0_u8; 17];
        for _ in 0..1000 {
            let u = OldRngCore::next_u64(&mut wrapped);
            z64 &= u;
            o64 |= u;

            let u = OldRngCore::next_u32(&mut wrapped);
            z32 &= u;
            o32 |= u;

            let mut bytes = [0; 17];
            OldRngCore::fill_bytes(&mut wrapped, &mut bytes);
            and_into(&mut z17, &bytes);
            or_into(&mut o17, &bytes);

            let mut bytes = [0; 17];
            OldRngCore::try_fill_bytes(&mut wrapped, &mut bytes).unwrap();
            and_into(&mut z17_try, &bytes);
            or_into(&mut o17_try, &bytes);
        }
        assert_eq!(z64, 0);
        assert_eq!(z32, 0);

        assert_eq!(o64, 0xffffffffffffffff_u64);
        assert_eq!(o32, 0xffffffff_u32);

        assert_eq!(z17, [0; 17]);
        assert_eq!(z17_try, [0; 17]);
        assert_eq!(o17, [0xff; 17]);
        assert_eq!(o17_try, [0xff; 17]);
    }

    #[test]
    fn test_wrapper_as_new() {
        let mut wrapped = testing_rng().rng_compat();

        let mut z64 = 0xffffffffffffffff_u64;
        let mut z32 = 0xffffffff_u32;
        let mut z17 = [0xff_u8; 17];
        let mut z17_try = [0xff_u8; 17];
        let mut o64 = 0_u64;
        let mut o32 = 0_u32;
        let mut o17 = [0_u8; 17];
        let mut o17_try = [0_u8; 17];
        for _ in 0..1000 {
            let u = RngCore::next_u64(&mut wrapped);
            z64 &= u;
            o64 |= u;

            let u = RngCore::next_u32(&mut wrapped);
            z32 &= u;
            o32 |= u;

            let mut bytes = [0; 17];
            RngCore::fill_bytes(&mut wrapped, &mut bytes);
            and_into(&mut z17, &bytes);
            or_into(&mut o17, &bytes);

            let mut bytes = [0; 17];
            RngCore::try_fill_bytes(&mut wrapped, &mut bytes).unwrap();
            and_into(&mut z17_try, &bytes);
            or_into(&mut o17_try, &bytes);
        }
        assert_eq!(z64, 0);
        assert_eq!(z32, 0);

        assert_eq!(o64, 0xffffffffffffffff_u64);
        assert_eq!(o32, 0xffffffff_u32);

        assert_eq!(z17, [0; 17]);
        assert_eq!(z17_try, [0; 17]);
        assert_eq!(o17, [0xff; 17]);
        assert_eq!(o17_try, [0xff; 17]);
    }
}
