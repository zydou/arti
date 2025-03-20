//! Random number generation.
//!
//! For most purposes in Arti, we use one of two random number generators:
//!  - `rand::rng()` (formerly called `rand::thread_rng()`, up till rand 0.9)
//!  - The [`CautiousRng`] implemented here.
//!
//! [`CautiousRng`] should be used whenever we are generating
//! a medium- or long-term cryptographic key:
//! one that will be stored to disk, or used for more than a single communication.
//! It is slower than [`rand::rng()`],
//! but is more robust against several kinds of failure.
//
// Note: Although we want to use CautiousRng
// whenever we generate a medium- or long-term key,
// we do not consider it a major
// security hole if we use rand::rng() instead:
// CautiousRng is a defense-in-depth mechanism.

use digest::{ExtendableOutput, Update};

use rand_core::TryRngCore;
use sha3::Shake256;
use zeroize::Zeroizing;

/// An exceptionally cautious wrapper for [`rand::OsRng`]
///
/// Ordinarily, one trusts `OsRng`.
/// But we want Arti to run on a wide variety of platforms,
/// and the chances of a bogus OsRng increases the more places we run.
/// This Rng combines OsRng with several other entropy sources,
/// in an attempt to reduce the likelihood of creating compromised keys.[^scary]
///
/// This Rng is slower than `OsRng`.
///
/// # Panics
///
/// This rng will panic if `OsRng` fails;
/// but that's the only sensible behavior for a cryptographic-heavy application like ours.
///
/// [^scary]: Who else remembers [CVE-2008-0166](https://www.cve.org/CVERecord?id=CVE-2008-0166)?
#[derive(Default)]
#[allow(clippy::exhaustive_structs)]
pub struct CautiousRng;

impl rand_core::RngCore for CautiousRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = Zeroizing::new([0_u8; 4]);
        self.fill_bytes(buf.as_mut());
        u32::from_le_bytes(*buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = Zeroizing::new([0_u8; 8]);
        self.fill_bytes(buf.as_mut());
        u64::from_le_bytes(*buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut xof = Shake256::default();
        let mut buf = Zeroizing::new([0_u8; 32]);

        // According to some oldschool crypto wisdom,
        // provided by cryptographers wearing tinfoil hats,
        // when you're making a construction like this you should poll your RNGs
        // from least trusted to most-trusted,
        // in case one of the least trusted ones is secretly Pascal's Demon,
        // providing the input deliberately tuned to make your Shake256 output predictable.
        //
        // The idea is somewhat ludicrous, but we have to poll in _some_ order,
        // and just writing this code has put us into a world of tinfoil hats.

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if let Ok(mut rdrand) = rdrand::RdRand::new() {
            // We'll tolerate a failure from rdrand here.
            let _ignore_failure = rdrand.try_fill_bytes(buf.as_mut());
            xof.update(buf.as_ref());
        }
        // TODO: Consider using rndr on aarch64.

        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Some(mut rng) = backup::backup_rng() {
                rng.fill_bytes(buf.as_mut());
                xof.update(buf.as_ref());
            }
        }

        rand::rng().fill_bytes(buf.as_mut());
        xof.update(buf.as_ref());

        rand_core::OsRng
            .try_fill_bytes(buf.as_mut())
            .expect("No strong entropy source was available: cannot proceed");
        xof.update(buf.as_ref());

        xof.finalize_xof_into(dest);
    }
}

impl rand_core::CryptoRng for CautiousRng {}

/// A backup RNG, independent of other known sources.
///
/// Not necessarily strong, but hopefully random enough to cause an attacker some trouble
/// in the event of catastrophic failure.
///
/// A failure from this RNG _does not_ cause a panic.
#[cfg(not(target_arch = "wasm32"))]
mod backup {

    use once_cell::sync::Lazy;
    use rand::{rngs::ReseedingRng, RngCore};
    use rand_chacha::ChaCha20Core;
    use std::sync::{Mutex, MutexGuard};

    /// The type we've chosen to use for our backup Rng.
    ///
    /// (We need to box this because the default JitterRng is unnameable.)
    ///
    /// We use JitterRng to reseed a ChaCha20 core
    /// because it is potentially _very_ slow.
    type BackupRng = ReseedingRng<ChaCha20Core, Box<dyn RngCore + Send>>;

    /// Static instance of our BackupRng; None if we failed to construct one.
    static JITTER_BACKUP: Lazy<Option<Mutex<BackupRng>>> = Lazy::new(new_backup_rng);

    /// Construct a new instance of our backup Rng;
    /// return None on failure.
    fn new_backup_rng() -> Option<Mutex<BackupRng>> {
        let jitter = rand_jitter::JitterRng::new().ok()?;
        let jitter: Box<dyn RngCore + Send> = Box::new(jitter);
        let reseeding = ReseedingRng::new(1024, jitter).ok()?;
        Some(Mutex::new(reseeding))
    }

    /// Return a MutexGuard for our backup rng, or None if we couldn't construct one.
    pub(super) fn backup_rng() -> Option<MutexGuard<'static, BackupRng>> {
        JITTER_BACKUP
            .as_ref()
            .map(|mutex| mutex.lock().expect("lock poisoned"))
    }
}
