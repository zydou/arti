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

/// Trait representing an Rng where every output is derived from
/// supposedly strong entropy.
///
/// Implemented by [`CautiousRng`].
///
/// # Warning
///
/// Do not implement this trait for new Rngs unless you know what you are doing;
/// any Rng to which you apply this trait should be _at least_ as
/// unpredictable and secure as `OsRng`.
///
/// We recommend using [`CautiousRng`] when you need an instance of this trait.
pub trait EntropicRng: rand_core::CryptoRng {}

impl EntropicRng for CautiousRng {}

/// Functionality for testing Rng code that requires an EntropicRng.
#[cfg(feature = "testing")]
mod testing {
    /// Testing only: Pretend that an inner RNG truly implements `EntropicRng`.
    #[allow(clippy::exhaustive_structs)]
    pub struct FakeEntropicRng<R>(pub R);

    impl<R: rand_core::RngCore> rand_core::RngCore for FakeEntropicRng<R> {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            self.0.fill_bytes(dst);
        }
    }
    impl<R: rand_core::CryptoRng> rand_core::CryptoRng for FakeEntropicRng<R> {}
    impl<R: rand_core::CryptoRng> super::EntropicRng for FakeEntropicRng<R> {}
}
#[cfg(feature = "testing")]
pub use testing::FakeEntropicRng;

/// An exceptionally cautious wrapper for [`rand_core::OsRng`]
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
            // We'll tolerate a failure from rdrand here,
            // since it can indicate a few different error conditions,
            // including a lack of hardware support, or exhausted CPU entropy
            // (whatever that is supposed to mean).
            // We only want to panic on a failure from OsRng.
            let _ignore_failure = rdrand.try_fill_bytes(buf.as_mut());

            // We add the output from rdrand unconditionally, since a partial return is possible,
            // and since there's no real harm in doing so.
            // (Performance is likely swamped by syscall overhead, and call to our BackupRng.)
            // In the worst case, we just add some NULs in this case, which is fine.
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

    use rand::{RngCore, rngs::ReseedingRng};
    use rand_chacha::ChaCha20Core;
    use std::sync::LazyLock;
    use std::sync::{Mutex, MutexGuard};

    /// The type we've chosen to use for our backup Rng.
    ///
    /// (We need to box this because the default JitterRng is unnameable.)
    ///
    /// We use JitterRng to reseed a ChaCha20 core
    /// because it is potentially _very_ slow.
    type BackupRng = ReseedingRng<ChaCha20Core, Box<dyn RngCore + Send>>;

    /// Static instance of our BackupRng; None if we failed to construct one.
    static JITTER_BACKUP: LazyLock<Option<Mutex<BackupRng>>> = LazyLock::new(new_backup_rng);

    /// Construct a new instance of our backup Rng;
    /// return None on failure.
    fn new_backup_rng() -> Option<Mutex<BackupRng>> {
        let jitter = rand_jitter::JitterRng::new().ok()?;
        let jitter: Box<dyn RngCore + Send> = Box::new(jitter);
        // The "1024" here is chosen more or less arbitrarily;
        // we might want to tune it if we find that it matters.
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
