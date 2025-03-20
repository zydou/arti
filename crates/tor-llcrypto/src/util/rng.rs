//! Prng utilities.

/// Helper to implement rand_core_06 for an Rng providing RngCore from rand_core 0.9.
///
/// We need this (for now) for compatibility with *-dalek and
/// some other crypto libraries.
///
/// (Please avoid propagating this type outside of the tor-llcrypto crate.
/// If you need it for a legacy crypto tool, it is usually better to wrap
/// that tool with an API that uses RngCompat.)
#[cfg_attr(feature = "rng-compat", visibility::make(pub))]
pub struct RngCompat<R>(R);

impl<R> RngCompat<R> {
    /// Create a ne RngCompat to wrap `rng`
    #[cfg_attr(feature = "rng-compat", visibility::make(pub))]
    pub(crate) fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: rand_core::RngCore> rand_core_06::RngCore for RngCompat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}
impl<R: rand_core::CryptoRng> rand_core_06::CryptoRng for RngCompat<R> {}

impl<R: rand_core_06::RngCore> rand_core::RngCore for RngCompat<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
}

impl<R: rand_core_06::CryptoRng + rand_core_06::RngCore> rand_core::CryptoRng for RngCompat<R> {}
