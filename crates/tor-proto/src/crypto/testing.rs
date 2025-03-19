pub(crate) struct FakePRNG<'a> {
    bytes: &'a [u8],
}
impl<'a> FakePRNG<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
impl<'a> rand_core::RngCore for FakePRNG<'a> {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(dest.len() <= self.bytes.len());

        dest.copy_from_slice(&self.bytes[0..dest.len()]);
        self.bytes = &self.bytes[dest.len()..];
    }
}
impl rand_core::CryptoRng for FakePRNG<'_> {}
