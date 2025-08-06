//! Pseudorandom number utilities for HashX's program generator
//!
//! HashX uses pseudorandom numbers to make individual decisions in the program
//! generation process. The program generator consumes u8 and u32 values that
//! use a shared u64 generator, implemented using SipHash1,3.
//!
//! We use the [`RngCore`] trait for this underlying u64 generator,
//! allowing substitute random number generators for testing or for special
//! purposes that don't require compatibility with HashX proper.
//!
//! The stateful u8 and u32 layer comes from this module's [`RngBuffer`].
//! It's important for the u8 and u32 queues to share a common generator.
//! The order of dequeueing u8 items vs u32 items intentionally modifies the
//! assignment of particular u64 [`RngCore`] values to the two queues.

use crate::siphash::{SipState, siphash13_ctr};
use arrayvec::ArrayVec;
use rand_core::RngCore;

/// Wrap a [`RngCore`] implementation for fast `u8` and `u32` output.
///
/// This maintains small queues for each data type: up to one `u32` and up to
/// 7 bytes. The queueing behavior matches conventions required by HashX:
/// The underlying `u64` values are always generated lazily, and component
/// values are extracted in big endian order.
#[derive(Debug)]
pub(crate) struct RngBuffer<'a, T: RngCore> {
    /// Inner [`RngCore`] implementation
    inner: &'a mut T,
    /// Buffer of remaining u8 values from breaking up a u64
    u8_vec: ArrayVec<u8, 7>,
    /// Up to one buffered u32 value
    u32_opt: Option<u32>,
}

impl<'a, T: RngCore> RngBuffer<'a, T> {
    /// Construct a new empty buffer around a [`RngCore`] implementation.
    ///
    /// No actual random numbers will be generated until the first call to
    /// [`Self::next_u8`] or [`Self::next_u32`].
    #[inline(always)]
    pub(crate) fn new(rng: &'a mut T) -> Self {
        Self {
            inner: rng,
            u8_vec: Default::default(),
            u32_opt: None,
        }
    }

    /// Request 32 bits from the buffered random number generator.
    ///
    /// If we have buffered data stored, returns that. If not,
    /// requests 64 bits from the [`RngCore`] and saves half for later.
    #[inline(always)]
    pub(crate) fn next_u32(&mut self) -> u32 {
        let previous = self.u32_opt;
        match previous {
            Some(value) => {
                self.u32_opt = None;
                value
            }
            None => {
                let value = self.inner.next_u64();
                self.u32_opt = Some(value as u32);
                (value >> 32) as u32
            }
        }
    }

    /// Request 8 bits from the buffered random number generator.
    ///
    /// If we have buffered data stored, returns that. If not,
    /// requests 64 bits from the [`RngCore`] and saves 7 bytes for later.
    #[inline(always)]
    pub(crate) fn next_u8(&mut self) -> u8 {
        let value = self.u8_vec.pop();
        match value {
            Some(value) => value,
            None => {
                // Little endian (reversed) order here,
                // because we dequeue items from the end of the Vec.
                let bytes = self.inner.next_u64().to_le_bytes();
                let (last, saved) = bytes.split_last().expect("u64 has nonzero length");
                self.u8_vec
                    .try_extend_from_slice(saved)
                    .expect("slice length correct");
                *last
            }
        }
    }
}

/// HashX-style random number generator built on SipHash1,3
///
/// This is an implementation of [`RngCore`] using SipHash1,3 as
/// the 64-bit PRNG layer needed by HashX's program generator.
#[derive(Debug, Clone)]
pub struct SipRand {
    /// SipHash state vector used as input to SipHash1,3 in counter mode
    key: SipState,
    /// Next unused counter value
    counter: u64,
}

impl SipRand {
    /// Build a new SipHash random number generator.
    ///
    /// The internal SipHash1,3 generator is initialized to a supplied
    /// internal state, and the counter is reset to zero.
    #[inline(always)]
    pub fn new(key: SipState) -> Self {
        Self::new_with_counter(key, 0)
    }

    /// Build a new [`SipRand`] with a specific initial counter value.
    #[inline(always)]
    pub fn new_with_counter(key: SipState, counter: u64) -> Self {
        Self { key, counter }
    }
}

impl RngCore for SipRand {
    /// Generate a full 64-bit random result using SipHash1,3.
    fn next_u64(&mut self) -> u64 {
        let value = siphash13_ctr(self.key, self.counter);
        self.counter += 1;
        value
    }

    /// Return a 32-bit value by discarding the upper half of a 64-bit result.
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    /// Fill `dest` with random data.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }
}

#[cfg(test)]
mod test {
    use super::{RngBuffer, SipRand, SipState};

    #[test]
    fn rng_vectors() {
        // Check against pseudorandom number streams seen during tor unit tests

        let (key0, _key1) = SipState::pair_from_seed(b"abc");
        let mut rng_inner = SipRand::new(key0);
        let mut rng = RngBuffer::new(&mut rng_inner);

        #[derive(Debug, PartialEq)]
        enum Value {
            U32(u32),
            U8(u8),
        }

        let expected = vec![
            Value::U32(0xf695edd0),
            Value::U32(0x2205449d),
            Value::U32(0x51c1ac51),
            Value::U32(0xcd19a7d1),
            Value::U8(0xad),
            Value::U32(0x79793a52),
            Value::U32(0xd965083d),
            Value::U8(0xf4),
            Value::U32(0x915e9969),
            Value::U32(0x7563b6e2),
            Value::U32(0x4e5a9d8b),
            Value::U32(0xef2bb9ce),
            Value::U8(0xcb),
            Value::U32(0xa4beee16),
            Value::U32(0x78fa6e6f),
            Value::U8(0x30),
            Value::U32(0xc321cb9f),
            Value::U32(0xbbf29635),
            Value::U32(0x919450f4),
            Value::U32(0xf3d8f358),
            Value::U8(0x3b),
            Value::U32(0x818a72e9),
            Value::U32(0x58225fcf),
            Value::U8(0x98),
            Value::U32(0x3fcb5059),
            Value::U32(0xaf5bcb70),
            Value::U8(0x14),
            Value::U32(0xd41e0326),
            Value::U32(0xe79aebc6),
            Value::U32(0xa348672c),
            Value::U8(0xcf),
            Value::U32(0x5d51b520),
            Value::U32(0x73afc36f),
            Value::U32(0x31348711),
            Value::U32(0xca25b040),
            Value::U32(0x3700c37b),
            Value::U8(0x62),
            Value::U32(0xf0d1d6a6),
            Value::U32(0xc1edebf3),
            Value::U8(0x9d),
            Value::U32(0x9bb1f33f),
            Value::U32(0xf1309c95),
            Value::U32(0x0797718a),
            Value::U32(0xa3bbcf7e),
            Value::U8(0x80),
            Value::U8(0x28),
            Value::U8(0xe9),
            Value::U8(0x2e),
            Value::U32(0xf5506289),
            Value::U32(0x97b46d7c),
            Value::U8(0x64),
            Value::U32(0xc99fe4ad),
            Value::U32(0x6e756189),
            Value::U8(0x54),
            Value::U8(0xf7),
            Value::U8(0x0f),
            Value::U8(0x7d),
            Value::U32(0x38c983eb),
        ];

        let mut actual = Vec::new();
        for item in &expected {
            match item {
                Value::U8(_) => actual.push(Value::U8(rng.next_u8())),
                Value::U32(_) => actual.push(Value::U32(rng.next_u32())),
            }
        }

        assert_eq!(expected, actual);
    }
}
