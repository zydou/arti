//! HashX-flavored SipHash implementation
//!
//! We need SipHash to generate parts of HashX's internal state: the initial
//! register values for the hash program, and the stream of pseudorandom numbers
//! used to generate the program itself. The fundamentals are as described in
//! the SipHash paper, but much of the algorithm around the basic add-rotate-xor
//! core has been modified:
//!
//!   - Seeding: vanilla SipHash uses a nothing-up-my-sleeve constant to safely
//!     init 256 bits of internal state from 128 bits of user-supplied key data.
//!     The HashX implementation instead uses Blake2b to pre-process an
//!     arbitrary sized seed into a 512-bit pseudorandom value which is directly
//!     used to init the state of two SipHash instances.
//!
//!   - The SipHash paper describes a compression function that includes a
//!     length indicator and padding, and supports variable length inputs. This
//!     is not needed, and HashX uses its own way of constructing a SipHash2,4
//!     instance that takes a counter as input.
//!
//!   - HashX also needs SipHash1,3 which it uses for a lightweight pseudorandom
//!     number stream internally. This variant isn't typically used on its own
//!     or implemented in libraries. HashX also uses its own counter input
//!     construction method.
//!
//!   - In addition to the SipHash1,3 and SipHash2,4 counter modes, HashX
//!     makes use of raw SipRounds while digesting a RegisterFile after the
//!     generated hash function completes.
//!
//! SipHash is defined by Jean-Philippe Aumasson and Daniel J.Bernstein in
//! their paper "SipHash: a fast short-input PRF" (2012).

use blake2::digest::block_buffer::LazyBuffer;
use blake2::digest::core_api::{BlockSizeUser, UpdateCore, VariableOutputCore};
use blake2::Blake2bVarCore;
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::mem;

/// HashX-style random number generator built on SipHash1,3
///
/// This offers a choice of 8-bit and 32-bit outputs, with separate queues to
/// deliver each using the 64-bit results from one shared SipHash1,3 counter.
/// The SipHash counter always starts at zero, and each queue runs in
/// most-significant to least-significant order.
#[derive(Debug, Clone)]
pub(crate) struct Rng {
    /// SipHash state vector used as input to SipHash1,3 in counter mode
    key: State,
    /// Next unused counter value
    counter: u64,
    /// Buffer 64-bit random words into 32-bit results
    u32_buffer: RngBuffer<u32>,
    /// Buffer 64-bit random words into 8-bit results
    u8_buffer: RngBuffer<u8>,
}

impl Rng {
    /// Build a new random number generator as defined by HashX.
    ///
    /// The internal SipHash1,3 generator is initialized to a supplied
    /// internal state, and the counter is reset to zero.
    pub(crate) fn new(key: State) -> Self {
        Rng {
            key,
            counter: 0,
            u32_buffer: RngBuffer::<u32>::new(),
            u8_buffer: RngBuffer::<u8>::new(),
        }
    }

    /// Generate a full 64-bit random result using SipHash1,3
    fn next_u64(&mut self) -> u64 {
        let value = siphash13_ctr(self.key, self.counter);
        self.counter += 1;
        value
    }

    /// Pull 32 bits of random data from the buffer,
    /// refilling it from SipHash as necessary.
    pub(crate) fn next_u32(&mut self) -> u32 {
        let attempt = self.u32_buffer.pop();
        match attempt {
            Some(value) => value,
            None => {
                let word = self.next_u64();
                self.u32_buffer.refill_and_pop(word)
            }
        }
    }

    /// Pull 8 bits of random data from the buffer,
    /// refilling it from SipHash as necessary.
    pub(crate) fn next_u8(&mut self) -> u8 {
        let attempt = self.u8_buffer.pop();
        match attempt {
            Some(value) => value,
            None => {
                let word = self.next_u64();
                self.u8_buffer.refill_and_pop(word)
            }
        }
    }
}

/// Shift register buffer for breaking one u64 down into smaller parts
#[derive(Debug, Clone)]
struct RngBuffer<T> {
    /// Current state of shift buffer
    word: u64,
    /// Number of least significant bits in 'word' that are still valid.
    remaining: u8,
    /// Our return type T is not stored on its own
    phantom: PhantomData<T>,
}

impl<T: TryFrom<u64>> RngBuffer<T>
where
    <T as TryFrom<u64>>::Error: Debug,
{
    /// Size of T in bits
    const BITS_PER_ITEM: u8 = (mem::size_of::<T>() * 8) as u8;

    /// Mask for selecting T from the least significant bits of a u64
    const ITEM_MASK: u64 = (1 << Self::BITS_PER_ITEM) - 1;

    /// Construct a new shift register buffer containing no data bits
    fn new() -> Self {
        Self {
            word: 0,
            remaining: 0,
            phantom: PhantomData,
        }
    }

    /// Return the current item at the output position of the shift
    /// register, masked and cast to the output data type.
    #[inline(always)]
    fn item_at_bit_position(&self) -> T {
        ((self.word >> self.remaining) & Self::ITEM_MASK)
            .try_into()
            .expect("item mask is always narrower than item type")
    }

    /// Refill the buffer and remove the most significant item.
    /// Buffer must be empty.
    fn refill_and_pop(&mut self, word: u64) -> T {
        assert!(self.remaining == 0);
        self.word = word;
        self.remaining = 64 - Self::BITS_PER_ITEM;
        self.item_at_bit_position()
    }

    /// Remove the most significant item in this buffer
    fn pop(&mut self) -> Option<T> {
        if self.remaining >= Self::BITS_PER_ITEM {
            self.remaining -= Self::BITS_PER_ITEM;
            Some(self.item_at_bit_position())
        } else {
            assert_eq!(self.remaining, 0);
            None
        }
    }
}

/// Internal state of one SipHash instance
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct State {
    /// State variable V0 as defined in the SipHash paper
    pub(crate) v0: u64,
    /// State variable V1 as defined in the SipHash paper
    pub(crate) v1: u64,
    /// State variable V2 as defined in the SipHash paper
    pub(crate) v2: u64,
    /// State variable V3 as defined in the SipHash paper
    pub(crate) v3: u64,
}

impl Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "siphash::State {{ v0: {:#018x}, v1: {:#018x}, v2: {:#018x}, v3: {:#018x} }}",
            self.v0, self.v1, self.v2, self.v3
        )
    }
}

impl State {
    /// Size of the internal SipHash state
    const SIZE: usize = 32;

    /// Construct a new SipHash state directly from bytes.
    /// This is not suitable for use with arbitrary user input, such
    /// as all zeroes. HashX always generates these initialization vectors
    /// using another pseudorandom function (Blake2b).
    fn new_from_bytes(bytes: &[u8; Self::SIZE]) -> State {
        State {
            v0: u64::from_le_bytes(bytes[0..8].try_into().expect("slice length matches")),
            v1: u64::from_le_bytes(bytes[8..16].try_into().expect("slice length matches")),
            v2: u64::from_le_bytes(bytes[16..24].try_into().expect("slice length matches")),
            v3: u64::from_le_bytes(bytes[24..32].try_into().expect("slice length matches")),
        }
    }

    /// Construct a pair of SipHash instances from the Blake2b hash of a
    /// variable length seed bytestring.
    pub(crate) fn pair_from_seed(seed: &[u8]) -> (State, State) {
        /// Choice of Blake2b engine; we need to use its lower level
        /// interface, to access new_with_params().
        type Core = Blake2bVarCore;

        /// Blake2b block size
        type BlockSize = <Core as BlockSizeUser>::BlockSize;

        let mut buffer = LazyBuffer::<BlockSize>::new(&[]);
        let mut core = Core::new_with_params(b"HashX v1", &[], 0, 64);
        let mut digest = Default::default();

        buffer.digest_blocks(seed, |blocks| core.update_blocks(blocks));
        core.finalize_variable_core(&mut buffer, &mut digest);

        (
            Self::new_from_bytes(digest[0..32].try_into().expect("slice length matches")),
            Self::new_from_bytes(digest[32..64].try_into().expect("slice length matches")),
        )
    }

    /// One `SipRound` as defined in the SipHash paper.
    #[inline(always)]
    pub(crate) fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(13);
        self.v3 = self.v3.rotate_left(16);
        self.v1 ^= self.v0;
        self.v3 ^= self.v2;
        self.v0 = self.v0.rotate_left(32);

        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = self.v1.rotate_left(17);
        self.v3 = self.v3.rotate_left(21);
        self.v1 ^= self.v2;
        self.v3 ^= self.v0;
        self.v2 = self.v2.rotate_left(32);
    }
}

/// HashX's flavor of SipHash1,3 counter mode with 64-bit output
fn siphash13_ctr(key: State, input: u64) -> u64 {
    let mut s = key;
    s.v3 ^= input;

    s.sip_round();

    s.v0 ^= input;
    s.v2 ^= 0xff;

    s.sip_round();
    s.sip_round();
    s.sip_round();

    s.v0 ^ s.v1 ^ s.v2 ^ s.v3
}

/// HashX's flavor of SipHash2,4 counter mode with 512-bit output
pub(crate) fn siphash24_ctr(key: State, input: u64) -> [u64; 8] {
    let mut s = key;
    s.v1 ^= 0xee;
    s.v3 ^= input;

    s.sip_round();
    s.sip_round();

    s.v0 ^= input;
    s.v2 ^= 0xee;

    s.sip_round();
    s.sip_round();
    s.sip_round();
    s.sip_round();

    let mut t = s;
    t.v1 ^= 0xdd;

    t.sip_round();
    t.sip_round();
    t.sip_round();
    t.sip_round();

    [s.v0, s.v1, s.v2, s.v3, t.v0, t.v1, t.v2, t.v3]
}

#[cfg(test)]
mod test {
    use super::{siphash24_ctr, Rng, State};

    #[test]
    fn sip_round_vectors() {
        // Test values from Appendix A of the SipHash paper

        // Includes constants, first message block, and keys
        let mut s = State {
            v0: 0x7469686173716475,
            v1: 0x6b617f6d656e6665,
            v2: 0x6b7f62616d677361,
            v3: 0x7c6d6c6a717c6d7b,
        };

        // Rounds for first example message block
        s.sip_round();
        s.sip_round();

        // Sample output after two rounds
        assert_eq!(
            s,
            State {
                v0: 0x4d07749cdd0858e0,
                v1: 0x0d52f6f62a4f59a4,
                v2: 0x634cb3577b01fd3d,
                v3: 0xa5224d6f55c7d9c8,
            }
        );
    }

    #[test]
    fn seed_hash_vectors() {
        // Check against seed hash values seen during tor unit tests

        let (key0, key1) = State::pair_from_seed(b"");
        assert_eq!(
            key0,
            State {
                v0: 0xcaca7747b3c5be92,
                v1: 0x296abd268b5f21de,
                v2: 0x9e4c4d2f95add72a,
                v3: 0x00ac7f27331ec1c7,
            }
        );
        assert_eq!(
            key1,
            State {
                v0: 0xc32d197f86f1c419,
                v1: 0xbbe47abaf4e28dfe,
                v2: 0xc174b9d5786f28d4,
                v3: 0xa2bd4197b22a035a,
            }
        );

        let (key0, key1) = State::pair_from_seed(b"abc");
        assert_eq!(
            key0,
            State {
                v0: 0xc538fa793ed99a50,
                v1: 0xd2fd3e8871310ea1,
                v2: 0xd2be7d8aff1f823a,
                v3: 0x557b84887cfe6c0e,
            }
        );
        assert_eq!(
            key1,
            State {
                v0: 0x610218b2104c3f5a,
                v1: 0x4222e8a58e702331,
                v2: 0x0d53a2563a33148d,
                v3: 0x7c24f97da4bff21f,
            }
        );
    }

    #[test]
    fn siphash24_ctr_vectors() {
        // Check against siphash24_ctr output seen during tor unit tests

        let (_key0, key1) = State::pair_from_seed(b"abc");
        assert_eq!(
            siphash24_ctr(key1, 0),
            [
                0xe8a59a4b3ccb5e4a,
                0xe45153f8bb93540d,
                0x32c6accb77141596,
                0xd5deaa56a3b1cfd7,
                0xc5f6ff8435b80af4,
                0xd26fd3ccfdf2a04f,
                0x3d7fa0f14653348e,
                0xf5a4750be0aa2ccf,
            ]
        );
        assert_eq!(
            siphash24_ctr(key1, 999),
            [
                0x312470a168998148,
                0xc9624473753e8d0e,
                0xc0879d8f0de37dbf,
                0xfa4cc48f4f6e95d5,
                0x9940dc39eaaceb2c,
                0x29143feae886f221,
                0x98f119184c4cffe5,
                0xcf1571c6d0d18131,
            ]
        );
    }

    #[test]
    fn rng_vectors() {
        // Check against pseudorandom number streams seen during tor unit tests

        let (key0, _key1) = State::pair_from_seed(b"abc");
        let mut rng = Rng::new(key0);

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
