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

use blake2::Blake2bVarCore;
use blake2::digest::block_buffer::LazyBuffer;
use blake2::digest::core_api::{BlockSizeUser, UpdateCore, VariableOutputCore};
use std::fmt::{self, Debug};

/// Internal state of one SipHash instance
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SipState {
    /// State variable V0 as defined in the SipHash paper
    pub(crate) v0: u64,
    /// State variable V1 as defined in the SipHash paper
    pub(crate) v1: u64,
    /// State variable V2 as defined in the SipHash paper
    pub(crate) v2: u64,
    /// State variable V3 as defined in the SipHash paper
    pub(crate) v3: u64,
}

impl Debug for SipState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SipState[ {:#018x}, {:#018x}, {:#018x}, {:#018x} ]",
            self.v0, self.v1, self.v2, self.v3
        )
    }
}

impl From<SipState> for [u64; 4] {
    #[inline(always)]
    fn from(s: SipState) -> Self {
        [s.v0, s.v1, s.v2, s.v3]
    }
}

impl From<[u64; 4]> for SipState {
    #[inline(always)]
    fn from(a: [u64; 4]) -> Self {
        Self::new(a[0], a[1], a[2], a[3])
    }
}

impl SipState {
    /// Size of the internal SipHash state
    const SIZE: usize = 32;

    /// Construct a new SipHash state.
    ///
    /// This takes the parameters `v0..v3` as defined in the SipHash paper.
    #[inline(always)]
    pub fn new(v0: u64, v1: u64, v2: u64, v3: u64) -> Self {
        Self { v0, v1, v2, v3 }
    }

    /// Construct a new SipHash state directly from bytes.
    ///
    /// This is not suitable for use with arbitrary user input, such
    /// as all zeroes. HashX always generates these initialization vectors
    /// using another pseudorandom function (Blake2b).
    #[inline(always)]
    pub fn new_from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        Self::new(
            u64::from_le_bytes(bytes[0..8].try_into().expect("slice length matches")),
            u64::from_le_bytes(bytes[8..16].try_into().expect("slice length matches")),
            u64::from_le_bytes(bytes[16..24].try_into().expect("slice length matches")),
            u64::from_le_bytes(bytes[24..32].try_into().expect("slice length matches")),
        )
    }

    /// Construct a pair of SipHash instances from a seed.
    ///
    /// The seed may be an arbitrary length. Takes the Blake2b hash of the seed
    /// using the correct settings for HashX, splitting the digest into two
    /// [`Self::new_from_bytes()`] calls.
    pub fn pair_from_seed(seed: &[u8]) -> (SipState, SipState) {
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

    /// One `SipRound` as defined in the SipHash paper
    ///
    /// Modifies the `SipState` in-place.
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
pub(crate) fn siphash13_ctr(key: SipState, input: u64) -> u64 {
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
pub(crate) fn siphash24_ctr(key: SipState, input: u64) -> [u64; 8] {
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
    use super::{SipState, siphash24_ctr};

    #[test]
    fn sip_round_vectors() {
        // Test values from Appendix A of the SipHash paper

        // Includes constants, first message block, and keys
        let mut s = SipState::new(
            0x7469686173716475,
            0x6b617f6d656e6665,
            0x6b7f62616d677361,
            0x7c6d6c6a717c6d7b,
        );

        // Rounds for first example message block
        s.sip_round();
        s.sip_round();

        // Sample output after two rounds
        let result: [u64; 4] = s.into();
        assert_eq!(
            result,
            [
                0x4d07749cdd0858e0,
                0x0d52f6f62a4f59a4,
                0x634cb3577b01fd3d,
                0xa5224d6f55c7d9c8,
            ]
        );
    }

    #[test]
    fn seed_hash_vectors() {
        // Check against seed hash values seen during tor unit tests

        let (key0, key1) = SipState::pair_from_seed(b"");
        assert_eq!(
            key0,
            [
                0xcaca7747b3c5be92,
                0x296abd268b5f21de,
                0x9e4c4d2f95add72a,
                0x00ac7f27331ec1c7
            ]
            .into()
        );
        assert_eq!(
            key1,
            SipState::new(
                0xc32d197f86f1c419,
                0xbbe47abaf4e28dfe,
                0xc174b9d5786f28d4,
                0xa2bd4197b22a035a,
            )
        );

        let (key0, key1) = SipState::pair_from_seed(b"abc");
        assert_eq!(
            key0,
            SipState {
                v0: 0xc538fa793ed99a50,
                v1: 0xd2fd3e8871310ea1,
                v2: 0xd2be7d8aff1f823a,
                v3: 0x557b84887cfe6c0e,
            }
        );
        assert_eq!(
            key1,
            SipState {
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

        let (_key0, key1) = SipState::pair_from_seed(b"abc");
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
}
