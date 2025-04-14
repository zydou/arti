//! Implementation for Counter Galois Onion (CGO) relay cell encryption
//!
//! CGO is an improved approach for encrypting relay cells, with better support
//! for tagging resistance, better forward secrecy, and other improvements.
//! It is described in [a paper][CGO] by Degabriele, Melloni, Münch, and Stam,
//! and specified in [proposal 359].
//!
//! CGO is based on a construction called "UIV+",
//! which provides the "robust pseudorandom permutation" security definition.
//! Notably, _encryption_ with UIV+ is non-malleable (and hence tagging resistant),
//! whereas _decryption_ with UIV+ is malleable (and hence not tagging resistant).
//!
//! [CGO]: https://eprint.iacr.org/2025/583
//! [proposal 359]: https://spec.torproject.org/proposals/359-cgo-redux.html
//
// Implementation note: For naming, I'm trying to use the symbols from the paper
// and the spec (which should be the same) wherever possible.

#![allow(dead_code)] // TODO #1943

// TODO:
//  - Round-trip tests.
//  - KDF code
//  - Relay operations
//    - Forward
//    - Backward
//    - Originating
//  - Client operations
//    - Originating
//    - Receiving

use aes::{Aes128, Aes256};
use cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, StreamCipher as _};
use digest::KeyInit;
use polyval::{universal_hash::UniversalHash, Polyval};
use static_assertions::const_assert;
use tor_cell::{chancell::ChanCmd, chancell::CELL_DATA_LEN};
use tor_error::internal;
use zeroize::Zeroizing;

/// Size of CGO tag, in bytes.
const CGO_TAG_LEN: usize = 16;
/// Size of CGO payload, in bytes.
const CGO_PAYLOAD_LEN: usize = CELL_DATA_LEN - CGO_TAG_LEN;

/// Size of CGO additional data, in bytes.
///
/// This is used to encode whether the cell command is `RELAY`` or `RELAY_EARLY`.
const CGO_AD_LEN: usize = 16;

/// Size of the "H" tweak passed to the UIV+ construction.
const HLEN_UIV: usize = CGO_TAG_LEN + CGO_AD_LEN;

/// Block length.
/// Used by various types.
const BLK_LEN: usize = 16;
/// Block length as a typenum; used to parameterize some types
/// that use ArrayLen.
type BlockLen = typenum::U16;
/// A single block.  Used as input to various functions.
type Block = [u8; BLK_LEN];

/// Helper trait to define the features we need from a block cipher,
/// and make our "where" declarations smaller.
///
/// Not sealed because it is never used outside of this crate.
trait BlkCipher:
    BlockCipher + KeyInit + BlockSizeUser<BlockSize = BlockLen> + BlockEncrypt + BlockDecrypt + Clone
{
    /// Length of the key used by this block cipher.
    const KEY_LEN: usize;
}
impl BlkCipher for Aes128 {
    const KEY_LEN: usize = 16;
}
impl BlkCipher for Aes256 {
    const KEY_LEN: usize = 32;
}

/// Define a tweakable block cipher.
mod et {
    use super::*;

    /// Type of the tweak accepted by the tweakable block cipher.
    ///
    /// (This might seem like a weird way to express `&[u8; TLEN_ET]`,
    /// but it _is_ the way that the UIV construction will provide the tweak.)
    pub(super) type EtTweak<'a> = (&'a [u8; CGO_TAG_LEN], u8, &'a [u8; CGO_PAYLOAD_LEN]);
    /// Total length of EtTweak fields.
    pub(super) const TLEN_ET: usize = CGO_TAG_LEN + 1 + CGO_PAYLOAD_LEN;

    /// Implementation for an LRW2 tweakable block cipher,
    /// with block length of [`BLK_LEN`],
    /// and specialized tweak of type [`EtTweak`].
    ///
    /// Corresponds to ET in the specification.
    #[derive(Clone)]
    pub(super) struct EtCipher<BC: BlkCipher> {
        /// Underlying block cipher
        kb: BC,
        /// Universal hash, initialized with the key KU.
        ku: Polyval,
    }
    impl<BC: BlkCipher> EtCipher<BC> {
        /// Helper: Given a tweak, compute the blinding value we will use
        /// for encrypting or decryption.
        fn compute_tweak_hash(&self, tweak: EtTweak<'_>) -> Zeroizing<Block> {
            // We want to compute the UH(KU, tweak.0 | tweak.1 | tweak.2).
            // This implementation is optimized to avoid excessive data copying.
            let mut ku = self.ku.clone();

            let mut block1 = Zeroizing::new([0_u8; 16]);
            block1[0] = tweak.1;
            block1[1..16].copy_from_slice(&tweak.2[0..15]);
            ku.update(&[(*tweak.0).into(), (*block1).into()]);
            ku.update_padded(&tweak.2[15..]);
            Zeroizing::new(ku.finalize().into())
        }

        /// Encrypt `block` in-place, using `tweak`.
        pub(super) fn encrypt(&self, tweak: EtTweak<'_>, block: &mut Block) {
            // ENC_ET((KB,KU), T, M) = UH(KU,T) ^ ENC_BC(KB, M ^ UH(KU,T))
            let tag: Zeroizing<[u8; 16]> = self.compute_tweak_hash(tweak);
            xor_into(block, &tag);
            self.kb.encrypt_block(block.into());
            xor_into(block, &tag);
        }

        /// Decrypt `block` in-place, using `tweak`.
        pub(super) fn decrypt(&self, tweak: EtTweak<'_>, block: &mut Block) {
            // DEC_ET((KB,KU), T, M) = UH(KU,T) ^ DEC_BC(KB, M ^ UH(KU,T))
            let tag: Zeroizing<[u8; 16]> = self.compute_tweak_hash(tweak);
            xor_into(block, &tag);
            self.kb.decrypt_block(block.into());
            xor_into(block, &tag);
        }
    }
    impl<BC: BlkCipher> CryptInit for EtCipher<BC> {
        fn seed_len() -> usize {
            BC::key_size() + polyval::KEY_SIZE
        }
        fn initialize(seed: &[u8]) -> crate::Result<Self> {
            // TODO PERF: Here and throughout, these initialize functions do more checking than we
            // necessarily need.  We should see if we can simplify them.
            if seed.len() != Self::seed_len() {
                return Err(internal!("Invalid seed length").into());
            }
            let (kb, ku) = seed.split_at(BC::key_size());
            Ok(Self {
                kb: BC::new(kb.into()),
                ku: Polyval::new(ku.into()),
            })
        }
    }
}

/// Define a tweakable pseudorandom stream generator.
mod prf {
    use tor_error::internal;

    use super::*;

    /// The type used as a tweak for this PRF.
    type PrfTweak = [u8; 16];
    /// Length of the PRF's output when used with t=0.
    const PRF_N0_LEN: usize = CGO_PAYLOAD_LEN;
    /// Offset of the PRF's output when used with t=1.
    const PRF_N1_OFFSET: usize = 31 * 16;
    const_assert!(PRF_N1_OFFSET >= PRF_N0_LEN);

    /// Pseudorandom function based on CTR128, Polyval, and an underlying block cipher.
    //
    // Definition: PRF((K, B), T, t) = CTR_{nt}(K, UH(B, T) + (t * C)).
    //   where t is 0 or 1 and C is 31.
    #[derive(Clone)]
    pub(super) struct Prf<BC: BlkCipher> {
        /// The underlying block cipher, initializd with the key "K"
        k: BC,
        /// Thu underlying universal hash, initialized with the key "B"
        b: Polyval,
    }
    impl<BC: BlkCipher> Prf<BC> {
        /// Helper: Return a stream cipher, initialized with an IV corresponding
        /// to `tweak` and an offset corresponding to `t`.
        fn cipher(&self, tweak: &PrfTweak, t: bool) -> ctr::Ctr128BE<BC> {
            use {
                cipher::{InnerIvInit as _, StreamCipherSeek as _},
                ctr::CtrCore,
            };
            let mut b = self.b.clone();
            b.update(&[(*tweak).into()]);
            // TODO PERF: Clone cost.
            let mut cipher: ctr::Ctr128BE<BC> = cipher::StreamCipherCoreWrapper::from_core(
                CtrCore::inner_iv_init(self.k.clone(), &b.finalize()),
            );
            if t {
                debug_assert_eq!(cipher.current_pos::<u32>(), 0_u32);
                cipher.seek(PRF_N1_OFFSET);
            }

            cipher
        }

        /// Apply the cipherstream from this Prf to `out`, with tweak parameter `tweak`
        /// and offset parameter `t=0`.
        pub(super) fn xor_n0_stream(&self, tweak: &PrfTweak, out: &mut [u8; PRF_N0_LEN]) {
            let mut stream = self.cipher(tweak, false);
            stream.apply_keystream(out);
        }

        /// Return a vector containing `n` bytes of this Prf, with tweak
        /// parameter `tweak` and offset parameter `t=1`.
        pub(super) fn get_n1_stream(&self, tweak: &PrfTweak, n: usize) -> Zeroizing<Vec<u8>> {
            let mut output = Zeroizing::new(vec![0_u8; n]);
            self.cipher(tweak, true).apply_keystream(output.as_mut());
            output
        }
    }

    impl<BC: BlkCipher> CryptInit for Prf<BC> {
        fn seed_len() -> usize {
            BC::key_size() + polyval::KEY_SIZE
        }
        fn initialize(seed: &[u8]) -> crate::Result<Self> {
            if seed.len() != Self::seed_len() {
                return Err(internal!("Invalid seed length").into());
            }
            let (k, b) = seed.split_at(BC::key_size());
            Ok(Self {
                k: BC::new(k.into()),
                b: Polyval::new(b.into()),
            })
        }
    }
}

/// Define the UIV+ tweakable wide-block cipher.
///
/// This construction is a "rugged pseudorandom permutation"; see above.
mod uiv {
    use super::*;

    /// Type of tweak used as input to the UIV encryption and decryption algorithms.
    pub(super) type UivTweak<'a> = (&'a [u8; BLK_LEN], u8);

    /// Keys for a UIV cipher.
    #[derive(Clone)]
    pub(super) struct Uiv<BC: BlkCipher> {
        /// Tweakable block cipher key; corresponds to J in the specification.
        j: et::EtCipher<BC>,
        /// PRF keys; corresponds to S in the specification.
        s: prf::Prf<BC>,

        /// Testing only: a copy of our current key material.
        ///
        /// (Used because otherwise, we cannot extract keys from our components,
        /// but we _do_ need to test that our key update code works sensibly.)
        #[cfg(test)]
        pub(super) keys: Zeroizing<Vec<u8>>,
    }

    /// Helper: split a mutable cell body into the left-hand (tag) and
    /// right-hand (body) parts.
    fn split(
        cell_body: &mut [u8; CELL_DATA_LEN],
    ) -> (&mut [u8; CGO_TAG_LEN], &mut [u8; CGO_PAYLOAD_LEN]) {
        //TODO PERF: Make sure that there is no actual checking done here!
        let (left, right) = cell_body.split_at_mut(CGO_TAG_LEN);
        (
            left.try_into().expect("split_at_mut returned wrong size!"),
            right.try_into().expect("split_at_mut returned wrong size!"),
        )
    }

    impl<BC: BlkCipher> Uiv<BC> {
        /// Encrypt `cell_body`, using the provided `tweak`.
        ///
        /// Corresponds to `ENC_UIV.`
        pub(super) fn encrypt(&self, tweak: UivTweak<'_>, cell_body: &mut [u8; CELL_DATA_LEN]) {
            // ENC_UIV((J,S), H, (X_L,X_R)):
            //     Y_L <-- ENC_ET(J, (H || X_R), X_L)
            //     Y_R <-- X_R ^ PRF_n0(S, Y_L, 0)
            //     return (Y_L, Y_R)
            let (left, right) = split(cell_body);
            self.j.encrypt((tweak.0, tweak.1, right), left);
            self.s.xor_n0_stream(left, right);
        }

        /// Decrypt `cell_body`, using the provided `tweak`.
        ///
        /// Corresponds to `DEC_UIV`.
        pub(super) fn decrypt(&self, tweak: UivTweak<'_>, cell_body: &mut [u8; CELL_DATA_LEN]) {
            // DEC_UIV((J,S), H, (Y_L,Y_R)):
            //    X_R <-- Y_R xor PRF_n0(S, Y_L, 0)
            //    X_L <-- DEC_ET(J, (H || X_R), Y_L)
            //    return (X_L, X_R)
            let (left, right) = split(cell_body);
            self.s.xor_n0_stream(left, right);
            self.j.decrypt((tweak.0, tweak.1, right), left);
        }

        /// Modify this Uiv, and the provided nonce, so that its current state
        /// cannot be recovered.
        ///
        /// Corresponds to `UPDATE_UIV`
        pub(super) fn update(&mut self, nonce: &mut [u8; BLK_LEN]) {
            // UPDATE_UIV((J,S), N):
            //     ((J',S'), N') = PRF_{n1}(S, N, 1)
            //     return ((J', S'), N')

            // TODO PERF: We could allocate significantly less here, by using
            // reinitialize functions, and by not actually expanding the key
            // stream.
            let n_bytes = Self::seed_len() + BLK_LEN;
            let seed = self.s.get_n1_stream(nonce, n_bytes);
            #[cfg(test)]
            {
                self.keys = Zeroizing::new(seed[..Self::seed_len()].to_vec());
            }
            let (j, s, n) = Self::split_seed(&seed);
            self.j = et::EtCipher::initialize(j).expect("Invalid slice len");
            self.s = prf::Prf::initialize(s).expect("invalid slice len");
            nonce[..].copy_from_slice(n);
        }

        /// Helper: divide seed into J, S, and N.
        fn split_seed(seed: &[u8]) -> (&[u8], &[u8], &[u8]) {
            let len_j = et::EtCipher::<BC>::seed_len();
            let len_s = prf::Prf::<BC>::seed_len();
            (
                &seed[0..len_j],
                &seed[len_j..len_j + len_s],
                &seed[len_j + len_s..],
            )
        }
    }

    impl<BC: BlkCipher> CryptInit for Uiv<BC> {
        fn seed_len() -> usize {
            super::et::EtCipher::<BC>::seed_len() + super::prf::Prf::<BC>::seed_len()
        }
        fn initialize(seed: &[u8]) -> crate::Result<Self> {
            if seed.len() != Self::seed_len() {
                return Err(internal!("Invalid seed length").into());
            }
            #[cfg(test)]
            let keys = Zeroizing::new(seed.to_vec());
            let (j, s, n) = Self::split_seed(seed);
            debug_assert!(n.is_empty());
            Ok(Self {
                j: et::EtCipher::initialize(j)?,
                s: prf::Prf::initialize(s)?,
                #[cfg(test)]
                keys,
            })
        }
    }
}

/// Xor all bytes from `input` into `output`.
fn xor_into<const N: usize>(output: &mut [u8; N], input: &[u8; N]) {
    for i in 0..N {
        output[i] ^= input[i];
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use hex_literal::hex;
    use rand::Rng as _;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn testvec_xor() {
        let mut b: [u8; 20] = *b"turning and turning ";
        let s = b"in the widening gyre";
        xor_into(&mut b, s);
        assert_eq!(b[..], hex!("1d1b521a010b4757080a014e1d1b154e0e171545"));
    }

    #[test]
    fn testvec_polyval() {
        use polyval::universal_hash::{KeyInit, UniversalHash};
        use polyval::Polyval;

        // Test vectors from RFC8452 worked example in appendix A.
        let h = hex!("25629347589242761d31f826ba4b757b");
        let x_1 = hex!("4f4f95668c83dfb6401762bb2d01a262");
        let x_2 = hex!("d1a24ddd2721d006bbe45f20d3c9f362");

        let mut hash = Polyval::new(&h.into());
        hash.update(&[x_1.into(), x_2.into()]);
        let result: [u8; 16] = hash.finalize().into();
        assert_eq!(result, hex!("f7a3b47b846119fae5b7866cf5e5b77e"));
    }

    // These True/False constants are here to make our test data parse without changes.
    #[allow(non_upper_case_globals)]
    const False: bool = false;
    #[allow(non_upper_case_globals)]
    const True: bool = true;
    include!("../../../testdata/cgo_et.rs");
    include!("../../../testdata/cgo_prf.rs");
    include!("../../../testdata/cgo_uiv.rs");

    /// Decode s as a N-byte hex string, or panic.
    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn testvec_et() {
        for (encrypt, keys, tweak, input, expect_output) in ET_TEST_VECTORS {
            let keys: [u8; 32] = unhex(keys);
            let tweak: [u8; et::TLEN_ET] = unhex(tweak);
            let mut block: [u8; 16] = unhex(input);
            let expect_output: [u8; 16] = unhex(expect_output);
            let et: et::EtCipher<Aes128> = et::EtCipher::initialize(&keys).unwrap();
            let tweak = (
                tweak[0..16].try_into().unwrap(),
                tweak[16],
                &tweak[17..].try_into().unwrap(),
            );
            if *encrypt {
                et.encrypt(tweak, &mut block);
            } else {
                et.decrypt(tweak, &mut block);
            }
            assert_eq!(block, expect_output);
        }
    }

    #[test]
    fn testvec_prf() {
        for (keys, offset, tweak, expect_output) in PRF_TEST_VECTORS {
            let keys: [u8; 32] = unhex(keys);
            assert!([0, 1].contains(offset));
            let tweak: [u8; 16] = unhex(tweak);
            let expect_output = hex::decode(expect_output).unwrap();
            let prf: prf::Prf<Aes128> = prf::Prf::initialize(&keys).unwrap();
            if *offset == 0 {
                assert_eq!(expect_output.len(), CGO_PAYLOAD_LEN);
                let mut data = [0_u8; CGO_PAYLOAD_LEN];
                prf.xor_n0_stream(&tweak, &mut data);
                assert_eq!(expect_output[..], data[..]);
            } else {
                let data = prf.get_n1_stream(&tweak, expect_output.len());
                assert_eq!(expect_output[..], data[..]);
            }
        }
    }

    #[test]
    fn testvec_uiv() {
        for (encrypt, keys, tweak, left, right, (expect_left, expect_right)) in UIV_TEST_VECTORS {
            let keys: [u8; 64] = unhex(keys);
            let tweak: [u8; 17] = unhex(tweak);
            let mut cell: [u8; 509] = unhex(&format!("{left}{right}"));
            let expected: [u8; 509] = unhex(&format!("{expect_left}{expect_right}"));

            let uiv: uiv::Uiv<Aes128> = uiv::Uiv::initialize(&keys).unwrap();
            let htweak = (tweak[0..16].try_into().unwrap(), tweak[16]);
            if *encrypt {
                uiv.encrypt(htweak, &mut cell);
            } else {
                uiv.decrypt(htweak, &mut cell);
            }
            assert_eq!(cell, expected);
        }
    }

    #[test]
    fn testvec_uiv_update() {
        let mut rng = testing_rng();

        for (keys, nonce, (expect_keys, expect_nonce)) in UIV_UPDATE_TEST_VECTORS {
            let keys: [u8; 64] = unhex(keys);
            let mut nonce: [u8; 16] = unhex(nonce);
            let mut uiv: uiv::Uiv<Aes128> = uiv::Uiv::initialize(&keys).unwrap();
            let expect_keys: [u8; 64] = unhex(expect_keys);
            let expect_nonce: [u8; 16] = unhex(expect_nonce);
            uiv.update(&mut nonce);
            assert_eq!(&nonce, &expect_nonce);
            assert_eq!(&uiv.keys[..], &expect_keys[..]);

            // Make sure that we can get the same results when we initialize a new UIV with the keys
            // allegedly used to reinitialize this one.
            let uiv2: uiv::Uiv<Aes128> = uiv::Uiv::initialize(&uiv.keys[..]).unwrap();

            let tweak: [u8; 16] = rng.random();
            let cmd = rng.random();
            let mut msg1: [u8; CELL_DATA_LEN] = rng.random();
            let mut msg2 = msg1.clone();

            uiv.encrypt((&tweak, cmd), &mut msg1);
            uiv2.encrypt((&tweak, cmd), &mut msg2);
        }
    }
}
