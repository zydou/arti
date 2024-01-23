//! A simple order-preserving encryption function.
//!
//! This function is used to generate revision counters for onion service
//! descriptors.  It is not suitable for other purposes.
//!
//! The scheme here is the one described in the specifications
//! as "Encrypted Time In Period".
//!
//! It is loosely based on the scheme first described in
//! G. Bebek. "Anti-tamper database research: Inference control
//! techniques."" Technical Report EECS 433 Final Report, Case
//! Western Reserve University, November 2002.

// NOTE:
//
// We use the same algorithm here as in C tor, not because it is a great
// algorithm, but because there has been a community of onion service operators
// who try to achieve load balancing by running multiple onion services with the
// same keys, and letting them "race" to publish at the HsDirs.  This only
// works if all the onion service instances produce the same revision counters.

use cipher::{KeyIvInit as _, StreamCipher as _};
use digest::Digest as _;

use tor_llcrypto::{cipher::aes::Aes256Ctr, d::Sha3_256};
use zeroize::Zeroizing;

/// Key for a simple order-preserving encryption on the offset from the start of an SRV protocol
/// run.
///
/// The algorithm here is chosen to be the same as used in the C tor
/// implementation.
#[derive(Clone, Debug)]
pub struct AesOpeKey {
    /// The key for our counter-mode cipher.
    key: Zeroizing<[u8; 32]>,
}

/// A prefix used when deriving an AES key for this purpose.
const DERIVATION_PREFIX: &[u8] = b"rev-counter-generation";

impl AesOpeKey {
    /// Construct a new [`AesOpeKey`] from a given secret.
    ///
    /// The secret should be unpredictable by an adversary.
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut h = Sha3_256::new();
        h.update(DERIVATION_PREFIX);
        h.update(secret);
        let key = Zeroizing::new(h.finalize().into());
        AesOpeKey { key }
    }

    /// Encrypt `offset` to a 64-bit number.
    ///
    /// (We do not implement a decryption operation.)
    ///
    /// # Limitations
    ///
    /// Like all order-preserving encryption, this scheme leaks information by
    /// its nature.  It also leaks more information than necessary: (the
    /// adversary can get a rough estimate for our input by dividing the output
    /// by 0x8001). The only security property that this algorithm tries to
    /// provide is that it prevents an adversary from inferring our clock skew.
    ///
    /// This algorithm is also not very efficient in its implementation.
    /// We expect that the result will become unacceptable if the time period is
    /// ever larger than a few days.
    pub fn encrypt(&self, offset: u32) -> u64 {
        // We add "1" here per the spec, since the encryption of 0 is 0.
        self.encrypt_inner(offset.saturating_add(1))
    }

    /// Implementation for the order-preserving encryption algorithm:
    ///
    /// For security, requires that `n` is at least 1.
    fn encrypt_inner(&self, n: u32) -> u64 {
        let iv = [0; 16].into();
        let mut ctr = Aes256Ctr::new((&*self.key).into(), &iv);

        /// Number of u16s to create at once.
        const BUF_LEN: usize = 8 * 1024;
        /// Number of bytes in a u16
        const STEP: usize = 2;

        // We start our accumulator at `n` because we want every increase in the
        // input to increase our output by at least 1, but it is otherwise
        // possible for one of our randomly generated u16s to be 0x0000.
        let mut result = u64::from(n);
        let mut n = n as usize;
        let mut buf = [0_u8; BUF_LEN * STEP];
        while n >= BUF_LEN {
            buf.fill(0);
            ctr.apply_keystream(&mut buf[..]);
            result += add_slice_as_le_u16(&buf[..]);
            n -= BUF_LEN;
        }
        if n > 0 {
            buf.fill(0);
            ctr.apply_keystream(&mut buf[..n * STEP]);
            result += add_slice_as_le_u16(&buf[..n * STEP]);
        }
        result
    }
}

/// Treating `slice` as a sequence of little-endian 2-byte words,
/// add them into a u64.
///
/// # Panics
///
/// Panics if slice is not even in size.
fn add_slice_as_le_u16(slice: &[u8]) -> u64 {
    assert_eq!(slice.len() % 2, 0);
    let s = slice
        .chunks_exact(2)
        .map(|bytepair| {
            let a: [u8; 2] = bytepair.try_into().expect("chunk was not of size 2!");
            u64::from(u16::from_le_bytes(a))
        })
        .sum();
    s
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn add_slice() {
        assert_eq!(6, add_slice_as_le_u16(&[1, 0, 2, 0, 3, 0]));
        assert_eq!(0x600, add_slice_as_le_u16(&[0, 1, 0, 2, 0, 3]));
        assert_eq!(
            419477,
            add_slice_as_le_u16(b"This is a string of moderate length!")
        );
    }

    #[test]
    fn test_vec() {
        let key = hex!("19e05891d55232c08c2cad91d612fdb9cbd6691949a0742434a76c80bc6992fe");
        let key = AesOpeKey { key: key.into() };

        // Test vectors taken from C tor.
        for (inp, expected) in [
            (82283, 2695743564_u64),
            (72661, 2381548866_u64),
            (72941, 2390408421_u64),
            (123122, 4036781069_u64),
            (12154, 402067100_u64),
            (121574, 3986197593_u64),
            (11391, 376696838_u64),
            (65845, 2161801517_u64),
            (86301, 2828270975_u64),
            (61284, 2013616892_u64),
            (70505, 2313368870_u64),
            (30438, 1001394664_u64),
            (60150, 1977329668_u64),
            (114800, 3764946628_u64),
            (109403, 3585352477_u64),
            (21893, 721388468_u64),
            (123569, 4051780471_u64),
            (95617, 3134921876_u64),
            (48561, 1597596985_u64),
            (53334, 1753691710_u64),
            (92746, 3040874493_u64),
            (7110, 234966492_u64),
            (9612, 318326551_u64),
            (106958, 3506124249_u64),
            (46889, 1542219146_u64),
            (87790, 2877361609_u64),
            (68878, 2260369112_u64),
            (47917, 1576681737_u64),
            (121128, 3971553290_u64),
            (108602, 3559176081_u64),
            (28217, 929692460_u64),
            (69498, 2280554161_u64),
            (63870, 2098322675_u64),
            (57542, 1891698992_u64),
            (122148, 4004515805_u64),
            (46254, 1521227949_u64),
            (42850, 1408996941_u64),
            (92661, 3037901517_u64),
            (57720, 1897369989_u64),
        ] {
            assert_eq!(key.encrypt_inner(inp), expected);
        }
    }
}
