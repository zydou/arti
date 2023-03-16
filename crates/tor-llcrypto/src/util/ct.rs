//! Define helpers for working with types in constant time.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// A byte array of length N for which comparisons are performed in constant
/// time.
///
/// # Limitations
///
/// It is possible to avoid constant time comparisons here, just by using the
/// `as_ref()` and `as_mut()` methods.  They should therefore be approached with
/// some caution.
///
/// (The decision to avoid implementing `Deref`/`DerefMut` is deliberate.)
#[allow(renamed_and_removed_lints)] // TODO Remove @ MSRV 1.68
#[allow(clippy::derive_hash_xor_eq)] // TODO Rename @ MSRV 1.68
#[derive(Clone, Copy, Debug, Hash, Zeroize, derive_more::Deref)]
pub struct CtByteArray<const N: usize>([u8; N]);

impl<const N: usize> ConstantTimeEq for CtByteArray<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for CtByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}
impl<const N: usize> Eq for CtByteArray<N> {}

impl<const N: usize> From<[u8; N]> for CtByteArray<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<CtByteArray<N>> for [u8; N] {
    fn from(value: CtByteArray<N>) -> Self {
        value.0
    }
}

impl<const N: usize> Ord for CtByteArray<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // At every point, this value will be set to:
        //       0 if a[i]==b[i] for all i considered so far.
        //       a[i] - b[i] for the lowest i that has a nonzero a[i] - b[i].
        let mut first_nonzero_difference = 0_i16;

        for (a, b) in self.0.iter().zip(other.0.iter()) {
            let difference = i16::from(*a) - i16::from(*b);

            // If it's already set to a nonzero value, this conditional
            // assignment does nothing. Otherwise, it sets it to `difference`.
            //
            // The use of conditional_assign and ct_eq ensures that the compiler
            // won't short-circuit our logic here and end the loop (or stop
            // computing differences) on the first nonzero difference.
            first_nonzero_difference
                .conditional_assign(&difference, first_nonzero_difference.ct_eq(&0));
        }

        // This comparison with zero is not itself constant-time, but that's
        // okay: we only want our Ord function not to leak the array values.
        first_nonzero_difference.cmp(&0)
    }
}

impl<const N: usize> PartialOrd for CtByteArray<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const N: usize> AsRef<[u8; N]> for CtByteArray<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8; N]> for CtByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;
    use tor_basic_utils::test_rng;

    #[allow(clippy::nonminimal_bool)]
    #[test]
    fn test_comparisons() {
        let num = 200;
        let mut rng = test_rng::testing_rng();

        let mut array: Vec<CtByteArray<32>> =
            (0..num).map(|_| rng.gen::<[u8; 32]>().into()).collect();
        array.sort();

        for i in 0..num {
            assert_eq!(array[i], array[i]);
            assert!(!(array[i] < array[i]));
            assert!(!(array[i] > array[i]));

            for j in (i + 1)..num {
                // Note that this test will behave incorrectly if the rng
                // generates the same 256 value twice, but that's ridiculously
                // implausible.
                assert!(array[i] < array[j]);
                assert_ne!(array[i], array[j]);
                assert!(array[j] > array[i]);
                assert_eq!(
                    array[i].cmp(&array[j]),
                    array[j].as_ref().cmp(array[i].as_ref()).reverse()
                );
            }
        }
    }
}
