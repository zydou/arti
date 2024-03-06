//! Code for deterministic and/or reproducible use of PRNGs in tests.
//!
//! Often in testing we want to test a random scenario, but we want to be sure
//! of our ability to reproduce the scenario if the test fails.
//!
//! To achieve this,  just have your test use [`testing_rng()`] in place of
//! [`rand::thread_rng()`].  Then the test will (by default) choose a new random
//! seed for every run, and print that seed to standard output.  If the test
//! fails, the seed will be displayed as part of the failure message, and you
//! will be able to use it to recreate the same PRNG seed as the one that caused
//! the failure.
//!
//! If you're running your tests in a situation where deterministic behavior is
//! key, you can also enable this via the environment.
//!
//! The run-time behavior is controlled using the `ARTI_TEST_PRNG` variable; you
//! can set it to any of the following:
//!   * `random` for a randomly seeded PRNG. (This is the default).
//!   * `deterministic` for an arbitrary seed that is the same on every run of
//!     the program. (You can use this in cases where even a tiny chance of
//!     stochastic behavior in your tests is unacceptable.)
//!   * A hexadecimal string, to specify a given seed to re-use from a previous
//!     test run.
//!
//! # WARNING
//!
//! This is for testing only!  Never ever use it in non-testing code.  Doing so
//! may compromise your security.
//!
//! You may wish to use clippy's `disallowed-methods` lint to ensure you aren't
//! using it outside of your tests.
//!
//! # Examples
//!
//! Here's a simple example of a test that verifies that integer sorting works
//! correctly by shuffling a short sequence and then re-sorting it.
//!
//! ```
//! use tor_basic_utils::test_rng::testing_rng;
//! use rand::{seq::SliceRandom};
//! let mut rng = testing_rng();
//!
//! let mut v = vec![-10, -3, 0, 1, 2, 3];
//! v.shuffle(&mut rng);
//! v.sort();
//! assert_eq!(&v, &[-10, -3, 0, 1, 2, 3])
//! ```
//!
//! Here's a trickier example of how you might write a test to override the
//! default behavior.  (For example, you might want to do this if the test is
//! unreliable and you don't have time to hunt down the issues.)
//!
//! ```
//! use tor_basic_utils::test_rng::Config;
//! let mut rng = Config::from_env()
//!     .unwrap_or(Config::Deterministic)
//!     .into_rng();
//! ```

// We allow printing to stdout and stderr in this module, since it's intended to
// be used by tests, where this is the preferred means of communication with the user.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use rand::{RngCore, SeedableRng};
// We'll use the same PRNG as the (current) standard.  We specify it here rather
// than using StdRng, since we want determinism in the future.
pub use rand_chacha::ChaCha12Rng as TestingRng;

/// The seed type for the RNG we're returning.
type Seed = <TestingRng as SeedableRng>::Seed;

/// Default seed for deterministic RNG usage.
///
/// This is the seed we use when we're told to use a deterministic RNG with no
/// specific seed.
const DEFAULT_SEED: Seed = *b"4   // chosen by fair dice roll.";

/// The environment variable that we inspect.
const PRNG_VAR: &str = "ARTI_TEST_PRNG";

/// Return a new, possibly deterministic, RNG for use in tests.
///
/// This function is **only** for testing: using it elsewhere may make your code
/// insecure!
///
/// The type of this RNG will depend on the value of `ARTI_TEST_PRNG`:
///   * If ARTI_TEST_PRNG is `random` or unset, we'll use a real seeded PRNG.
///   * If ARTI_TEST_PRNG is `deterministic`, we'll use a standard canned PRNG
///     seed.
///   * If ARTI_TEST_PRNG is a hexadecimal string, we'll use that as the PRNG
///     seed.
///
/// We'll print the value of this RNG seed to stdout, so that if the test fails,
/// you'll know what seed to use in reproducing it.
///
/// # Panics
///
/// Panics if the environment variable is set to an invalid value.
///
/// (If your code must not panic, then it is not test code, and you should not
/// be using this function.)
pub fn testing_rng() -> TestingRng {
    // Somewhat controversially, we prefer a Random prng by default.  Our
    // rationale is that, if this weren't the default, nobody would ever set it,
    // and we'd never find out about busted tests or code.
    Config::from_env().unwrap_or(Config::Random).into_rng()
}

/// Type describing a testing_rng configuration.
///
/// This is a separate type so that you can pick different defaults, or inspect
/// the configuration before using it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum Config {
    /// Use a PRNG with a randomly chosen seed.
    Random,
    /// Use a PRNG with a (default) pre-selected seed.
    Deterministic,
    /// Use a specific seed value for the PRNG.
    Seeded(Seed),
}

impl Config {
    /// Return the testing PRNG from the environment, if one is configured.
    ///
    /// # Panics
    ///
    /// Panics if the environment variable is set to an invalid value.
    ///
    /// (If your code must not panic, then it is not test code, and you should not
    /// be using this function.)
    pub fn from_env() -> Option<Self> {
        match Self::from_env_result(std::env::var(PRNG_VAR)) {
            Ok(c) => c,
            Err(e) => {
                panic!(
                    "Bad value for {}: {}\n\
                    We recognize `random`, `deterministic`, or a hexadecimal seed.",
                    PRNG_VAR, e
                );
            }
        }
    }

    /// Read the configuration from the result of `std::env::var()`.
    ///
    /// Return None if there was no option.
    fn from_env_result(var: Result<String, std::env::VarError>) -> Result<Option<Self>, Error> {
        match var {
            Ok(s) if s.is_empty() => Ok(None),
            Ok(s) => Ok(Some(Config::from_str(&s)?)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(Error::InvalidUnicode),
        }
    }

    /// Read the configuration from a provided string.
    ///
    /// The string format is as described in [`testing_rng`].
    ///
    /// Return None if this string can't be interpreted as a [`Config`]
    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(if s == "random" {
            Self::Random
        } else if s == "deterministic" {
            Self::Deterministic
        } else if let Some(seed) = decode_seed_bytes(s) {
            Self::Seeded(seed)
        } else {
            return Err(Error::UnrecognizedValue(s.to_string()));
        })
    }

    /// Consume this `Config` and return a `Seed`.
    fn into_seed(self) -> Seed {
        match self {
            Config::Deterministic => DEFAULT_SEED,
            Config::Seeded(seed) => seed,
            Config::Random => {
                let mut seed = Seed::default();
                rand::thread_rng().fill_bytes(&mut seed[..]);
                seed
            }
        }
    }

    /// Consume this `Config` and return a `TestingRng`.
    pub fn into_rng(self) -> TestingRng {
        let seed = self.into_seed();
        println!("  Using RNG seed {}={}", PRNG_VAR, format_seed_bytes(&seed));
        TestingRng::from_seed(seed)
    }
}

/// Format `seed` in the format expected by [`decode_seed_bytes`].
///
/// This is a separate function to make it clearer what the tests are testing.
fn format_seed_bytes(seed: &Seed) -> String {
    hex::encode(seed)
}

/// Try to see whether a literal seed can be decoded from a given string.  If
/// so, return it.
///
/// We currently use a hex encoding, truncating or zero-extending the provided
/// seed as needed.
fn decode_seed_bytes(s: &str) -> Option<Seed> {
    if s.is_empty() {
        // Do not accept the empty string.
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mut seed = Seed::default();
    let n = std::cmp::min(seed.len(), bytes.len());
    seed[..n].copy_from_slice(&bytes[..n]);
    Some(seed)
}

/// An error from trying to decode a [`Config`] from a string.
#[derive(Clone, Debug, thiserror::Error, Eq, PartialEq)]
enum Error {
    /// We got a value that wasn't unicode.
    #[error("Value was not UTF-8")]
    InvalidUnicode,
    /// We got a value that we otherwise couldn't decode.
    #[error("Could not interpret {0:?} as a PRNG seed.")]
    UnrecognizedValue(String),
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use std::env::VarError;

    use super::*;

    #[test]
    fn from_str() {
        assert_eq!(Ok(Config::Deterministic), Config::from_str("deterministic"));
        assert_eq!(Ok(Config::Random), Config::from_str("random"));
        assert_eq!(Ok(Config::Seeded([0x00; 32])), Config::from_str("00"));
        {
            let s = "aaaaaaaa";
            let seed = [
                0xaa, 0xaa, 0xaa, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ];
            assert_eq!(Ok(Config::Seeded(seed)), Config::from_str(s));
        }
        {
            let seed = *b"hello world. this is a longer st";
            let mut s = hex::encode(seed);
            assert_eq!(Ok(Config::Seeded(seed)), Config::from_str(&s));
            // we can make it longer, and it just gets truncated.
            s.push_str("aabbccddeeff");
            assert_eq!(Ok(Config::Seeded(seed)), Config::from_str(&s));
        }

        assert_eq!(
            Err(Error::UnrecognizedValue("".to_string())),
            Config::from_str("")
        );

        assert_eq!(
            Err(Error::UnrecognizedValue("return 4".to_string())),
            Config::from_str("return 4")
        );
    }

    #[test]
    fn from_env() {
        assert_eq!(
            Ok(Some(Config::Deterministic)),
            Config::from_env_result(Ok("deterministic".to_string()))
        );
        assert_eq!(
            Ok(Some(Config::Random)),
            Config::from_env_result(Ok("random".to_string()))
        );
        assert_eq!(
            Ok(Some(Config::Seeded([0xcd; 32]))),
            Config::from_env_result(Ok("cd".repeat(32)))
        );
        assert_eq!(Ok(None), Config::from_env_result(Ok("".to_string())));
        assert_eq!(Ok(None), Config::from_env_result(Err(VarError::NotPresent)));
        assert_eq!(
            Err(Error::InvalidUnicode),
            Config::from_env_result(Err(VarError::NotUnicode("3".into())))
        );
        assert_eq!(
            Err(Error::UnrecognizedValue("123".to_string())),
            Config::from_env_result(Ok("123".to_string()))
        );
    }

    #[test]
    fn make_seed() {
        assert_eq!(Config::Deterministic.into_seed(), DEFAULT_SEED);
        assert_eq!(Config::Seeded([0x24; 32]).into_seed(), [0x24; 32]);

        let s1 = Config::Random.into_seed();
        let s2 = Config::Random.into_seed();
        assert_ne!(s1, s2);
    }

    #[test]
    fn code_decode() {
        assert_eq!(
            decode_seed_bytes(&format_seed_bytes(&DEFAULT_SEED)).unwrap(),
            DEFAULT_SEED
        );
    }

    #[test]
    fn determinism() {
        let mut d_rng = Config::Deterministic.into_rng();
        let values: Vec<_> = std::iter::repeat_with(|| d_rng.next_u32())
            .take(8)
            .collect();

        // This should be the same every time.
        let deterministic_values = vec![
            4222362647, 2976626662, 1407369338, 1087750672, 196711223, 996083910, 836259566,
            2589890951,
        ];
        assert_eq!(values, deterministic_values);

        // But if we use a random RNG, we'll get different values
        // (with P=1-2^-256)
        let mut r_rng = Config::Random.into_rng();
        let values: Vec<_> = std::iter::repeat_with(|| r_rng.next_u32())
            .take(8)
            .collect();
        assert_ne!(values, deterministic_values);
    }
}
