//! Utility to return a random hostname.

use crate::RngExt as _;
use rand::{Rng, seq::IndexedRandom as _};

/// The prefixes we put at the front of every random hostname, with terminating `.`.
const PREFIXES: &[&str] = &["www."];

/// The suffixes that we use when picking a random hostname, with preceding `.`.
const SUFFIXES: &[&str] = &[".com", ".net", ".org"];

/// The characters that we use for the middle part of a hostname.
const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz-0123456789";

/// Lowest permissible hostname length.
const MIN_LEN: usize = 16;
/// Highest permissible hostname length.
const MAX_LEN: usize = 32;

/// Return a somewhat random-looking hostname.
///
/// The specific format of the hostname is not guaranteed.
pub fn random_hostname<R: Rng>(rng: &mut R) -> String {
    // TODO: This is, roughly, what C tor does.
    // But that doesn't mean it's remotely clever.
    let prefix = PREFIXES.choose(rng).expect("TLDS was empty!?");
    let suffix = SUFFIXES.choose(rng).expect("TLDS was empty!?");

    let length: usize = rng
        .gen_range_checked(MIN_LEN..=MAX_LEN)
        .expect("Somehow MIN..=MAX wasn't a valid range?");
    let center_length = length
        .checked_sub(prefix.len() + suffix.len())
        .expect("prefix and suffix exceeded MIN_LEN");

    let mut output = String::from(*prefix);
    for _ in 0..center_length {
        output.push(*CHARSET.choose(rng).expect("CHARSET was empty!?") as char);
    }
    output.push_str(suffix);

    assert_eq!(length, output.len());
    output
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::test_rng::testing_rng;

    #[test]
    fn generate_names() {
        let mut rng = testing_rng();

        for _ in 0..100 {
            let name = random_hostname(&mut rng);
            assert!(PREFIXES.iter().any(|tld| name.starts_with(tld)));
            assert!(SUFFIXES.iter().any(|tld| name.ends_with(tld)));
            assert!(name.len() >= MIN_LEN);
            assert!(name.len() <= MAX_LEN);
            for ch in name.chars() {
                assert!(matches!(ch, '.' | '-' | '0'..='9' | 'a'..='z'));
            }
        }
    }
}
