//! Constant-time utilities.
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Try to find an item in a slice without leaking where and whether the
/// item was found.
///
/// If there is any item `x` in the `array` for which `matches(x)`
/// is true, this function will return a reference to one such
/// item.  (We don't specify which.)
///
/// Otherwise, this function returns none.
///
/// We evaluate `matches` on every item of the array, and try not to
/// leak by timing which element (if any) matched.
///
/// Note that this doesn't necessarily do a constant-time comparison,
/// and that it is not constant-time for found/not-found case.
pub(crate) fn lookup<T, F>(array: &[T], matches: F) -> Option<&T>
where
    F: Fn(&T) -> Choice,
{
    // ConditionallySelectable isn't implemented for usize, so we need
    // to use u64.
    let mut idx: u64 = 0;
    let mut found: Choice = 0.into();

    for (i, x) in array.iter().enumerate() {
        let equal = matches(x);
        idx.conditional_assign(&(i as u64), equal);
        found.conditional_assign(&equal, equal);
    }

    if found.into() {
        Some(&array[idx as usize])
    } else {
        None
    }
}

/// Convert a boolean into a Choice.
///
/// This isn't necessarily a good idea or constant-time.
pub(crate) fn bool_to_choice(v: bool) -> Choice {
    Choice::from(u8::from(v))
}

/// Return true if two slices are equal.  Performs its operation in constant
/// time, but returns a bool instead of a subtle::Choice.
pub(crate) fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let choice = a.ct_eq(b);
    choice.unwrap_u8() == 1
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #[test]
    fn test_bytes_eq() {
        use super::bytes_eq;
        assert!(bytes_eq(&b"123"[..], &b"1234"[..3]));
        assert!(!bytes_eq(&b"123"[..], &b"1234"[..]));
        assert!(bytes_eq(&b"45"[..], &b"45"[..]));
        assert!(!bytes_eq(&b"hi"[..], &b"45"[..]));
        assert!(bytes_eq(&b""[..], &b""[..]));
    }

    #[test]
    fn test_lookup() {
        use super::lookup;
        use subtle::ConstantTimeEq;
        let items = vec![
            "One".to_string(),
            "word".to_string(),
            "of".to_string(),
            "every".to_string(),
            "length".to_string(),
        ];
        let of_word = lookup(&items[..], |i| i.len().ct_eq(&2));
        let every_word = lookup(&items[..], |i| i.len().ct_eq(&5));
        let no_word = lookup(&items[..], |i| i.len().ct_eq(&99));
        assert_eq!(of_word.unwrap(), "of");
        assert_eq!(every_word.unwrap(), "every");
        assert_eq!(no_word, None);
    }
}
