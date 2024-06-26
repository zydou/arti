//! Constant-time utilities.
use subtle::{Choice, ConstantTimeEq};

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

/// Returns true if all bytes of the input are zero (including if the slice is
/// empty). Executes in constant time for a given length of input.
pub(crate) fn is_zero(x: &[u8]) -> bool {
    // It's tempting to lift the Choice out of the fold loop, s.t. the loop does
    // a simple bit-or of each byte, but then the compiler could theoretically
    // exit the loop early if all bits become one (i.e. 0xff). (Granted this
    // seems unlikely in practice)
    x.iter()
        .map(|b| bool_to_choice(*b == 0))
        .fold(bool_to_choice(true), std::ops::BitAnd::bitand)
        .unwrap_u8()
        == 1
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
    fn test_is_zero() {
        use super::is_zero;
        assert!(is_zero(&[]));
        assert!(is_zero(&[0]));
        assert!(is_zero(&[0, 0]));
        assert!(!is_zero(&[1, 0]));
        assert!(!is_zero(&[0, 1]));
        assert!(!is_zero(&[0, 1, 0]));
    }
}
