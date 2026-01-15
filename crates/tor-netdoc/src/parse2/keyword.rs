//! Keywords in netdocs

use super::*;

/// A netdoc keyword
///
/// # Safety
///
/// Invariants:
///
///   * length is between 1 and 255 ([`MAX_LEN`]) inclusive
///   * there are no nul bytes
//
// (These are not currently relied on but may become safety invariants in the future.)
#[derive(Debug, Clone, Copy, Eq, PartialEq, derive_more::Display)]
pub struct KeywordRef<'s>(&'s str);

/// Invalid keyword
#[derive(Error, Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvalidKeyword {
    /// Empty keyword
    #[error("Keyword cannot be empty")]
    Empty,
    /// Keyword too long
    #[error("Keyword longer than {MAX_LEN} bytes")]
    TooLong,
    /// Keyword contained nul byte
    #[error("Keyword contains nul byte")]
    ContainsNul,
}

/// Maximum length of a keyword
pub const MAX_LEN: usize = 255;

impl<'s> KeywordRef<'s> {
    /// Make a new `Keyword` from a string in const context
    ///
    /// # Panics
    ///
    /// Panics if the string does not meet the invariants.
    pub const fn new_const(s: &'s str) -> Self {
        // unwrap_or_else isn't const.  expect isn't const.
        match Self::new(s) {
            Ok(y) => y,
            Err(_e) => panic!("new_const failed"), // can't format error in const
        }
    }

    /// Make a new `Keyword` from a string, without checking invariants
    pub const fn new(s: &'s str) -> Result<Self, InvalidKeyword> {
        use InvalidKeyword as IK;
        if s.is_empty() {
            return Err(IK::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(IK::TooLong);
        }
        // s.as_bytes().contains(&b'0'),
        // but
        //   (&[u8]).contains() isn't const
        //   for b in (&[u8]) isn't const
        {
            let mut unchecked = s.as_bytes();
            while let Some((h, t)) = unchecked.split_first() {
                if *h == b'\0' {
                    return Err(IK::ContainsNul);
                }
                unchecked = t;
            }
        }
        Ok(KeywordRef(s))
    }

    /// Make a new `Keyword` from a string, without checking invariants
    ///
    /// ### Safety
    ///
    /// The invariants for [`KeywordRef`] must be satisfied.
    pub unsafe fn new_unchecked(s: &'s str) -> Self {
        KeywordRef(s)
    }

    /// Obtain the `Keyword` as a `str`
    pub fn as_str(&self) -> &str {
        self.0
    }
    /// Obtain the `Keyword`'s length
    #[allow(clippy::len_without_is_empty)] // they can't ever be empty
    pub fn len(&self) -> usize {
        self.as_str().len()
    }
}

impl<'s> AsRef<str> for KeywordRef<'s> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// We could implement `PartialEq<str>` instead but that leads to unnatural code like
//
//   let kw: KeywordRef<'_> = ...;
//   if kw == *"expected" { ...
//
impl PartialEq<&str> for KeywordRef<'_> {
    fn eq(&self, s: &&str) -> bool {
        self.as_str() == *s
    }
}
