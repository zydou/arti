//! "Slugs" used as part of on-disk filenames and other similar purposes
//!
//! Arti uses "slugs" as parts of filenames in many places.
//! Slugs are fixed or variable strings which either
//! designate the kind of a thing, or which of various things this is.
//!
//! Slugs have a restricted character set:
//! Lowercase ASCII alphanumerics and underscore.
//! We may extend this to allow additional characters in the future,
//! but /, +, and . (the slug separators) will never be valid slug characters.
//!
//! Slugs may be empty, but many use cases don't allow empty slugs.
//!
//! Slugs can be concatenated to build file names.
//! When concatenating slugs to make filenames,
//! they should be separated using `/`, `+`, or `.`
//! ([`SLUG_SEPARATOR_CHARS`]).
//! The first slug should not be empty.
//! Slugs should not be concatenated without separators (for security reasons).
//!
//! On Windows only, the following slugs are forbidden,
//! because of [absurd Windows filename behaviours](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file):
//! `con` `prn` `aux` `nul`
//! `com1` `com2` `com3` `com4` `com5` `com6` `com7` `com8` `com9` `com0`
//! `lpt1` `lpt2` `lpt3` `lpt4` `lpt5` `lpt6` `lpt7` `lpt8` `lpt9` `lpt0`.

use std::borrow::Borrow;
use std::ffi::OsStr;
use std::fmt::{self, Display};
use std::mem;
use std::ops::Deref;
use std::path::Path;

use paste::paste;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use os::ForbiddenOnWindows;

/// An owned slug, checked for syntax
///
/// The syntax check can be relied on for safety/soundness.
// We adopt this rule so that eventually we could have AsRef<[std::ascii::Char]>, etc.
#[derive(Debug, Clone, Serialize, Deserialize)] //
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(derive_more::Display)]
#[serde(try_from = "String", into = "String")]
// Box<str> since we don't expect to change the size; that makes it 2 words rather than 3
// (But our public APIs are in terms of String.)
pub struct Slug(Box<str>);

/// A borrwed slug, checked for syntax
///
/// The syntax check can be relied on for safety/soundness.
#[derive(Debug, Serialize)] //
#[derive(Eq, PartialEq, Ord, PartialOrd, Hash)] //
#[derive(derive_more::Display)]
#[serde(transparent)]
#[repr(transparent)] // SAFETY: this attribute is needed for unsafe in new_unchecked
pub struct SlugRef(str);

/// Characters which are good to use to separate slugs
///
/// Guaranteed to never overlap with the valid slug character set.
///
/// We might expand this set, but not ever reduce it.
pub const SLUG_SEPARATOR_CHARS: &str = "/+.";

/// Error for an invalid slug
#[derive(Error, Debug, Clone, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BadSlug {
    /// Slug contains a forbidden character
    BadCharacter(char),
    /// We are on Windows and the slug is one of the forbidden ones
    ///
    /// On Unix, the field is an unhinhabited enum, so this is then an uninhabited variant.
    ForbiddenOnWindows(ForbiddenOnWindows),
}

impl Slug {
    /// Make a Slug out of an owned `String`, if it has the correct syntax
    pub fn new(s: String) -> Result<Slug, BadSlug> {
        Ok(unsafe {
            // SAFETY: we check, and then call new_unchecked
            check_syntax(&s)?;
            Slug::new_unchecked(s)
        })
    }

    /// Make a Slug out of an owned `String`, without checking the syntax
    ///
    /// # Safety
    ///
    /// It's the caller's responsibility to check the syntax of the input string.
    pub unsafe fn new_unchecked(s: String) -> Slug {
        Slug(s.into())
    }
}

impl SlugRef {
    /// Make a SlugRef out of a `str`, if it has the correct syntax
    pub fn new(s: &str) -> Result<&SlugRef, BadSlug> {
        Ok(unsafe {
            // SAFETY: we check, and then call new_unchecked
            check_syntax(s)?;
            SlugRef::new_unchecked(s)
        })
    }

    /// Make a SlugRef out of a `str`, without checking the syntax
    ///
    /// # Safety
    ///
    /// It's the caller's responsibility to check the syntax of the input string.
    pub unsafe fn new_unchecked<'s>(s: &'s str) -> &'s SlugRef {
        unsafe {
            // SAFETY
            // SlugRef is repr(transparent).  So the alignment and memory layout
            // are the same, and the pointer metadata is the same too.
            // The lifetimes is correct by construction.
            //
            // We do this, rather than `struct SlugRef<'r>(&'r str)`,
            // because that way we couldn't impl Deref.
            mem::transmute::<&'s str, &'s SlugRef>(s)
        }
    }

    /// Make an owned `Slug`
    fn to_slug(&self) -> Slug {
        unsafe {
            // SAFETY: self is a SlugRef so our syntax is right
            Slug::new_unchecked(self.0.into())
        }
    }
}

impl TryFrom<String> for Slug {
    type Error = BadSlug;
    fn try_from(s: String) -> Result<Slug, BadSlug> {
        Slug::new(s)
    }
}

impl From<Slug> for String {
    fn from(s: Slug) -> String {
        s.0.into()
    }
}

impl<'s> TryFrom<&'s str> for &'s SlugRef {
    type Error = BadSlug;
    fn try_from(s: &'s str) -> Result<&'s SlugRef, BadSlug> {
        SlugRef::new(s)
    }
}

impl Deref for Slug {
    type Target = SlugRef;
    fn deref(&self) -> &SlugRef {
        unsafe {
            // SAFETY: self is a Slug so our syntax is right
            SlugRef::new_unchecked(&self.0)
        }
    }
}

impl Borrow<SlugRef> for Slug {
    fn borrow(&self) -> &SlugRef {
        self
    }
}
impl Borrow<str> for Slug {
    fn borrow(&self) -> &str {
        self.as_ref()
    }
}

impl ToOwned for SlugRef {
    type Owned = Slug;
    fn to_owned(&self) -> Slug {
        self.to_slug()
    }
}

/// Implement `fn as_...(&self) -> ...` and `AsRef`
macro_rules! impl_as_with_inherent { { $ty:ident } => { paste!{
    impl SlugRef {
        #[doc = concat!("Obtain this slug as a `", stringify!($ty), "`")]
        pub fn [<as_ $ty:snake>](&self) -> &$ty {
            self.as_ref()
        }
    }
    impl_as_ref!($ty);
} } }
/// Implement `AsRef`
macro_rules! impl_as_ref { { $ty:ty } => { paste!{
    impl AsRef<$ty> for SlugRef {
        fn as_ref(&self) -> &$ty {
            self.0.as_ref()
        }
    }
} } }

impl_as_with_inherent!(str);
impl_as_with_inherent!(Path);
impl_as_ref!(OsStr);
impl_as_ref!([u8]);

/// Check the string `s` to see if it would be valid as a slug
///
/// This is a low-level method for special cases.
/// Usually, use [`Slug::new`] etc.
//
// SAFETY
// This function checks the syntax, and is relied on by unsafe code
#[allow(clippy::if_same_then_else)] // clippy objects to the repeated Ok(())
pub fn check_syntax(s: &str) -> Result<(), BadSlug> {
    // check legal character set
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            Ok(())
        } else if c == '_' {
            Ok(())
        } else {
            Err(BadSlug::BadCharacter(c))
        }?;
    }

    os::check_forbidden(s).map_err(BadSlug::ForbiddenOnWindows)?;

    Ok(())
}

impl Display for BadSlug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BadSlug::BadCharacter(c) => {
                let num = u32::from(*c);
                write!(f, "character {c:?} (U+{num:04X}) is not allowed")
            }
            BadSlug::ForbiddenOnWindows(e) => os::fmt_error(e, f),
        }
    }
}

/// Forbidden slug support for Windows
#[cfg(target_family = "windows")]
mod os {
    use super::*;

    /// A slug which is forbidden because we are on Windows (as found in an invalid slug error)
    ///
    /// (On Unix this is an uninhabited enum.)
    //
    // Double reference so that BadSlug has to contain only one word, not two
    pub type ForbiddenOnWindows = &'static &'static str;

    /// The forbidden slugs - windows thinks "C:\\Program Files\lpt0.json" is a printer.
    const FORBIDDEN: &[&str] = &[
        "con", "prn", "aux", "nul", //
        "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "com0", //
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt0",
    ];

    /// Check whether this slug is forbidden here
    pub(super) fn check_forbidden(s: &str) -> Result<(), ForbiddenOnWindows> {
        for bad in FORBIDDEN {
            if s == *bad {
                return Err(bad);
            }
        }
        Ok(())
    }

    /// Display a forbidden slug error
    pub(super) fn fmt_error(s: &ForbiddenOnWindows, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "slug (name) {s:?} is not allowed on Windows")
    }
}
/// Forbidden slug support for non-Windows
#[cfg(not(target_family = "windows"))]
mod os {
    use super::*;

    /// A slug which is forbidden because we are on Windows (as found in an invalid slug error)
    ///
    /// But this is the non-Windows build,
    /// so here this is an unhinhabited enum.
    ///
    /// On Windows this is `&'static &'static str`.
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, derive_more::Display)]
    #[allow(clippy::exhaustive_enums)] // uninhabitedness is indeed an API guarantee on Unix
    pub enum ForbiddenOnWindows {}

    /// Check whether this slug is forbidden here
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn check_forbidden(_s: &str) -> Result<(), ForbiddenOnWindows> {
        Ok(())
    }

    /// Display a forbidden slug error
    pub(super) fn fmt_error(s: &ForbiddenOnWindows, _: &mut fmt::Formatter) -> fmt::Result {
        match *s {}
    }
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

    use super::*;
    use itertools::chain;

    #[test]
    fn bad() {
        for c in chain!(
            SLUG_SEPARATOR_CHARS.chars(), //
            ['\\', ' ', '\n', '\0']
        ) {
            let s = format!("x{c}y");
            let e_ref = SlugRef::new(&s).unwrap_err();
            assert_eq!(e_ref, BadSlug::BadCharacter(c));
            let e_own = Slug::new(s).unwrap_err();
            assert_eq!(e_ref, e_own);
        }
    }

    #[test]
    fn good() {
        let all = chain!(
            b'a'..=b'z', //
            b'0'..=b'9',
            [b'_'],
        )
        .map(char::from);

        let chk = |s: String| {
            let sref = SlugRef::new(&s).unwrap();
            let slug = Slug::new(s.clone()).unwrap();
            assert_eq!(sref.to_string(), s);
            assert_eq!(slug.to_string(), s);
        };

        chk(all.clone().collect());

        for c in all {
            chk(format!("{c}"));
        }

        chk("".into());
    }

    #[test]
    fn badchar_msg() {
        let chk = |s: &str, m: &str| {
            assert_eq!(
                SlugRef::new(s).unwrap_err().to_string(),
                m, //
            );
        };

        chk(".", "character '.' (U+002E) is not allowed");
        chk("\0", "character '\\0' (U+0000) is not allowed");
        chk(
            "\u{12345}",
            "character '\u{12345}' (U+12345) is not allowed",
        );
    }

    #[test]
    fn windows_forbidden() {
        for s in ["con", "prn", "lpt0"] {
            let r = SlugRef::new(s);
            if cfg!(target_family = "windows") {
                assert_eq!(
                    r.unwrap_err().to_string(),
                    format!("slug (name) \"{s}\" is not allowed on Windows"),
                );
            } else {
                assert_eq!(r.unwrap().as_str(), s);
            }
        }
    }
}
