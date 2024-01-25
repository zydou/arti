//! [`ArtiPath`] and [`ArtiPathComponent`]

use std::str::FromStr;

use derive_adhoc::{define_derive_adhoc, Adhoc};
use derive_more::{Deref, Display, Into};
use serde::{Deserialize, Serialize};
use tor_persist::slug::{self, Slug, BadSlug};

use crate::{ArtiPathSyntaxError, KeyPathRange};

define_derive_adhoc! {
    /// Implement `new()`, `TryFrom<String>` in terms of `validate_str`, and `as_ref<str>`
    //
    // TODO maybe this is generally useful?  Or maybe we should find a crate?
    ValidatedString for struct, expect items =

    impl $ttype {
        #[doc = concat!("Create a new [`", stringify!($tname), "`].")]
        ///
        /// This function returns an error if `inner` is not in the right syntax.
        pub fn new(inner: String) -> Result<Self, ArtiPathSyntaxError> {
            Self::validate_str(&inner)?;
            Ok(Self(inner))
        }
    }

    impl TryFrom<String> for $ttype {
        type Error = ArtiPathSyntaxError;

        fn try_from(s: String) -> Result<Self, ArtiPathSyntaxError> {
            Self::new(s)
        }
    }

    impl FromStr for $ttype {
        type Err = ArtiPathSyntaxError;

        fn from_str(s: &str) -> Result<Self, ArtiPathSyntaxError> {
            Self::validate_str(s)?;
            Ok(Self(s.to_owned()))
        }
    }

    impl AsRef<str> for $ttype {
        fn as_ref(&self) -> &str {
            &self.0.as_str()
        }
    }
}

/// A unique identifier for a particular instance of a key.
///
/// In an [`ArtiNativeKeystore`](crate::ArtiNativeKeystore), this also represents the path of the
/// key relative to the root of the keystore, minus the file extension.
///
/// An `ArtiPath` is a nonempty sequence of [`ArtiPathComponent`]s, separated by `/`.  Path
/// components may contain UTF-8 alphanumerics, and (except as the first or last character) `-`,
/// `_`, or  `.`.
/// Consequently, leading or trailing or duplicated / are forbidden.
///
/// The last component of the path may optionally contain the encoded (string) representation
/// of one or more
/// [`KeySpecifierComponent`](crate::KeySpecifierComponent)
/// s representing the denotators of the key.
/// They are separated from the rest of the component, and from each other,
/// by [`DENOTATOR_SEP`] characters.
/// Denotators are encoded using their
/// [`KeySpecifierComponent::to_component`](crate::KeySpecifierComponent::to_component)
/// implementation.
/// The denotators **must** come after all the other fields.
/// Denotator strings are validated in the same way as [`ArtiPathComponent`]s.
///
/// For example, the last component of the path `"foo/bar/bax+denotator_example+1"`
/// is `"bax+denotator_example+1"`.
/// Its denotators are `"denotator_example"` and `"1"` (encoded as strings).
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
///
// But this should be done _after_ we rewrite define_key_specifier using d-a
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Deref, Into, Display)] //
#[derive(Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[derive(Adhoc)]
#[derive_adhoc(ValidatedString)]
pub struct ArtiPath(String);

/// A separator for `ArtiPath`s.
pub(crate) const PATH_SEP: char = '/';

/// A separator for that marks the beginning of the keys denotators
/// within an [`ArtiPath`].
///
/// This separator can only appear within the last component of an [`ArtiPath`],
/// and the substring that follows it is assumed to be the string representation
/// of the denotators of the path.
pub const DENOTATOR_SEP: char = '+';

impl ArtiPath {
    /// Validate the underlying representation of an `ArtiPath`
    fn validate_str(inner: &str) -> Result<(), ArtiPathSyntaxError> {
        // Validate the denotators, if there are any.
        let path = if let Some((main_part, denotators)) = inner.split_once(DENOTATOR_SEP) {
            for d in denotators.split(DENOTATOR_SEP) {
                if d.is_empty() {
                    return Err(BadSlug::EmptySlugNotAllowed.into());
                }
                let () = ArtiPathComponent::validate_str(d)?;
            }

            main_part
        } else {
            inner
        };

        if let Some(e) = path
            .split(PATH_SEP)
            .map(|s| if s.is_empty() { Err(BadSlug::EmptySlugNotAllowed.into()) } else { Ok(slug::check_syntax(s)?) })
            .find(|e| e.is_err())
        {
            return e;
        }

        Ok(())
    }

    /// Return the substring corresponding to the specified `range`.
    ///
    /// Returns `None` if `range` is not within the bounds of this `ArtiPath`.
    ///
    /// ### Example
    /// ```
    /// # use tor_keymgr::{ArtiPath, KeyPathRange, ArtiPathSyntaxError};
    /// # fn demo() -> Result<(), ArtiPathSyntaxError> {
    /// let path = ArtiPath::new("foo_bar_bax_1".into())?;
    ///
    /// let range = KeyPathRange::from(2..5);
    /// assert_eq!(path.substring(&range), Some("o_b"));
    ///
    /// let range = KeyPathRange::from(22..50);
    /// assert_eq!(path.substring(&range), None);
    /// # Ok(())
    /// # }
    /// #
    /// # demo().unwrap();
    /// ```
    pub fn substring(&self, range: &KeyPathRange) -> Option<&str> {
        self.0.get(range.0.clone())
    }
}

/// A component of an [`ArtiPath`].
///
/// An `ArtiPathComponent` must be a valid [`Slug`].
/// See [slug] for the syntactic requirements.
//
// TODO: we should abolish ArtiPathComponent in favour of Slug
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Into, Display)] //
#[derive(Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ArtiPathComponent(Slug);

impl ArtiPathComponent {
    /// Create a new [`ArtiPathComponent`].
    pub fn new(s: String) -> Result<Self, ArtiPathSyntaxError> {
        Ok(Slug::new(s).map(Self)?)
    }

    /// Return a view of this `ArtiPathComponent` as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Validate the underlying representation of an `ArtiPathComponent`.
    fn validate_str(inner: &str) -> Result<(), ArtiPathSyntaxError> {
        Ok(Slug::new(inner.to_string()).map(|_| ())?)
    }
}

impl TryFrom<String> for ArtiPathComponent {
    type Error = ArtiPathSyntaxError;

    fn try_from(s: String) -> Result<Self, ArtiPathSyntaxError> {
        Self::new(s)
    }
}

impl From<ArtiPathComponent> for String {
    fn from(c: ArtiPathComponent) -> Self {
        c.0.to_string()
    }
}

impl FromStr for ArtiPathComponent {
    type Err = ArtiPathSyntaxError;

    fn from_str(s: &str) -> Result<Self, ArtiPathSyntaxError> {
        Self::new(s.to_string())
    }
}
