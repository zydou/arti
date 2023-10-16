//! The [`KeySpecifier`] trait and its implementations.

use std::result::Result as StdResult;

use derive_more::{Deref, DerefMut, Display, From, Into};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The path of a key in the Arti key store.
///
/// An `ArtiPath` is a nonempty sequence of [`ArtiPathComponent`]s, separated by `/`.  Path
/// components may contain UTF-8 alphanumerics, and (except as the first or last character) `-`,
/// `_`, or  `.`.
/// Consequently, leading or trailing or duplicated / are forbidden.
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
//
// TODO HSS: Create an error type for ArtiPath errors instead of relying on internal!
// TODO HSS: disallow consecutive `.` to prevent path traversal.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Deref, DerefMut, Into, Display)]
pub struct ArtiPath(String);

/// The identifier of a key.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, From, Display)]
#[non_exhaustive]
pub enum KeyPath {
    /// An Arti key path.
    Arti(ArtiPath),
    /// A C-Tor key path.
    CTor(CTorPath),
}

impl KeyPath {
    /// Return the underlying [`ArtiPath`], if this is a `KeyPath::Arti`.
    pub fn arti(&self) -> Option<&ArtiPath> {
        match self {
            KeyPath::Arti(ref arti) => Some(arti),
            KeyPath::CTor(_) => None,
        }
    }

    /// Return the underlying [`CTorPath`], if this is a `KeyPath::CTor`.
    pub fn ctor(&self) -> Option<&CTorPath> {
        match self {
            KeyPath::Arti(_) => None,
            KeyPath::CTor(ref ctor) => Some(ctor),
        }
    }
}

/// A separator for `ArtiPath`s.
const PATH_SEP: char = '/';

impl ArtiPath {
    /// Create a new [`ArtiPath`].
    ///
    /// This function returns an error if `inner` is not a valid `ArtiPath`.
    // TODO HSS this function (and validate_str) should have a bespoke error type
    pub fn new(inner: String) -> StdResult<Self, ArtiPathError> {
        if let Some(e) = inner
            .split(PATH_SEP)
            .find_map(|s| ArtiPathComponent::validate_str(s).err())
        {
            return Err(e);
        }

        Ok(Self(inner))
    }
}

/// A component of an [`ArtiPath`].
///
/// Path components may contain UTF-8 alphanumerics, and (except as the first or last character)
/// `-`,  `_`, or `.`.
#[derive(
    Clone,
    Debug,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::Into,
    derive_more::Display,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct ArtiPathComponent(String);

impl ArtiPathComponent {
    /// Create a new [`ArtiPathComponent`].
    ///
    /// This function returns an error if `inner` is not a valid `ArtiPathComponent`.
    pub fn new(inner: String) -> StdResult<Self, ArtiPathError> {
        Self::validate_str(&inner)?;

        Ok(Self(inner))
    }

    /// Check whether `c` can be used within an `ArtiPathComponent`.
    fn is_allowed_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
    }

    /// Validate the underlying representation of an `ArtiPath` or `ArtiPathComponent`.
    fn validate_str(inner: &str) -> StdResult<(), ArtiPathError> {
        /// These cannot be the first or last chars of an `ArtiPath` or `ArtiPathComponent`.
        const MIDDLE_ONLY: &[char] = &['-', '_', '.'];

        if inner.is_empty() {
            return Err(ArtiPathError::EmptyPathComponent);
        }

        if let Some(c) = inner.chars().find(|c| !Self::is_allowed_char(*c)) {
            return Err(ArtiPathError::DisallowedChar(c));
        }

        if inner.contains("..") {
            return Err(ArtiPathError::PathTraversal);
        }

        for c in MIDDLE_ONLY {
            if inner.starts_with(*c) || inner.ends_with(*c) {
                return Err(ArtiPathError::BadOuterChar(*c));
            }
        }

        Ok(())
    }
}

impl TryFrom<String> for ArtiPathComponent {
    type Error = ArtiPathError;

    fn try_from(s: String) -> StdResult<ArtiPathComponent, ArtiPathError> {
        Self::new(s)
    }
}

impl AsRef<str> for ArtiPathComponent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The path of a key in the C Tor key store.
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Deref, DerefMut, Into, Display)]
pub struct CTorPath(String);

/// The "specifier" of a key, which identifies an instance of a key.
///
/// [`KeySpecifier::arti_path()`] should uniquely identify an instance of a key.
pub trait KeySpecifier {
    /// The location of the key in the Arti key store.
    ///
    /// This also acts as a unique identifier for a specific key instance.
    fn arti_path(&self) -> StdResult<ArtiPath, KeyPathError>;

    /// The location of the key in the C Tor key store (if supported).
    ///
    /// This function should return `None` for keys that are recognized by Arti's key stores, but
    /// not by C Tor's key store (such as `HsClientIntroAuthKeypair`).
    fn ctor_path(&self) -> Option<CTorPath>;
}

/// An error returned by a [`KeySpecifier`].
#[derive(Error, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum KeyPathError {
    /// Encountered an invalid `ArtiPath`
    #[error("Bad ArtiPath")]
    Arti(#[from] ArtiPathError),

    /// Unsuported [`KeyPath`] type.
    #[error("Unsupported key path")]
    NotSupported,
}

/// An error caused by an invalid [`ArtiPath`].
#[derive(Error, Debug, Copy, Clone)]
#[error("Invalid ArtiPath")]
#[non_exhaustive]
pub enum ArtiPathError {
    /// Found an empty path component.
    #[error("Empty path component")]
    EmptyPathComponent,

    /// The path contains a disallowed char.
    #[error("Found disallowed char {0}")]
    DisallowedChar(char),

    /// The path contains the `..` pattern.
    #[error("Found `..` pattern")]
    PathTraversal,

    /// The path starts with a disallowed char.
    #[error("Path starts or ends with disallowed char {0}")]
    BadOuterChar(char),
}

impl KeySpecifier for ArtiPath {
    fn arti_path(&self) -> StdResult<ArtiPath, KeyPathError> {
        Ok(self.clone())
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        None
    }
}

impl KeySpecifier for CTorPath {
    fn arti_path(&self) -> StdResult<ArtiPath, KeyPathError> {
        Err(KeyPathError::NotSupported)
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        Some(self.clone())
    }
}

impl KeySpecifier for KeyPath {
    fn arti_path(&self) -> StdResult<ArtiPath, KeyPathError> {
        match self {
            KeyPath::Arti(p) => p.arti_path(),
            KeyPath::CTor(p) => p.arti_path(),
        }
    }

    fn ctor_path(&self) -> Option<CTorPath> {
        match self {
            KeyPath::Arti(p) => p.ctor_path(),
            KeyPath::CTor(p) => p.ctor_path(),
        }
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

    macro_rules! assert_err {
        ($ty:ident, $inner:expr, $error_kind:pat) => {{
            let path = $ty::new($inner.to_string());
            assert!(path.is_err(), "{} should be invalid", $inner);
            assert!(
                matches!(path.as_ref().unwrap_err(), $error_kind),
                "wrong error type for {}: {path:?}",
                $inner
            );
        }};
    }

    macro_rules! assert_ok {
        ($ty:ident, $inner:expr) => {{
            let path = $ty::new($inner.to_string());
            assert!(path.is_ok(), "{} should be valid", $inner);
            assert_eq!(path.unwrap().to_string(), *$inner);
        }};
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn arti_path_validation() {
        const VALID_ARTI_PATHS: &[&str] = &[
            "my-hs-client-2",
            "hs_client",
            "client٣¾",
            "clientß",
            "client.key",
        ];

        const BAD_OUTER_CHAR_ARTI_PATHS: &[&str] = &[
            "-hs_client",
            "_hs_client",
            "hs_client-",
            "hs_client_",
            ".client",
            "client.",
            "-",
            "_",
        ];

        const DISALLOWED_CHAR_ARTI_PATHS: &[&str] = &["c++", "client?", "no spaces please"];

        const EMPTY_PATH_COMPONENT: &[&str] =
            &["/////", "/alice/bob", "alice//bob", "alice/bob/", "/"];

        for path in VALID_ARTI_PATHS {
            assert_ok!(ArtiPath, path);
            assert_ok!(ArtiPathComponent, path);
        }

        for path in DISALLOWED_CHAR_ARTI_PATHS {
            assert_err!(ArtiPath, path, ArtiPathError::DisallowedChar(_));
            assert_err!(ArtiPathComponent, path, ArtiPathError::DisallowedChar(_));
        }

        for path in BAD_OUTER_CHAR_ARTI_PATHS {
            assert_err!(ArtiPath, path, ArtiPathError::BadOuterChar(_));
            assert_err!(ArtiPathComponent, path, ArtiPathError::BadOuterChar(_));
        }

        for path in EMPTY_PATH_COMPONENT {
            assert_err!(ArtiPath, path, ArtiPathError::EmptyPathComponent);
            assert_err!(ArtiPathComponent, path, ArtiPathError::DisallowedChar('/'));
        }

        const SEP: char = PATH_SEP;
        // This is a valid ArtiPath, but not a valid ArtiPathComponent
        let path = format!("a{SEP}client{SEP}key.private");
        assert_ok!(ArtiPath, &path);
        assert_err!(ArtiPathComponent, &path, ArtiPathError::DisallowedChar('/'));

        const PATH_WITH_TRAVERSAL: &str = "alice/../bob";
        assert_err!(ArtiPath, PATH_WITH_TRAVERSAL, ArtiPathError::PathTraversal);
        assert_err!(
            ArtiPathComponent,
            PATH_WITH_TRAVERSAL,
            ArtiPathError::DisallowedChar('/')
        );

        const REL_PATH: &str = "./bob";
        assert_err!(ArtiPath, REL_PATH, ArtiPathError::BadOuterChar('.'));
        assert_err!(
            ArtiPathComponent,
            REL_PATH,
            ArtiPathError::DisallowedChar('/')
        );
    }

    #[test]
    fn serde() {
        // TODO HSS clone-and-hack with tor_hsservice::::nickname::test::serde
        // perhaps there should be some utility in tor-basic-utils for testing
        // validated string newtypes, or something
        #[derive(Serialize, Deserialize, Debug)]
        struct T {
            n: ArtiPathComponent,
        }
        let j = serde_json::from_str(r#"{ "n": "x" }"#).unwrap();
        let t: T = serde_json::from_value(j).unwrap();
        assert_eq!(&t.n.to_string(), "x");

        assert_eq!(&serde_json::to_string(&t).unwrap(), r#"{"n":"x"}"#);

        let j = serde_json::from_str(r#"{ "n": "!" }"#).unwrap();
        let e = serde_json::from_value::<T>(j).unwrap_err();
        assert!(
            e.to_string().contains("Found disallowed char"),
            "wrong msg {e:?}"
        );
    }
}
