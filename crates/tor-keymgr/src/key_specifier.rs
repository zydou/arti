//! The [`KeySpecifier`] trait and its implementations.

use crate::{KeystoreError, Result};
use tor_error::HasKind;

/// The path of a key in the Arti key store.
///
/// # Requirements
///
/// An `ArtiPath` may only consist of UTF-8 alphanumeric, dash (`-`), underscore (`_`), and path
/// separator (`/`) characters. In addition, its underlying string representation must:
///   * not begin or end in `-` or `_`
///   * not contain any consecutive repeated `/` characters
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
//
// TODO hs: remove normalization and implement the validation described here
#[derive(
    Clone, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::Into, derive_more::Display,
)]
pub struct ArtiPath(String);

/// Encountered an invalid arti path.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Invalid arti path: {0}")]
struct InvalidArtiPathError(String);

impl HasKind for InvalidArtiPathError {
    fn kind(&self) -> tor_error::ErrorKind {
        // TODO HSS: this error kind is bad, because it doesn't tell us exactly where the error is
        // coming from (`ArtiPath` will be used as a basis for various kinds of specifiers, such as
        // HsClientSpecifier).
        tor_error::ErrorKind::KeystoreBadArtiPath
    }
}

impl KeystoreError for InvalidArtiPathError {}

/// A separator for `ArtiPath`s.
const PATH_SEP: char = '/';

impl ArtiPath {
    /// Create a new [`ArtiPath`].
    ///
    /// This function returns an error if `inner` is not a valid `ArtiPath`.
    pub fn new(inner: String) -> Result<Self> {
        let is_allowed = |c: char| ArtiPathComponent::is_allowed_char(c) || c == PATH_SEP;

        if inner.chars().any(|c| !is_allowed(c)) {
            Err(Box::new(InvalidArtiPathError(inner)))
        } else {
            Self::normalize_string(&inner).map(Self)
        }
    }

    /// Remove all but the first of consecutive path separator (`/`) elements from `s`.
    ///
    /// This function returns an error if `s` consists solely of path sepatators.
    fn normalize_string(s: &str) -> Result<String> {
        if s.chars().all(|c| c == PATH_SEP) {
            return Err(Box::new(InvalidArtiPathError(s.into())));
        }

        let mut chars = s.chars().collect::<Vec<_>>();
        chars.dedup_by(|a, b| *a == PATH_SEP && *b == PATH_SEP);

        Ok(chars.into_iter().collect::<String>())
    }
}

/// A component of an [`ArtiPath`].
///
/// This represents a substring of an [`ArtiPath`] between path separators (`/`).
///
/// # Requirements
///
/// An `ArtiPathComponent` may only consist of UTF-8 alphanumeric, dash (`-`), and underscore (`_`)
/// characters. In addition, the first and last characters of its underlying string representation
/// cannot be `-` or `_`.
//
// TODO hs: implement the validation described here
#[derive(
    Clone, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::Into, derive_more::Display,
)]
pub struct ArtiPathComponent(String);

impl ArtiPathComponent {
    /// Create a new [`ArtiPathComponent`].
    ///
    /// This function returns an error if `inner` is not a valid `ArtiPathComponent`.
    pub fn new(inner: String) -> Result<Self> {
        if inner.chars().any(|c| !Self::is_allowed_char(c)) {
            Err(Box::new(InvalidArtiPathError(inner)))
        } else {
            Ok(Self(inner))
        }
    }

    /// Check whether `c` can be used within an `ArtiPathComponent`.
    fn is_allowed_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_' || c == '-'
    }
}

/// The path of a key in the C Tor key store.
#[derive(Clone, Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct CTorPath(String);

/// The "specifier" of a key, which identifies an instance of a key.
///
/// [`KeySpecifier::arti_path()`] should uniquely identify an instance of a key.
pub trait KeySpecifier {
    /// The location of the key in the Arti key store.
    ///
    /// This also acts as a unique identifier for a specific key instance.
    fn arti_path(&self) -> Result<ArtiPath>;

    /// The location of the key in the C Tor key store (if supported).
    ///
    /// This function should return `None` for keys that are recognized by Arti's key stores, but
    /// not by C Tor's key store (such as `HsClientIntroAuthKeypair`).
    fn ctor_path(&self) -> Option<CTorPath>;
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
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    fn is_invalid_arti_path_error(err: &Error, inner: &str) -> bool {
        matches!(err, Error::InvalidArtiPath(c) if c == inner)
    }

    macro_rules! check_valid {
        ($ty:ident, $inner:expr, $expect_valid:expr) => {{
            let path = $ty::new($inner.to_string());

            if $expect_valid {
                assert!(path.is_ok(), "{} should be valid", $inner);
                assert_eq!(path.unwrap().to_string(), *$inner);
            } else {
                assert!(path.is_err(), "{} should be invalid", $inner);
                assert!(
                    is_invalid_arti_path_error(path.as_ref().unwrap_err(), $inner),
                    "wrong error type for {}: {path:?}",
                    $inner
                );
            }
        }};
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn arti_path_validation() {
        const VALID_ARTI_PATHS: &[&str] =
            &["my-hs-client-2", "hs_client_", "_", "client٣¾", "clientß"];

        const INVALID_ARTI_PATHS: &[&str] = &[
            "alice/../bob",
            "./bob",
            "c++",
            "client?",
            "no spaces please",
            "/",
            "/////",
        ];

        for path in VALID_ARTI_PATHS {
            check_valid!(ArtiPath, path, true);
            check_valid!(ArtiPathComponent, path, true);
        }

        for path in INVALID_ARTI_PATHS {
            check_valid!(ArtiPath, path, false);
            check_valid!(ArtiPathComponent, path, false);
        }

        const SEP: char = PATH_SEP;
        // This is a valid ArtiPath, but not a valid ArtiPathComponent
        let path = format!("{SEP}client{SEP}key");
        check_valid!(ArtiPath, &path, true);
        check_valid!(ArtiPathComponent, &path, false);
    }

    #[test]
    fn arti_path_normalization() {
        const SEP: char = PATH_SEP;

        let normalized_paths = vec![
            (
                format!("client{SEP}{SEP}{SEP}key"),
                Some(format!("client{SEP}key")),
            ),
            ("ccccclient-----key".into(), None),
            (format!("{SEP}hs-client{SEP}key-1-2-3{SEP}"), None),
        ];

        for (path, normalized) in normalized_paths {
            let arti_path = ArtiPath::new(path.clone()).unwrap();
            let normalized = normalized.unwrap_or_else(|| path.clone());
            assert_eq!(arti_path.as_ref(), normalized);
        }
    }
}
