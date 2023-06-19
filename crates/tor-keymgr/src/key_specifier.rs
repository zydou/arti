//! The [`KeySpecifier`] trait and its implementations.

use crate::{KeystoreError, Result};
use std::path;
use tor_error::HasKind;

/// The path of a key in the Arti key store.
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
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

impl ArtiPath {
    /// Create a new [`ArtiPath`].
    ///
    /// An `ArtiPath` may only consist of UTF-8 alphanumeric, dash (`-`), underscore (`_`), and
    /// path separator characters.
    ///
    /// The specified string is normalized by replacing any consecutive occurrences of the path
    /// separator character with a single path separator.
    ///
    /// This function returns an error if `inner` contains any disallowed characters, or if it
    /// consists solely of path sepatators.
    pub fn new(inner: String) -> Result<Self> {
        let is_allowed =
            |c: char| ArtiPathComponent::is_allowed_char(c) || c == path::MAIN_SEPARATOR;

        if inner.chars().any(|c| !is_allowed(c)) {
            Err(Box::new(InvalidArtiPathError(inner)))
        } else {
            Self::normalize_string(&inner).map(Self)
        }
    }

    /// Remove all but the first of consecutive [MAIN_SEPARATOR](path::MAIN_SEPARATOR) elements
    /// from `s`.
    ///
    /// This function returns an error if `s` consists solely of path sepatators.
    fn normalize_string(s: &str) -> Result<String> {
        if s.chars().all(|c| c == path::MAIN_SEPARATOR) {
            return Err(Box::new(InvalidArtiPathError(s.into())));
        }

        let mut chars = s.chars().collect::<Vec<_>>();
        chars.dedup_by(|a, b| *a == path::MAIN_SEPARATOR && *b == path::MAIN_SEPARATOR);

        Ok(chars.into_iter().collect::<String>())
    }
}

/// A component of an [`ArtiPath`].
///
/// This represents a substring of an [`ArtiPath`] between path separators (`/`).
#[derive(
    Clone, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::Into, derive_more::Display,
)]
pub struct ArtiPathComponent(String);

impl ArtiPathComponent {
    /// Create a new [`ArtiPathComponent`].
    ///
    /// An `ArtiPathComponent` may only consist of UTF-8 alphanumeric, dash
    /// (`-`), and underscore (`_`) characters.
    ///
    /// This function returns an error if `inner` contains any disallowed characters.
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
