//! The [`KeySpecifier`] trait and its implementations.

use crate::{KeystoreError, Result};
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
    /// This function returns an error if the specified string is not a valid Arti path.
    // TODO hs: restrict the character set and syntax for values of this type (it should not be
    // possible to construct an ArtiPath out of a String that uses disallowed chars, or one that is in
    // the wrong format (TBD exactly what this format is supposed to look like)
    #[allow(clippy::unnecessary_wraps)] // TODO hs: remove
    pub fn new(inner: String) -> Result<Self> {
        Ok(Self(inner))
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
    /// This function returns an error if the specified string contains any disallowed characters.
    ///
    /// TODO hs: restrict the character set and syntax for values of this type (it should not be
    /// possible to construct an ArtiPathComponent out of a String that uses disallowed chars, or
    /// one that is in the wrong format (TBD exactly what this format is supposed to look like)
    #[allow(clippy::unnecessary_wraps)] // TODO hs: remove
    pub fn new(inner: String) -> Result<Self> {
        Ok(Self(inner))
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
