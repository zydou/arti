//! The [`KeySpecifier`] trait and its implementations.

use crate::Result;

/// The path of a key in the Arti key store.
///
/// NOTE: There is a 1:1 mapping between a value that implements `KeySpecifier` and its
/// corresponding `ArtiPath`. A `KeySpecifier` can be converted to an `ArtiPath`, but the reverse
/// conversion is not supported.
#[derive(Clone, Debug, derive_more::Deref, derive_more::DerefMut, derive_more::Into)]
pub struct ArtiPath(String);

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
