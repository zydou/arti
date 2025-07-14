//! Raw keystore entry identifiers used in plumbing CLI functionalities.

use std::path::PathBuf;

use amplify::Getters;
use tor_basic_utils::PathExt;
use tor_key_forge::KeystoreItemType;

use crate::{ArtiPath, KeystoreId, UnrecognizedEntry};

/// A raw keystore entry descriptor.
#[cfg_attr(feature = "onion-service-cli-extra", visibility::make(pub))]
#[derive(Debug, Clone, PartialEq, derive_more::From, Getters)]
pub(crate) struct RawKeystoreEntry {
    /// The underlying keystore-specific raw identifier of the entry.
    #[getter(skip)]
    raw_id: RawEntryId,
    /// The keystore this entry was found in.
    #[getter(skip)]
    keystore_id: KeystoreId,
}

impl RawKeystoreEntry {
    /// Return the underlying keystore-specific raw identifier of the entry.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn raw_id(&self) -> &RawEntryId {
        &self.raw_id
    }

    /// Return the ID of the keystore this entry was found in.
    #[cfg(feature = "onion-service-cli-extra")]
    pub fn keystore_id(&self) -> &KeystoreId {
        &self.keystore_id
    }
}

impl From<&UnrecognizedEntry> for RawKeystoreEntry {
    fn from(value: &UnrecognizedEntry) -> Self {
        value.clone().into()
    }
}

impl RawKeystoreEntry {
    /// Returns a new instance of [`RawKeystoreEntry`]
    /// that identifies an entry with the specified `raw_id`
    /// raw identifier in the keystore with the specified
    /// `keystore_id`.
    pub(crate) fn new(raw_id: RawEntryId, keystore_id: KeystoreId) -> Self {
        Self {
            raw_id,
            keystore_id,
        }
    }
}

/// The raw identifier of a key inside a [`Keystore`](crate::Keystore).
///
/// The exact type of the identifier depends on the backing storage of the keystore
/// (for example, an on-disk keystore will identify its entries by [`Path`](RawEntryId::Path)).
#[cfg_attr(feature = "onion-service-cli-extra", visibility::make(pub))]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, derive_more::Display)]
pub(crate) enum RawEntryId {
    /// An entry identified by path inside an on-disk keystore.
    // NOTE: this will only be used by on-disk keystores like
    // [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)
    #[display("{}", _0.display_lossy())]
    Path(PathBuf),

    /// An entry of an in-memory ephemeral key storage
    /// [`ArtiEphemeralKeystore`](crate::ArtiEphemeralKeystore)
    #[display("{} {:?}", _0.0, _0.1)]
    Ephemeral((ArtiPath, KeystoreItemType)),
    // TODO: when/if we add support for non on-disk keystores,
    // new variants will be added
}
