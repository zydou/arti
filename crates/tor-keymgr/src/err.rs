//! An error type for the `tor-keymgr` crate.

use tor_error::HasKind;

use dyn_clone::DynClone;
use tor_persist::slug::BadSlug;

use std::error::Error as StdError;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use crate::raw::RawKeystoreEntry;
use crate::{KeyPath, KeyPathError, KeystoreId};

/// An Error type for this crate.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Detected keustore corruption.
    #[error("{0}")]
    Corruption(#[from] KeystoreCorruptionError),

    /// An opaque error returned by a [`Keystore`](crate::Keystore).
    #[error("{0}")]
    Keystore(#[from] Arc<dyn KeystoreError>),

    /// An error returned when the [`KeyMgr`](crate::KeyMgr) is asked to generate a key that already exists.
    ///
    /// Note that because there is no locking of the keystore,
    /// this situation is not reliably detected
    /// in the presence of concurrent tasks trying to generate the same key.
    ///
    /// So this error is provided to help the human user,
    /// but mustn't be relied on for correctness.
    #[error("Key already exists")]
    KeyAlreadyExists,

    /// Error coming from the tor-key-forgecrate
    #[error("{0}")]
    KeyForge(#[from] tor_key_forge::Error),

    /// An error caused by an invalid certificate.
    #[error("{0}")]
    InvalidCert(#[from] tor_key_forge::InvalidCertError),

    /// An error returned when the [`KeyMgr`](crate::KeyMgr) is unable to
    /// find a [`Keystore`](crate::Keystore) matching a given [`KeystoreId`]
    /// in either its `primary_store` field or the `secondary_stores` collection.
    #[error("Keystore {0} not found")]
    KeystoreNotFound(KeystoreId),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error returned by a [`Keystore`](crate::Keystore).
pub trait KeystoreError:
    HasKind + StdError + DynClone + fmt::Debug + fmt::Display + Send + Sync + 'static
{
}

impl HasKind for Error {
    fn kind(&self) -> tor_error::ErrorKind {
        use Error as E;
        use tor_error::ErrorKind as EK;

        match self {
            E::Keystore(e) => e.kind(),
            E::Corruption(_) => EK::KeystoreCorrupted,
            E::KeyAlreadyExists => EK::BadApiUsage, // TODO: not strictly right
            E::KeystoreNotFound(_) => EK::BadApiUsage, // TODO: not strictly right
            E::KeyForge(_) => EK::BadApiUsage,
            E::InvalidCert(_) => EK::BadApiUsage, // TODO: not strictly right
            E::Bug(e) => e.kind(),
        }
    }
}

/// An error caused by a syntactically invalid [`ArtiPath`](crate::ArtiPath).
///
/// The `ArtiPath` is not in the legal syntax: it contains bad characters,
/// or a syntactically invalid components.
///
/// (Does not include any errors arising from paths which are invalid
/// *for the particular key*.)
#[derive(thiserror::Error, Debug, Clone)]
#[error("Invalid ArtiPath")]
#[non_exhaustive]
pub enum ArtiPathSyntaxError {
    /// One of the path slugs was invalid.
    #[error("{0}")]
    Slug(#[from] BadSlug),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error caused by keystore corruption.
#[derive(thiserror::Error, Debug, Clone)]
#[error("Keystore corruption")]
#[non_exhaustive]
pub enum KeystoreCorruptionError {
    /// A keystore contains a key that has an invalid [`KeyPath`].
    #[error("{0}")]
    KeyPath(#[from] KeyPathError),

    /// A keystore contains an unrecognized [`KeyPath`].
    #[error("Unrecognized key path {0}")]
    Unrecognized(KeyPath),

    /// Missing certificate for key.
    #[error("Missing certificate for key")]
    MissingCertificate,

    /// Missing the subject key of a certificate we own.
    #[error("Subject key of certificate not found")]
    MissingSubjectKey,

    /// Missing signing key for certificate.
    #[error("Missing signing key for certificate")]
    MissingSigningKey,
}

/// An error that happens when we encounter an unknown key type.
#[derive(thiserror::Error, PartialEq, Eq, Debug, Clone)]
#[error("unknown key type: arti_extension={arti_extension}")]
pub struct UnknownKeyTypeError {
    /// The extension used for keys of this type in an Arti keystore.
    pub(crate) arti_extension: String,
}

/// An unrecognized keystore entry.
#[derive(Clone, Debug, amplify::Getters, thiserror::Error)]
#[error("Unrecognized keystore entry")]
pub struct UnrecognizedEntryError {
    /// An identifier of the entry that caused the error.
    entry: UnrecognizedEntry,
    /// The underlying error that occurred.
    // TODO: This should be an `Error` specific for the situation.
    //
    // [`KeystoreError`] is a provvisory solution that presents
    // some issues, for example:
    //
    // * not all variants of `KeystoreError` are relevant
    // * redundancy with some other Error types like
    // [`MalformedServiceKeyError::NotAKey`](crate::keystore::ctor::err::MalformedServiceKeyError)
    // * [`Keystore::list`](crate::Keystore) returns
    // `StdResult<Vec<StdResult<(KeyPath, KeystoreItemType), UnrecognizedEntryError>>, KeystoreError>`,
    // `KeystoreError` presents itself twice at 2 different levels, there is ambiguity
    #[source]
    error: Arc<dyn KeystoreError>,
}

impl UnrecognizedEntryError {
    /// Create a new instance of `KeystoreListError` given an `UnrecognizedEntry`
    /// and an `Arc<dyn KeystoreError>`.
    pub(crate) fn new(entry: UnrecognizedEntry, error: Arc<dyn KeystoreError>) -> Self {
        Self { entry, error }
    }
}

/// The opaque identifier of an unrecognized key inside a [`Keystore`](crate::Keystore).
#[derive(Debug, Clone, PartialEq, derive_more::From, derive_more::Into)]
pub struct UnrecognizedEntry(RawKeystoreEntry);

#[cfg(feature = "onion-service-cli-extra")]
impl Deref for UnrecognizedEntry {
    type Target = RawKeystoreEntry;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_error::ErrorKind;

    #[derive(Debug, Copy, Clone, PartialEq, thiserror::Error)]
    #[error("The source of a test error")]
    struct TestErrorSource;

    #[derive(Debug, Clone, thiserror::Error)]
    #[error("A test error")]
    struct TestError(#[from] TestErrorSource);

    impl KeystoreError for TestError {}

    impl HasKind for TestError {
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn error_source() {
        let e: Error = (Arc::new(TestError(TestErrorSource)) as Arc<dyn KeystoreError>).into();

        assert_eq!(
            e.source().unwrap().to_string(),
            TestError(TestErrorSource).to_string()
        );
    }
}
