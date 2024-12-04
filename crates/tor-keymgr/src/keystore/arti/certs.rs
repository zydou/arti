//! Helpers for parsing certificates.

use std::path::PathBuf;

use tor_error::internal;
use tor_key_forge::{CertType, EncodedEd25519Cert};

use crate::keystore::arti::err::ArtiNativeKeystoreError;
use crate::{ErasedKey, Result};

/// An unparsed key certificate.
pub(super) struct UnparsedCert {
    /// The contents of the cert file.
    inner: Vec<u8>,
    /// The path of the file (for error reporting).
    #[allow(dead_code)]
    path: PathBuf,
}

impl UnparsedCert {
    /// Create a new [`UnparsedCert`].
    pub(super) fn new(inner: Vec<u8>, path: PathBuf) -> Self {
        Self { inner, path }
    }

    /// Parse a key certificate, converting the key material into a known type,
    /// and return the type-erased value.
    ///
    /// The caller is expected to downcast the value returned to a concrete type.
    pub(super) fn parse_certificate_erased(self, cert_type: &CertType) -> Result<ErasedKey> {
        match cert_type {
            CertType::Ed25519TorCert => {
                // TODO: check if the cert is in the expected format?
                Ok(Box::new(EncodedEd25519Cert::from_bytes(&self.inner)))
            }
            _ => Err(
                ArtiNativeKeystoreError::Bug(internal!("Unknown cert type {cert_type:?}")).into(),
            ),
        }
    }
}
