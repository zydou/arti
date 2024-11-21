//! Helpers for encoding certificate material.

use crate::{ErasedKey, Result};
use tor_cert::EncodedEd25519Cert;

/// A key certificate.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum CertData {
    /// A tor-specific ed25519 cert.
    TorEd25519Cert(EncodedEd25519Cert),
}

impl CertData {
    /// Convert the cert material into a known cert type,
    /// and return the type-erased value.
    ///
    /// The caller is expected to downcast the value returned to the correct concrete type.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn into_erased(self) -> Result<ErasedKey> {
        match self {
            Self::TorEd25519Cert(cert) => Ok(Box::new(cert)),
        }
    }
}
