//! Shared OpenSSH helpers.

use ssh_key::Algorithm;

/// The algorithm string for x25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const X25519_ALGORITHM_NAME: &str = "x25519@spec.torproject.org";

/// The algorithm string for expanded ed25519 SSH keys.
///
/// See <https://spec.torproject.org/ssh-protocols.html>
pub(crate) const ED25519_EXPANDED_ALGORITHM_NAME: &str = "ed25519-expanded@spec.torproject.org";

/// SSH key algorithms.
//
// Note: this contains all the types supported by ssh_key, plus variants representing
// x25519 and expanded ed25519 keys.
#[derive(Clone, Debug, PartialEq, derive_more::Display)]
#[non_exhaustive]
pub enum SshKeyAlgorithm {
    /// Digital Signature Algorithm
    Dsa,
    /// Elliptic Curve Digital Signature Algorithm
    Ecdsa,
    /// Ed25519
    Ed25519,
    /// Expanded Ed25519
    Ed25519Expanded,
    /// X25519
    X25519,
    /// RSA
    Rsa,
    /// FIDO/U2F key with ECDSA/NIST-P256 + SHA-256
    SkEcdsaSha2NistP256,
    /// FIDO/U2F key with Ed25519
    SkEd25519,
    /// An unrecognized [`ssh_key::Algorithm`].
    Unknown(ssh_key::Algorithm),
}

impl From<Algorithm> for SshKeyAlgorithm {
    fn from(algo: Algorithm) -> SshKeyAlgorithm {
        match &algo {
            Algorithm::Dsa => SshKeyAlgorithm::Dsa,
            Algorithm::Ecdsa { .. } => SshKeyAlgorithm::Ecdsa,
            Algorithm::Ed25519 => SshKeyAlgorithm::Ed25519,
            Algorithm::Rsa { .. } => SshKeyAlgorithm::Rsa,
            Algorithm::SkEcdsaSha2NistP256 => SshKeyAlgorithm::SkEcdsaSha2NistP256,
            Algorithm::SkEd25519 => SshKeyAlgorithm::SkEd25519,
            Algorithm::Other(name) => match name.as_str() {
                X25519_ALGORITHM_NAME => SshKeyAlgorithm::X25519,
                ED25519_EXPANDED_ALGORITHM_NAME => SshKeyAlgorithm::Ed25519Expanded,
                _ => SshKeyAlgorithm::Unknown(algo),
            },
            // Note: ssh_key::Algorithm is non_exhaustive, so we need this catch-all variant
            _ => SshKeyAlgorithm::Unknown(algo),
        }
    }
}
