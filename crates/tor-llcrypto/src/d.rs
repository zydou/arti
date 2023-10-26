//! Digests and XOFs used to implement the Tor protocol.
//!
//! In various places, for legacy reasons, Tor uses SHA1, SHA2, SHA3,
//! and SHAKE.  We re-export them all here, in forms implementing the
//! the [`digest::Digest`] traits.
//!
//! Other code should access these digests via the traits in the
//! [`digest`] crate.

#[cfg(feature = "with-openssl")]
pub use openssl_compat::Sha1;
#[cfg(not(feature = "with-openssl"))]
pub use sha1::Sha1;

pub use sha2::{Sha256, Sha512};
pub use sha3::{Sha3_256, Shake128, Shake256, Shake256Reader};

/// Compatibility layer between OpenSSL and `digest`
#[cfg(feature = "with-openssl")]
mod openssl_compat {
    use openssl::sha::Sha1 as OpenSslSha1;

    use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update};

    /// Wrapper around OpenSSL Sha1 to make it compatible with `digest`
    #[derive(Default, Clone)]
    pub struct Sha1(OpenSslSha1);

    impl Update for Sha1 {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
    }

    impl OutputSizeUser for Sha1 {
        type OutputSize = typenum::consts::U20;
    }

    impl FixedOutput for Sha1 {
        fn finalize_into(self, out: &mut Output<Self>) {
            *out = self.0.finish().into();
        }
    }

    impl HashMarker for Sha1 {}
}
