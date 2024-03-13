//! Facilities to construct AuthCert objects.
//!
//! (These are only for testing right now, since we don't yet
//! support signing or encoding.)

use super::{AuthCert, AuthCertKeyIds};

use crate::{BuildError as Error, BuildResult};
use std::net::SocketAddrV4;
use std::ops::Range;
use std::time::SystemTime;
use tor_llcrypto::pk::rsa;

/// A builder object used to construct an authority certificate.
///
/// Create one of these with the [`AuthCert::builder`] method.
///
/// This facility is only enabled when the crate is built with
/// the `build_docs` feature.
#[cfg_attr(docsrs, doc(cfg(feature = "build_docs")))]
pub struct AuthCertBuilder {
    /// See [`AuthCert::address`]
    address: Option<SocketAddrV4>,
    /// See [`AuthCert::identity_key`]
    identity_key: Option<rsa::PublicKey>,
    /// See [`AuthCert::signing_key`]
    signing_key: Option<rsa::PublicKey>,
    /// See [`AuthCert::published`]
    published: Option<SystemTime>,
    /// See [`AuthCert::expires`]
    expires: Option<SystemTime>,
}

impl AuthCertBuilder {
    /// Make a new AuthCertBuilder
    pub(crate) fn new() -> Self {
        AuthCertBuilder {
            address: None,
            identity_key: None,
            signing_key: None,
            published: None,
            expires: None,
        }
    }

    /// Set the IPv4 address for this authority.
    ///
    /// This field is optional.
    pub fn address(&mut self, address: SocketAddrV4) -> &mut Self {
        self.address = Some(address);
        self
    }

    /// Set the identity key for this authority.
    ///
    /// This field is required.
    pub fn identity_key(&mut self, key: rsa::PublicKey) -> &mut Self {
        self.identity_key = Some(key);
        self
    }

    /// Set the identity key for this certificate.
    ///
    /// This field is required.
    pub fn signing_key(&mut self, key: rsa::PublicKey) -> &mut Self {
        self.signing_key = Some(key);
        self
    }

    /// Set the lifespan for this certificate.
    ///
    /// These fields are required.
    pub fn lifespan(&mut self, lifespan: Range<SystemTime>) -> &mut Self {
        self.published = Some(lifespan.start);
        self.expires = Some(lifespan.end);
        self
    }

    /// Try to construct an [`AuthCert`] from this builder.
    ///
    /// This function can fail if any of the builder's fields are
    /// missing or ill-formed.
    ///
    /// # Danger
    ///
    /// This function is dangerous because it can be used to construct a
    /// certificate where no certificate actually exists: The identity key
    /// here has not, in fact, attested to the signing key.
    ///
    /// You should only use this function for testing.
    pub fn dangerous_testing_cert(&self) -> BuildResult<AuthCert> {
        let published = self
            .published
            .ok_or(Error::CannotBuild("Missing published time"))?;
        let expires = self
            .expires
            .ok_or(Error::CannotBuild("Missing expiration time"))?;
        if expires < published {
            return Err(Error::CannotBuild("Expires before published time."));
        }
        let identity_key = self
            .identity_key
            .as_ref()
            .ok_or(Error::CannotBuild("Missing identity key."))?
            .clone();
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(Error::CannotBuild("Missing signing key."))?
            .clone();

        let id_fingerprint = identity_key.to_rsa_identity();
        let sk_fingerprint = signing_key.to_rsa_identity();

        let key_ids = AuthCertKeyIds {
            id_fingerprint,
            sk_fingerprint,
        };

        Ok(AuthCert {
            address: self.address,
            identity_key,
            signing_key,
            published,
            expires,
            key_ids,
        })
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use hex_literal::hex;
    use std::time::Duration;

    fn rsa1() -> rsa::PublicKey {
        let der = hex!("30818902818100d527b6c63d6e81d39c328a94ce157dccdc044eb1ad8c210c9c9e22487b4cfade6d4041bd10469a657e3d82bc00cf62ac3b6a99247e573b54c10c47f5dc849b0accda031eca6f6e5dc85677f76dec49ff24d2fcb2b5887fb125aa204744119bb6417f45ee696f8dfc1c2fc21b2bae8e9e37a19dc2518a2c24e7d8fd7fac0f46950203010001");
        rsa::PublicKey::from_der(&der).unwrap()
    }

    fn rsa2() -> rsa::PublicKey {
        let der = hex!("3082010a0282010100d4e420607eddac8264d888cf89a7af78e619db21db5a4671497797614826316f13e2136fd65ed12bbebb724aa6c214d9ceb30a28053778c3da25b87cdb24a246ba427726e17c60b507ed26d8c6377aa14f611dc12f7a7e67ada07fd04e42225a0b84331e347373590f41410c11853e42ee9a34e95a7715edddb651b063e12bf3a58b8c5dce5efd2681d1d4a6ba02def665eb2ba64520577f4d659849858a10f9303fbd934be8a1a461dbe5d7bf0c12c2a3281c63dcdd28f77f5516046253cf7f7a907c15ed2f7baf0aac4c9be3092ec173e15881aebc5d53b5c73dbc545684165510926d8ca202f2e06faaf0da35950c162bf36a2868006837b8b39b61c5b2b10203010001");
        rsa::PublicKey::from_der(&der).unwrap()
    }

    #[test]
    fn simple_cert() {
        let now = SystemTime::now();
        let one_hour = Duration::new(3600, 0);
        let later = now + one_hour * 2;
        let addr = "192.0.0.1:9090".parse().unwrap();
        let cert = AuthCert::builder()
            .identity_key(rsa2())
            .signing_key(rsa1())
            .address(addr)
            .lifespan(now..later)
            .dangerous_testing_cert()
            .unwrap();

        assert_eq!(cert.key_ids().id_fingerprint, rsa2().to_rsa_identity());
        assert_eq!(cert.key_ids().sk_fingerprint, rsa1().to_rsa_identity());
        assert_eq!(cert.published(), now);
        assert_eq!(cert.expires(), later);
    }

    #[test]
    fn failing_cert() {
        let now = SystemTime::now();
        let one_hour = Duration::new(3600, 0);
        let later = now + one_hour * 2;

        {
            let c = AuthCert::builder()
                .identity_key(rsa1())
                .lifespan(now..later)
                .dangerous_testing_cert();
            assert!(c.is_err()); // no signing key.
        }

        {
            let c = AuthCert::builder()
                .signing_key(rsa1())
                .lifespan(now..later)
                .dangerous_testing_cert();
            assert!(c.is_err()); // no identity key.
        }

        {
            let c = AuthCert::builder()
                .signing_key(rsa1())
                .identity_key(rsa2())
                .dangerous_testing_cert();
            assert!(c.is_err()); // no lifespan.
        }

        {
            let c = AuthCert::builder()
                .signing_key(rsa1())
                .identity_key(rsa2())
                .lifespan(later..now)
                .dangerous_testing_cert();
            assert!(c.is_err()); // bad lifespan.
        }
    }
}
