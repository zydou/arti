//! Code for generating x509 certificates.
//!
//! For the most part, Tor doesn't actually need x509 certificates.
//! We only keep them around for two purposes:
//!
//! 1. The `RSA_ID_X509` certificate is provided in a CERTS cell,
//!    and used to transmit the RSA identity key.
//! 2. TLS requires the responder to have an x509 certificate.

// This module uses the `x509-cert` crate to generate certificates;
// if we decide to switch, `rcgen` and `x509-certificate`
// seem like the likeliest options.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use digest::Digest;
use rand::CryptoRng;
use rsa::pkcs8::{EncodePrivateKey as _, SubjectPublicKeyInfo};
use tor_error::into_internal;
use tor_llcrypto::{pk::rsa::KeyPair as RsaKeypair, util::rng::RngCompat};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{DateTime, Encode, asn1::GeneralizedTime, zeroize::Zeroizing},
    ext::pkix::{KeyUsage, KeyUsages},
    serial_number::SerialNumber,
    time::Validity,
};

/// Legacy identity keys are required to have this length.
const EXPECT_ID_BITS: usize = 1024;
/// Legacy identity keys are required to have this exponent.
const EXPECT_ID_EXPONENT: u32 = 65537;
/// Lifetime of generated id certs, in days.
const ID_CERT_LIFETIME_DAYS: u32 = 365;

/// Create an X.509 certificate, for use in a CERTS cell,
/// self-certifying the provided RSA identity key.
///
/// The resulting certificate will be encoded in DER.
/// Its cert_type field should be 02 when it is sent in a CERTS cell.
///
/// The resulting certificate is quite minimal, and has no unnecessary extensions.
///
/// Returns an error on failure, or if `keypair` is not a 1024-bit RSA key
/// with exponent of 65537.
pub fn create_legacy_rsa_id_cert<Rng: CryptoRng>(
    rng: &mut Rng,
    now: SystemTime,
    hostname: &str,
    keypair: &RsaKeypair,
) -> Result<Vec<u8>, X509CertError> {
    use rsa::pkcs1v15::SigningKey;
    use tor_llcrypto::d::Sha256;
    let public = keypair.to_public_key();
    if !public.exponent_is(EXPECT_ID_EXPONENT) {
        return Err(X509CertError::InvalidSigningKey("Invalid exponent".into()));
    }
    if !public.bits() == EXPECT_ID_BITS {
        return Err(X509CertError::InvalidSigningKey(
            "Invalid key length".into(),
        ));
    }

    let self_signed_profile = Profile::Manual { issuer: None };
    let serial_number = random_serial_number(rng)?;
    let (validity, _) = cert_validity(now, ID_CERT_LIFETIME_DAYS)?;
    // NOTE: This is how C Tor builds its DNs, but that doesn't mean it's a good idea.
    let subject: x509_cert::name::Name = format!("CN={hostname}")
        .parse()
        .map_err(X509CertError::InvalidHostname)?;
    let spki = SubjectPublicKeyInfo::from_key(keypair.to_public_key().as_key().clone())?;

    let signer = SigningKey::<Sha256>::new(keypair.as_key().clone());

    let mut builder = CertificateBuilder::new(
        self_signed_profile,
        serial_number,
        validity,
        subject,
        spki,
        &signer,
    )?;

    // We do not, strictly speaking, need this extension: Tor doesn't care that it's there.
    // We do, however, need _some_ extension, or else we'll generate a v1 certificate,
    // which we don't want to do.
    builder.add_extension(&KeyUsage(
        KeyUsages::KeyCertSign | KeyUsages::DigitalSignature,
    ))?;

    let cert = builder.build()?;

    let mut output = Vec::new();
    let _ignore_length: x509_cert::der::Length = cert
        .encode_to_vec(&mut output)
        .map_err(X509CertError::CouldNotEncode)?;
    Ok(output)
}

/// A set of x.509 certificate information and keys for use with a TLS library.
///
/// Only relays need this: They should set these as the certificate(s) to be used
/// for incoming TLS connections.
///
/// This is not necessarily the most convenient form to manipulate certificates in:
/// rather, it is intended to provide the formats that TLS libraries generally
/// expect to get.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TlsKeyAndCert {
    /// A list of certificates in DER form.
    ///
    /// (This may contain more than one certificate, but for now only one certificate is used.)
    certificates: Vec<Vec<u8>>,

    /// A private key for use in the TLS handshake.
    private_key: ecdsa::SigningKey<p256::NistP256>,

    /// A SHA256 digest of the link certificate
    /// (the one certifying the private key's public component).
    ///
    /// This digest is the one what will be certified by the relay's
    /// [`SIGNING_V_TLS_CERT`](crate::CertType::SIGNING_V_TLS_CERT)
    /// certificate.
    sha256_digest: [u8; 32],

    /// A time after which this set of link information won't be valid,
    /// and another should be generated.
    expiration: SystemTime,
}

/// What lifetime do we pick for a TLS certificate, in days?
const TLS_CERT_LIFETIME_DAYS: u32 = 30;

impl TlsKeyAndCert {
    /// Return the certificates as a list of DER-encoded values.
    pub fn certificates_der(&self) -> Vec<&[u8]> {
        self.certificates.iter().map(|der| der.as_ref()).collect()
    }
    /// Return the certificates as a concatenated list in PEM ("BEGIN CERTIFICATE") format.
    pub fn certificate_pem(&self) -> String {
        let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
        self.certificates
            .iter()
            .map(|der| pem::encode_config(&pem::Pem::new("CERTIFICATE", &der[..]), config))
            .collect()
    }
    /// Return the private key in (unencrypted) PKCS8 DER format.
    pub fn private_key_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, X509CertError> {
        Ok(self
            .private_key
            .to_pkcs8_der()
            .map_err(X509CertError::CouldNotFormatPkcs8)?
            .to_bytes())
    }
    /// Return the private key in (unencrypted) PKCS8 PEM ("BEGIN PRIVATE KEY") format.
    pub fn private_key_pkcs8_pem(&self) -> Result<Zeroizing<String>, X509CertError> {
        self.private_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(X509CertError::CouldNotFormatPkcs8)
    }
    /// Return the earliest time at which any of these certificates will expire.
    pub fn expiration(&self) -> SystemTime {
        self.expiration
    }

    /// Return the SHA256 digest of the link certificate
    ///
    /// This digest is the one certified with the relay's
    /// [`SIGNING_V_TLS_CERT`](crate::CertType::SIGNING_V_TLS_CERT)
    /// certificate.
    pub fn link_cert_sha256(&self) -> &[u8; 32] {
        &self.sha256_digest
    }

    /// Create a new TLS link key and associated certificate(s).
    ///
    /// The certificate will be valid at `now`, and for a while after.
    ///
    /// The certificate parameters and keys are chosen for reasonable security,
    /// approximate conformance to RFC5280, and limited fingerprinting resistance.
    ///
    /// Note: The fingerprinting resistance is quite limited.
    /// We will likely want to pursue these avenues for better fingerprinting resistance:
    ///
    /// - Encourage more use of TLS 1.3, where server certificates are encrypted.
    ///   (This prevents passive fingerprinting only.)
    /// - Adjust this function to make certificates look even more normal
    /// - Integrate with ACME-supporting certificate issuers (Letsencrypt, etc)
    ///   to get real certificates for Tor relays.
    pub fn create<Rng: CryptoRng>(
        rng: &mut Rng,
        now: SystemTime,
        issuer_hostname: &str,
        subject_hostname: &str,
    ) -> Result<Self, X509CertError> {
        // We choose to use p256 here as the most commonly used elliptic curve
        // group for X.509 web certificate signing, as of this writing.
        //
        // We want to use an elliptic curve here for its higher security/performance ratio than RSA,
        // and for its _much_ faster key generation time.
        let private_key = p256::ecdsa::SigningKey::random(&mut RngCompat::new(&mut *rng));
        let public_key = p256::ecdsa::VerifyingKey::from(&private_key);

        // Note that we'll discard this key after signing the certificate with it:
        // The real certification for private_key is done in the SIGNING_V_TLS_CERT
        // certificate.
        let issuer_private_key = p256::ecdsa::SigningKey::random(&mut RngCompat::new(&mut *rng));

        // NOTE: This is how C Tor builds its DNs, but that doesn't mean it's a good idea.
        let issuer = format!("CN={issuer_hostname}")
            .parse()
            .map_err(X509CertError::InvalidHostname)?;
        let subject: x509_cert::name::Name = format!("CN={subject_hostname}")
            .parse()
            .map_err(X509CertError::InvalidHostname)?;

        let self_signed_profile = Profile::Leaf {
            issuer,
            enable_key_agreement: true,
            enable_key_encipherment: true,
            include_subject_key_identifier: true,
        };
        let serial_number = random_serial_number(rng)?;
        let (validity, expiration) = cert_validity(now, TLS_CERT_LIFETIME_DAYS)?;
        let spki = SubjectPublicKeyInfo::from_key(public_key)?;

        let builder = CertificateBuilder::new(
            self_signed_profile,
            serial_number,
            validity,
            subject,
            spki,
            &issuer_private_key,
        )?;

        let cert = builder.build::<ecdsa::der::Signature<_>>()?;

        let mut certificate_der = Vec::new();
        let _ignore_length: x509_cert::der::Length = cert
            .encode_to_vec(&mut certificate_der)
            .map_err(X509CertError::CouldNotEncode)?;

        let sha256_digest = tor_llcrypto::d::Sha256::digest(&certificate_der).into();
        let certificates = vec![certificate_der];

        Ok(TlsKeyAndCert {
            certificates,
            private_key,
            sha256_digest,
            expiration,
        })
    }
}

/// Return a Validity that includes `now`, and lasts for `lifetime_days` additionally.
///
/// Additionally, return the time at which the certificate expires.
///
/// We ensure that our cert is valid at least a day into the past.
///
/// We obfuscate our current time a little by rounding to the nearest midnight UTC.
fn cert_validity(
    now: SystemTime,
    lifetime_days: u32,
) -> Result<(Validity, SystemTime), X509CertError> {
    const ONE_DAY: Duration = Duration::new(86400, 0);

    let start_of_day_containing = |when| -> Result<_, X509CertError> {
        let dt = DateTime::from_system_time(when)
            .map_err(into_internal!("Couldn't represent time as a DER DateTime"))?;
        let dt = DateTime::new(dt.year(), dt.month(), dt.day(), 0, 0, 0)
            .map_err(into_internal!("Couldn't construct DER DateTime"))?;
        Ok(x509_cert::time::Time::GeneralTime(
            GeneralizedTime::from_date_time(dt),
        ))
    };

    let start_on_day = now - ONE_DAY;
    let end_on_day = start_on_day + ONE_DAY * lifetime_days;

    let validity = Validity {
        not_before: start_of_day_containing(start_on_day)?,
        not_after: start_of_day_containing(end_on_day)?,
    };
    let expiration = validity.not_after.into();
    Ok((validity, expiration))
}

/// Return a random serial number for use in a new certificate.
fn random_serial_number<Rng: CryptoRng>(rng: &mut Rng) -> Result<SerialNumber, X509CertError> {
    const SER_NUMBER_LEN: usize = 16;
    let mut buf = [0; SER_NUMBER_LEN];
    rng.fill_bytes(&mut buf[..]);
    Ok(SerialNumber::new(&buf[..]).map_err(into_internal!("Couldn't construct serial number!"))?)
}

/// An error that has occurred while trying to create a certificate.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum X509CertError {
    /// We received a signing key that we can't use.
    #[error("Provided signing key not valid: {0}")]
    InvalidSigningKey(String),

    /// We received a subject key that we can't use.
    #[error("Couldn't use provided key as a subject")]
    SubjectKeyError(#[from] x509_cert::spki::Error),

    /// We received a hostname that we couldn't use:
    /// probably, it contained an equals sign or a comma.
    #[error("Unable to set hostname when creating certificate")]
    InvalidHostname(#[source] x509_cert::der::Error),

    /// We couldn't construct the certificate.
    #[error("Unable to build certificate")]
    CouldNotBuild(#[source] Arc<x509_cert::builder::Error>),

    /// We constructed the certificate, but couldn't encode it as DER.
    #[error("Unable to encode certificate")]
    CouldNotEncode(#[source] x509_cert::der::Error),

    /// We constructed a key but couldn't format it as PKCS8.
    #[error("Unable to format key as PKCS8")]
    CouldNotFormatPkcs8(#[source] p256::pkcs8::Error),

    /// We've encountered some kind of a bug.
    #[error("Internal error while creating certificate")]
    Bug(#[from] tor_error::Bug),
}

impl From<x509_cert::builder::Error> for X509CertError {
    fn from(value: x509_cert::builder::Error) -> Self {
        X509CertError::CouldNotBuild(Arc::new(value))
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn identity_cert_generation() {
        let mut rng = testing_rng();
        let keypair = RsaKeypair::generate(&mut rng).unwrap();
        let cert = create_legacy_rsa_id_cert(
            &mut rng,
            SystemTime::now(),
            "www.house-of-pancakes.example.com",
            &keypair,
        )
        .unwrap();

        let key_extracted = tor_llcrypto::util::x509_extract_rsa_subject_kludge(&cert[..]).unwrap();
        assert_eq!(key_extracted, keypair.to_public_key());

        // TODO: It would be neat to validate this certificate with an independent x509 implementation,
        // but afaict most of them sensibly refuse to handle RSA1024.
        //
        // I've checked the above-generated cert using `openssl verify`, but that's it.
    }

    #[test]
    fn tls_cert_info() {
        let mut rng = testing_rng();
        let certified = TlsKeyAndCert::create(
            &mut rng,
            SystemTime::now(),
            "foo.example.com",
            "bar.example.com",
        )
        .unwrap();
        dbg!(certified);
    }
}
