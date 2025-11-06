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

use rand::CryptoRng;
use rsa::pkcs8::SubjectPublicKeyInfo;
use tor_error::into_internal;
use tor_llcrypto::pk::rsa::KeyPair as RsaKeypair;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::{DateTime, Encode, asn1::GeneralizedTime},
    ext::pkix::{KeyUsage, KeyUsages},
    serial_number::SerialNumber,
    time::Validity,
};

/// Legacy identity keys are required to have this length.
const EXPECT_ID_BITS: usize = 1024;
/// Legacy identity keys are required to
const EXPECT_ID_EXPONENT: u32 = 65537;

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
    let serial_number = {
        const SER_NUMBER_LEN: usize = 16;
        let mut buf = [0; SER_NUMBER_LEN];
        rng.fill_bytes(&mut buf[..]);
        SerialNumber::new(&buf[..]).map_err(into_internal!("Couldn't construct serial number!"))?
    };
    let validity = identity_cert_validity(now)?;
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

// TODO: We'll need a method to generate a certificate or two for use with TLS.

/// Return a Validity for an identity certificate generated at `now`.
///
/// We ensure that our cert is valid at least a day into the past,
/// and about a year into the future.
///
/// We obfuscate our current time a little by rounding to the nearest midnight.
fn identity_cert_validity(now: SystemTime) -> Result<Validity, X509CertError> {
    let (year, month, day) = {
        let start_day = now - Duration::new(86400, 0);
        let dt = x509_cert::der::DateTime::from_system_time(start_day).map_err(into_internal!(
            "Couldn't represent our time as a DER DateTime"
        ))?;
        (dt.year(), dt.month(), dt.day())
    };
    let time = |year, month, day| -> Result<_, X509CertError> {
        {
            let date_time = DateTime::new(
                year, month, day, 0, // hour
                0, // minutes
                0, // seconds
            )
            .map_err(into_internal!("Could not construct start date"))?;
            Ok(x509_cert::time::Time::GeneralTime(
                GeneralizedTime::from_date_time(date_time),
            ))
        }
    };
    Ok(Validity {
        not_before: time(year, month, day)?,
        not_after: time(year + 1, month, day)?,
    })
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
}
