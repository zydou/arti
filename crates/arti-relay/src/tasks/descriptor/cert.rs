//! Code to help with building certificate going in the router descriptor.
//!
//! This is not a lot of code but it helps for a better modular mental model of all the
//! code needed for building descriptors.

use anyhow::Context;

use tor_cert::KeyUnknownCert;
use tor_checkable::TimeBound as _;
use tor_key_forge::ToEncodableCert as _;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdoc::types::{Ed25519IdentityCert, EmbeddedCert};
use tor_relay_crypto::RelaySigningKeyCert;
use web_time_compat::SystemTime;

/// Build an embedded identity certificate.
///
/// This verifies the generated certificate against the given time and identity.
pub(super) fn build_identity_cert(
    cert: RelaySigningKeyCert,
    identity: Ed25519Identity,
    now: SystemTime,
) -> anyhow::Result<EmbeddedCert<Ed25519IdentityCert, KeyUnknownCert>> {
    let signing_cert = tor_cert::Ed25519Cert::decode(&cert.to_encodable_cert())
        .context("Failed to decode relay signing cert")?;
    let identity_cert = Ed25519IdentityCert::verify(signing_cert.clone())
        .context("Failed to verify relay signing cert")?
        .if_valid_at(&now)
        .context("Relay signing cert is not valid at publication time")?;
    anyhow::ensure!(
        identity_cert.id_ed25519 == identity,
        "Relay signing cert does not match relay identity"
    );
    Ok(EmbeddedCert::new(identity_cert, signing_cert))
}
