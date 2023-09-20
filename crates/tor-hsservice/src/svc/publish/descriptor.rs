//! Helpers for building and representing hidden service descriptors.

use std::sync::Arc;
use std::time::SystemTime;

use rand_core::{CryptoRng, RngCore};

use tor_cert::Ed25519Cert;
use tor_error::Bug;
use tor_hscrypto::pk::{HsBlindIdKey, HsBlindIdKeypair, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::RevisionCounter;
use tor_llcrypto::pk::curve25519;
use tor_netdoc::doc::hsdesc::{HsDescBuilder, IntroPointDesc};
use tor_netdoc::NetdocBuilder;

use crate::config::DescEncryptionConfig;
use crate::ipt_set::{Ipt, IptSet};
use crate::OnionServiceConfig;

// TODO HSS: Dummy types that should be implemented elsewhere.

/// TODO: add a real x25519 cert type in tor-cert.
#[allow(unreachable_pub)]
#[derive(Clone)]
pub struct X25519Cert;

impl X25519Cert {
    #[allow(unreachable_pub)]
    /// The time when this certificate will expire.
    pub fn expiry(&self) -> SystemTime {
        // TODO
        SystemTime::now()
    }
}

/// Build the descriptor.
///
/// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
/// signing keys (KP_hs_blind_id, KS_hs_blind_id).
#[allow(unreachable_code)] // TODO HSS: remove
#[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
pub(crate) fn build_sign<Rng: RngCore + CryptoRng>(
    config: Arc<OnionServiceConfig>,
    hsid: HsIdKey,
    blind_id_kp: &HsBlindIdKeypair,
    ipt_set: &IptSet,
    period: TimePeriod,
    revision_counter: RevisionCounter,
    rng: &mut Rng,
) -> Result<String, Bug> {
    // TODO HSS: should this be configurable? If so, we should read it from the svc config.
    //
    /// The CREATE handshake type we support.
    const CREATE2_FORMATS: &[u32] = &[1, 2];

    let intro_points = ipt_set
        .ipts
        .iter()
        .map(|ipt_in_set| build_intro_point_desc(&ipt_in_set.ipt))
        .collect::<Vec<_>>();

    let blind_id_key = HsBlindIdKey::from(blind_id_kp);
    let subcredential = hsid.compute_subcredential(&blind_id_key, period);
    // The short-term descriptor signing key (KP_hs_desc_sign, KS_hs_desc_sign).
    // TODO HSS: these should be provided by the KeyMgr.
    let hs_desc_sign = todo!();
    let hs_desc_sign_cert: Ed25519Cert = todo!();
    // TODO HSS: support introduction-layer authentication.
    let auth_required = None;

    let is_single_onion_service =
        matches!(config.anonymity, crate::Anonymity::DangerouslyNonAnonymous);
    let intro_auth_key_cert: Ed25519Cert = todo!();
    let intro_enc_key_cert: X25519Cert = todo!();

    // TODO HSS: Temporarily disabled while we figure out how we want the client auth config to
    // work; see #1028
    /*
    let auth_clients: Vec<curve25519::PublicKey> = match config.encrypt_descriptor {
        Some(auth_clients) => build_auth_clients(&auth_clients),
        None => vec![],
    };
    */

    let auth_clients = vec![];

    Ok(HsDescBuilder::default()
        .blinded_id(blind_id_kp)
        .hs_desc_sign(hs_desc_sign)
        .hs_desc_sign_cert_expiry(hs_desc_sign_cert.expiry())
        .create2_formats(CREATE2_FORMATS)
        .auth_required(auth_required)
        .is_single_onion_service(is_single_onion_service)
        .intro_points(&intro_points[..])
        .intro_auth_key_cert_expiry(intro_auth_key_cert.expiry())
        .intro_enc_key_cert_expiry(intro_enc_key_cert.expiry())
        .lifetime(((ipt_set.lifetime.as_secs() / 60) as u16).into())
        .revision_counter(revision_counter)
        .subcredential(subcredential)
        .auth_clients(&auth_clients)
        .build_sign(rng)?)
}

/// Create an [`IntroPointDesc`] from the specified introduction point.
fn build_intro_point_desc(_ipt: &Ipt) -> IntroPointDesc {
    todo!()
}

/// Return the list of authorized public keys from the specified [`DescEncryptionConfig`].
fn build_auth_clients(_auth_clients: &DescEncryptionConfig) -> Vec<curve25519::PublicKey> {
    todo!()
}

/// The freshness status of a descriptor at a particular HsDir.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub(super) enum DescriptorStatus {
    #[default]
    /// Dirty, needs to be (re)uploaded.
    Dirty,
    /// Clean, does not need to be reuploaded.
    Clean,
}

/// A descriptor and its revision.
pub(super) struct VersionedDescriptor {
    /// The serialized descriptor.
    pub(super) desc: String,
    /// The revision counter.
    pub(super) revision_counter: RevisionCounter,
}
