//! Helpers for building and representing hidden service descriptors.

use std::sync::Arc;
use std::time::Duration;

use rand_core::{CryptoRng, RngCore};

use tor_cert::Ed25519Cert;
use tor_hscrypto::pk::{HsBlindIdKey, HsBlindIdKeypair, HsDescSigningKeypair, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::RevisionCounter;
use tor_keymgr::{KeyMgr, ToEncodableKey};
use tor_llcrypto::pk::curve25519;
use tor_netdoc::doc::hsdesc::{HsDescBuilder, IntroPointDesc};
use tor_netdoc::NetdocBuilder;
use tor_rtcompat::Runtime;

use crate::config::DescEncryptionConfig;
use crate::ipt_set::{Ipt, IptSet};
use crate::svc::keys::{HsSvcKeyRole, HsSvcKeySpecifier};
use crate::svc::publish::reactor::ReactorError;
use crate::{HsNickname, OnionServiceConfig};

// TODO HSS: Dummy types that should be implemented elsewhere.

/// Build the descriptor.
///
/// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
/// signing keys (KP_hs_blind_id, KS_hs_blind_id).
#[allow(unreachable_code)] // TODO HSS: remove
#[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
pub(crate) fn build_sign<R: Runtime, Rng: RngCore + CryptoRng>(
    keymgr: Arc<KeyMgr>,
    config: Arc<OnionServiceConfig>,
    ipt_set: &IptSet,
    period: TimePeriod,
    revision_counter: RevisionCounter,
    rng: &mut Rng,
    runtime: R,
) -> Result<String, ReactorError> {
    // TODO HSS: should this be configurable? If so, we should read it from the svc config.
    //
    /// The CREATE handshake type we support.
    const CREATE2_FORMATS: &[u32] = &[1, 2];

    /// Lifetime of the intro_{auth, enc}_key_cert certificates in the descriptor.
    ///
    /// From C-Tor src/feature/hs/hs_descriptor.h:
    ///
    /// "This defines the lifetime of the descriptor signing key and the cross certification cert of
    /// that key. It is set to 54 hours because a descriptor can be around for 48 hours and because
    /// consensuses are used after the hour, add an extra 6 hours to give some time for the service
    /// to stop using it."
    const HS_DESC_CERT_LIFETIME_SEC: Duration = Duration::from_secs(54 * 60 * 60);

    let intro_points = ipt_set
        .ipts
        .iter()
        .map(|ipt_in_set| build_intro_point_desc(&ipt_in_set.ipt))
        .collect::<Vec<_>>();

    let nickname = todo!();

    let hsid = read_svc_key::<HsIdKey>(&keymgr, nickname, HsSvcKeyRole::HsIdPublicKey)?;
    let blind_id_kp =
        read_svc_key::<HsBlindIdKeypair>(&keymgr, nickname, HsSvcKeyRole::BlindIdKeypair(period))?;
    let blind_id_key = HsBlindIdKey::from(&blind_id_kp);
    let subcredential = hsid.compute_subcredential(&blind_id_key, period);

    // The short-term descriptor signing key (KP_hs_desc_sign, KS_hs_desc_sign).
    // TODO HSS: these should be provided by the KeyMgr.
    let hs_desc_sign = read_svc_key::<HsDescSigningKeypair>(
        &keymgr,
        nickname,
        HsSvcKeyRole::DescSigningKeypair(period),
    )?;
    let hs_desc_sign_cert: Ed25519Cert = todo!();

    // TODO HSS: support introduction-layer authentication.
    let auth_required = None;

    let is_single_onion_service =
        matches!(config.anonymity, crate::Anonymity::DangerouslyNonAnonymous);

    let now = runtime.wallclock();
    let intro_auth_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let intro_enc_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;

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
        .blinded_id(&blind_id_kp)
        .hs_desc_sign(&hs_desc_sign.into())
        .hs_desc_sign_cert_expiry(hs_desc_sign_cert.expiry())
        .create2_formats(CREATE2_FORMATS)
        .auth_required(auth_required)
        .is_single_onion_service(is_single_onion_service)
        .intro_points(&intro_points[..])
        .intro_auth_key_cert_expiry(intro_auth_key_cert_expiry)
        .intro_enc_key_cert_expiry(intro_enc_key_cert_expiry)
        .lifetime(((ipt_set.lifetime.as_secs() / 60) as u16).into())
        .revision_counter(revision_counter)
        .subcredential(subcredential)
        .auth_clients(&auth_clients)
        .build_sign(rng)?)
}

/// Read the specified key from the keystore.
fn read_svc_key<K>(
    keymgr: &Arc<KeyMgr>,
    nickname: HsNickname,
    role: HsSvcKeyRole,
) -> Result<K, ReactorError>
where
    K: ToEncodableKey,
{
    let svc_key_spec = HsSvcKeySpecifier::new(nickname, role);

    keymgr
        .get::<K>(&svc_key_spec)?
        .ok_or_else(|| ReactorError::MissingKey(role))
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
