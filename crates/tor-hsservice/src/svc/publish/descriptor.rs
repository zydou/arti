//! Helpers for building and representing hidden service descriptors.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rand_core::{CryptoRng, RngCore};

use tor_hscrypto::pk::{HsBlindIdKey, HsBlindIdKeypair, HsDescSigningKeypair, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::RevisionCounter;
use tor_keymgr::{KeyMgr, ToEncodableKey};
use tor_llcrypto::pk::curve25519;
use tor_netdoc::doc::hsdesc::HsDescBuilder;
use tor_netdoc::NetdocBuilder;

use crate::config::DescEncryptionConfig;
use crate::ipt_set::IptSet;
use crate::svc::publish::reactor::ReactorError;
use crate::{HsNickname, HsSvcKeyRole, HsSvcKeySpecifier, OnionServiceConfig};

// TODO HSS: Dummy types that should be implemented elsewhere.

/// Build the descriptor.
///
/// The `now` argument is used for computing the expiry of the `intro_{auth, enc}_key_cert`
/// certificates included in the descriptor. The expiry will be set to 54 hours from `now`.
///
/// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
/// signing keys (KP_hs_blind_id, KS_hs_blind_id).
pub(crate) fn build_sign<Rng: RngCore + CryptoRng>(
    keymgr: Arc<KeyMgr>,
    config: Arc<OnionServiceConfig>,
    ipt_set: &IptSet,
    period: TimePeriod,
    revision_counter: RevisionCounter,
    rng: &mut Rng,
    now: SystemTime,
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
        .map(|ipt_in_set| ipt_in_set.ipt.clone())
        .collect::<Vec<_>>();

    let nickname = &config.nickname;

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

    // TODO HSS: support introduction-layer authentication.
    let auth_required = None;

    let is_single_onion_service =
        matches!(config.anonymity, crate::Anonymity::DangerouslyNonAnonymous);

    // TODO HSS: perhaps the certificates should be read from the keystore, rather than created
    // when building the descriptor. See #1048
    let intro_auth_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let intro_enc_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let hs_desc_sign_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;

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
        .hs_desc_sign_cert_expiry(hs_desc_sign_cert_expiry)
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
    nickname: &HsNickname,
    role: HsSvcKeyRole,
) -> Result<K, ReactorError>
where
    K: ToEncodableKey,
{
    let svc_key_spec = HsSvcKeySpecifier::new(nickname, role);

    // TODO HSS: most of the time, we don't want to return a MissingKey error. Generally, if a
    // key/cert is missing, we should try to generate it, and only return MissingKey if generating
    // the key is not possible. This can happen, for example, if we have to generate and
    // cross-certify a key, but we're missing the signing key (e.g. if we're trying to generate
    // `hs_desc_sign_cert`, but we don't have a corresponding `hs_blind_id` key in the keystore).
    // It can also happen if, for example, if we need to generate a new blind_hs_id, but the
    // KS_hs_id is stored offline (not that if both KS_hs_id and KP_hs_id are missing from the
    // keystore, we would just generate a new hs_id keypair, rather than return a MissingKey error
    // -- TODO HSS: decide if this is the correct behaviour!)
    //
    // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1615#note_2946313
    keymgr
        .get::<K>(&svc_key_spec)?
        .ok_or_else(|| ReactorError::MissingKey(role))
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
