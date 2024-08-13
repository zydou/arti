//! Helpers for building and representing hidden service descriptors.

use super::*;
use crate::config::OnionServiceConfigPublisherView;
use tor_cell::chancell::msg::HandshakeType;

/// Build the descriptor.
///
/// The `now` argument is used for computing the expiry of the `intro_{auth, enc}_key_cert`
/// certificates included in the descriptor. The expiry will be set to 54 hours from `now`.
///
/// Note: `blind_id_kp` is the blinded hidden service signing keypair used to sign descriptor
/// signing keys (KP_hs_blind_id, KS_hs_blind_id).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_sign<Rng: RngCore + CryptoRng>(
    keymgr: &Arc<KeyMgr>,
    config: &Arc<OnionServiceConfigPublisherView>,
    authorized_clients: &Arc<Mutex<Option<RestrictedDiscoveryKeys>>>,
    ipt_set: &IptSet,
    period: TimePeriod,
    revision_counter: RevisionCounter,
    rng: &mut Rng,
    now: SystemTime,
) -> Result<VersionedDescriptor, FatalError> {
    // TODO: should this be configurable? If so, we should read it from the svc config.
    //
    /// The CREATE handshake type we support.
    const CREATE2_FORMATS: &[HandshakeType] = &[HandshakeType::NTOR];

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

    let svc_key_spec = HsIdKeypairSpecifier::new(nickname.clone());
    let hsid_kp = keymgr
        .get::<HsIdKeypair>(&svc_key_spec)?
        .ok_or_else(|| FatalError::MissingHsIdKeypair(nickname.clone()))?;
    let hsid = HsIdKey::from(&hsid_kp);

    // TODO: make the keystore selector configurable
    let keystore_selector = Default::default();
    let blind_id_kp = read_blind_id_keypair(keymgr, nickname, period)?
        .ok_or_else(|| internal!("hidden service offline mode not supported"))?;

    let blind_id_key = HsBlindIdKey::from(&blind_id_kp);
    let subcredential = hsid.compute_subcredential(&blind_id_key, period);

    let hs_desc_sign_key_spec = DescSigningKeypairSpecifier::new(nickname.clone(), period);
    let hs_desc_sign = keymgr.get_or_generate::<HsDescSigningKeypair>(
        &hs_desc_sign_key_spec,
        keystore_selector,
        rng,
    )?;

    // TODO #1028: support introduction-layer authentication.
    let auth_required = None;

    let is_single_onion_service =
        matches!(config.anonymity, crate::Anonymity::DangerouslyNonAnonymous);

    // TODO (#955): perhaps the certificates should be read from the keystore, rather than created
    // when building the descriptor. See #1048
    let intro_auth_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let intro_enc_key_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;
    let hs_desc_sign_cert_expiry = now + HS_DESC_CERT_LIFETIME_SEC;

    cfg_if::cfg_if! {
        if #[cfg(feature = "restricted-discovery")] {
            let authorized_clients = authorized_clients.lock().expect("lock poisoned");
            let auth_clients: Option<Vec<curve25519::PublicKey>> = authorized_clients
                .as_ref()
                .map(|authorized_clients| {
                    if authorized_clients.is_empty() {
                        return Err(FatalError::RestrictedDiscoveryNoClients);
                    }
                    let auth_clients = authorized_clients
                        .iter()
                        .map(|(nickname, key)| {
                            trace!("encrypting descriptor for client {nickname}");
                            (*key).clone().into()
                        })
                        .collect_vec();
                    Ok(auth_clients)
                })
                .transpose()?;
        } else {
            let auth_clients: Option<Vec<curve25519::PublicKey>> = None;
        }
    }

    if let Some(ref auth_clients) = auth_clients {
        debug!("Encrypting descriptor for {} clients", auth_clients.len());
    }

    let desc_signing_key_cert = create_desc_sign_key_cert(
        &hs_desc_sign.as_ref().verifying_key(),
        &blind_id_kp,
        hs_desc_sign_cert_expiry,
    )
    .map_err(into_bad_api_usage!(
        "failed to sign the descriptor signing key"
    ))?;

    let desc = HsDescBuilder::default()
        .blinded_id(&(&blind_id_kp).into())
        .hs_desc_sign(hs_desc_sign.as_ref())
        .hs_desc_sign_cert(desc_signing_key_cert)
        .create2_formats(CREATE2_FORMATS)
        .auth_required(auth_required)
        .is_single_onion_service(is_single_onion_service)
        .intro_points(&intro_points[..])
        .intro_auth_key_cert_expiry(intro_auth_key_cert_expiry)
        .intro_enc_key_cert_expiry(intro_enc_key_cert_expiry)
        .lifetime(((ipt_set.lifetime.as_secs() / 60) as u16).into())
        .revision_counter(revision_counter)
        .subcredential(subcredential)
        .auth_clients(auth_clients.as_deref())
        .build_sign(rng)
        .map_err(|e| into_internal!("failed to build descriptor")(e))?;

    Ok(VersionedDescriptor {
        desc,
        revision_counter,
    })
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
#[derive(Clone)]
pub(super) struct VersionedDescriptor {
    /// The serialized descriptor.
    pub(super) desc: String,
    /// The revision counter.
    pub(super) revision_counter: RevisionCounter,
}
