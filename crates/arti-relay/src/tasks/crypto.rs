//! Key rotation tasks of the relay.

use anyhow::Context;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tor_basic_utils::rand_hostname;
use tor_cert::x509::TlsKeyAndCert;
use tor_chanmgr::ChanMgr;
use tor_error::internal;
use tor_key_forge::ToEncodableCert;
use tor_keymgr::{
    CertSpecifierPattern, KeyCertificateSpecifier, KeyMgr, KeyPath, KeySpecifier,
    KeySpecifierPattern, Keygen, KeystoreSelector, ToEncodableKey,
};
use tor_proto::RelayIdentities;
use tor_relay_crypto::{
    RelaySigningKeyCert, gen_link_cert, gen_signing_cert, gen_tls_cert,
    pk::{
        RelayIdentityKeypair, RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypair,
        RelayIdentityRsaKeypairSpecifier, RelayLinkSigningKeypair,
        RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
        RelaySigningKeyCertSpecifier, RelaySigningKeyCertSpecifierPattern, RelaySigningKeypair,
        RelaySigningKeypairSpecifier, RelaySigningKeypairSpecifierPattern,
        RelaySigningPublicKeySpecifier, Timestamp,
    },
};
use tor_rtcompat::{Runtime, SleepProviderExt};

/// Buffer time before key expiry to trigger rotation. This ensures we rotate slightly before the
/// key actually expires rather than right at or after expiry.
///
/// C-tor uses 3 hours for the link/auth key and 1 day for the signing key. Let's use 3 hours here,
/// it should be plenty to make it happen even if hiccups happen.
const KEY_ROTATION_EXPIRE_BUFFER: Duration = Duration::from_secs(3 * 60 * 60);

/// Key lifefime duration of 2 days
const KEY_DURATION_2DAYS: Duration = Duration::from_secs(2 * 24 * 60 * 60);
/// Key lifefime duration of 30 days
const KEY_DURATION_30DAYS: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Key lifefime duration of 6 months
const KEY_DURATION_6MONTHS: Duration = Duration::from_secs(6 * 30 * 24 * 60 * 60);

/// Build a fresh [`RelayIdentities`] object using a [`KeyMgr`].
///
/// Every single certificate is generated in this function.
///
/// This function assumes that all required keys are in the keymgr.
fn build_proto_identities(keymgr: &KeyMgr) -> anyhow::Result<RelayIdentities> {
    let mut rng = tor_llcrypto::rng::CautiousRng;
    let now = SystemTime::now();

    // Get the identity keypairs.
    let rsa_id_kp: RelayIdentityRsaKeypair = keymgr
        .get(&RelayIdentityRsaKeypairSpecifier::new())
        .context("Failed to get RSA identity from key manager")?
        .context("Missing RSA identity")?;
    let ed_id_kp: RelayIdentityKeypair = keymgr
        .get(&RelayIdentityKeypairSpecifier::new())
        .context("Failed to get Ed25519 identity from key manager")?
        .context("Missing Ed25519 identity")?;
    // We have to list match here because the key specifier here uses a valid_until. We don't know
    // what it is so we list and take the first one.
    let link_sign_kp: RelayLinkSigningKeypair = keymgr
        .get_entry(
            keymgr
                .list_matching(&RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
                .first()
                .context("No store entry for link authentication key")?,
        )
        .context("Failed to get link authentication key from key manager")?
        .context("Missing link authentication key")?;
    let kp_relaysign_id: RelaySigningKeypair = keymgr
        .get_entry(
            keymgr
                .list_matching(&RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
                .first()
                .context("No store entry for signing key")?,
        )
        .context("Failed to get signing key from key manager")?
        .context("Missing signing key")?;

    // TLS key and cert. Random hostname like C-tor. We re-use the issuer_hostname for the RSA
    // legacy cert.
    let issuer_hostname = rand_hostname::random_hostname(&mut rng);
    let subject_hostname = rand_hostname::random_hostname(&mut rng);
    let tls_key_and_cert =
        TlsKeyAndCert::create(&mut rng, now, &issuer_hostname, &subject_hostname)
            .context("Failed to create TLS keys and certificates")?;

    // Create the RSA X509 certificate.
    let cert_id_x509_rsa = tor_cert::x509::create_legacy_rsa_id_cert(
        &mut rng,
        SystemTime::now(),
        &issuer_hostname,
        rsa_id_kp.keypair(),
    )
    .context("Failed to create legacy RSA identity certificate")?;

    // The following expiry duration have been taken from C-tor.

    let cert_id_rsa = tor_cert::rsa::EncodedRsaCrosscert::encode_and_sign(
        rsa_id_kp.keypair(),
        &ed_id_kp.to_ed25519_id(),
        now + KEY_DURATION_6MONTHS,
    )?;

    // Create the signing key cert, link cert and tls cert.
    //
    // TODO(relay): We need to check the KeyMgr for the signing cert but for now the KeyMgr API
    // doesn't allow us to get it out. We will do a re-design of the cert API there. This is fine
    // as long as we don't support offline keys.
    let cert_id_sign_ed = gen_signing_cert(&ed_id_kp, &kp_relaysign_id, now + KEY_DURATION_30DAYS)?;
    let cert_sign_link_auth_ed =
        gen_link_cert(&kp_relaysign_id, &link_sign_kp, now + KEY_DURATION_2DAYS)?;
    let cert_sign_tls_ed = gen_tls_cert(
        &kp_relaysign_id,
        *tls_key_and_cert.link_cert_sha256(),
        now + KEY_DURATION_2DAYS,
    )?;

    Ok(RelayIdentities::new(
        &rsa_id_kp.public().into(),
        ed_id_kp.to_ed25519_id(),
        link_sign_kp,
        cert_id_sign_ed.to_encodable_cert(),
        cert_sign_tls_ed,
        cert_sign_link_auth_ed.to_encodable_cert(),
        cert_id_x509_rsa,
        cert_id_rsa,
        tls_key_and_cert,
    ))
}

/// Generate a key `K` directly into the key manager.
///
/// If the key already exists, the error is ignored as this could happen if the system time drifts
/// between the get and the generate.
fn generate_key<K>(keymgr: &KeyMgr, spec: &dyn KeySpecifier) -> Result<(), tor_keymgr::Error>
where
    K: ToEncodableKey,
    K::Key: Keygen,
{
    let mut rng = tor_llcrypto::rng::CautiousRng;

    match keymgr.generate::<K>(spec, KeystoreSelector::default(), &mut rng, false) {
        Ok(_) => {}
        // Key already existing can happen due to wall clock strangeness,
        // so simply ignore it.
        Err(tor_keymgr::Error::KeyAlreadyExists) => (),
        Err(e) => return Err(e),
    };
    Ok(())
}

/// Go through keystore entries matching `pattern` and remove any that are within
/// [`KEY_ROTATION_EXPIRE_BUFFER`] of expiry.
///
/// Returns `(removed, min_remaining)` where `removed` indicates whether any entry was deleted and
/// `min_remaining` is the minimum `valid_until` of the entries that were kept (if any).
fn remove_expired<F>(
    keymgr: &KeyMgr,
    pattern: &tor_keymgr::KeyPathPattern,
    label: &'static str,
    expiry_from_keypath: F,
) -> anyhow::Result<(bool, Option<SystemTime>)>
where
    F: Fn(&KeyPath) -> anyhow::Result<Timestamp>,
{
    let entries = keymgr.list_matching(pattern)?;
    let mut removed = false;
    let mut min_valid_until: Option<Timestamp> = None;

    for entry in entries {
        let valid_until = expiry_from_keypath(entry.key_path())?;
        if valid_until <= Timestamp::from(SystemTime::now() + KEY_ROTATION_EXPIRE_BUFFER) {
            tracing::debug!("Expired {} in keymgr. Removing it.", label);
            keymgr.remove_entry(&entry)?;
            removed = true;
        } else {
            min_valid_until =
                Some(min_valid_until.map_or(valid_until, |current| current.min(valid_until)));
        }
    }

    Ok((removed, min_valid_until.map(SystemTime::from)))
}

/// Attempt to generate a key using the given [`KeySpecifier`].
///
/// Return true if generated else false.
fn try_generate_key<K, P>(keymgr: &KeyMgr, spec: &dyn KeySpecifier) -> anyhow::Result<bool>
where
    K: ToEncodableKey,
    K::Key: Keygen,
    P: KeySpecifierPattern,
{
    let mut generated = false;
    let mut rng = tor_llcrypto::rng::CautiousRng;
    let entries = keymgr.list_matching(&P::new_any().arti_pattern()?)?;
    if entries.is_empty() {
        let _ = keymgr.get_or_generate::<K>(spec, KeystoreSelector::default(), &mut rng)?;
        generated = true;
    }

    Ok(generated)
}

/// Attempt to generate a key and cert using the given [`KeyCertificateSpecifier`] which is signed
/// by the given [`KeySpecifier]` in `signing_key_spec`.
///
/// The `make_certificate` is used to generate the certificate stored in the [`KeyMgr`].
///
/// Return true if generated else false.
fn try_generate_key_cert<K, C, P>(
    keymgr: &KeyMgr,
    cert_spec: &dyn KeyCertificateSpecifier,
    signing_key_spec: &dyn KeySpecifier,
    make_certificate: impl FnOnce(&K, &<C as ToEncodableCert<K>>::SigningKey) -> C,
) -> anyhow::Result<bool>
where
    K: ToEncodableKey,
    K::Key: Keygen,
    C: ToEncodableCert<K>,
    P: CertSpecifierPattern,
{
    let mut generated = false;
    let mut rng = tor_llcrypto::rng::CautiousRng;
    let entries = keymgr.list_matching(&P::new_any().arti_pattern()?)?;
    if entries.is_empty() {
        let _ = keymgr.get_or_generate_key_and_cert::<K, C>(
            cert_spec,
            signing_key_spec,
            make_certificate,
            KeystoreSelector::default(),
            &mut rng,
        )?;
        generated = true;
    }

    Ok(generated)
}

/// Try to generate all keys and certs needed for a relay.
///
/// This tries to generate the [`RelayLinkSigningKeypair`] and the [`RelaySigningKeypair`] +
/// [`RelaySigningKeyCert`]. Note that identity keys are NOT generated within this function, it is
/// only attempted once at boot time. This is so we avoid retrying to generate them at each key
/// rotation as those identity keys never rotate.
///
/// Returns the minimum valid until value if a key was generated. Else, a None value indicates that
/// no key was generated.
fn try_generate_all(keymgr: &KeyMgr) -> anyhow::Result<Option<SystemTime>> {
    let link_expiry = SystemTime::now() + KEY_DURATION_2DAYS;
    let link_spec = RelayLinkSigningKeypairSpecifier::new(Timestamp::from(link_expiry));
    let link_generated = try_generate_key::<
        RelayLinkSigningKeypair,
        RelayLinkSigningKeypairSpecifierPattern,
    >(keymgr, &link_spec)?;

    fn make_signing_cert(
        subject_key: &RelaySigningKeypair,
        signing_key: &RelayIdentityKeypair,
    ) -> RelaySigningKeyCert {
        gen_signing_cert(
            signing_key,
            subject_key,
            SystemTime::now() + KEY_DURATION_30DAYS,
        )
        .expect("failed to generate relay signing cert")
    }

    let cert_expiry = SystemTime::now() + KEY_DURATION_30DAYS;
    // We either get the existing one or generate this new one.
    let cert_spec = RelaySigningKeyCertSpecifier::new(RelaySigningPublicKeySpecifier::new(
        Timestamp::from(cert_expiry),
    ));
    let cert_generated = try_generate_key_cert::<
        RelaySigningKeypair,
        RelaySigningKeyCert,
        RelaySigningKeyCertSpecifierPattern,
    >(
        keymgr,
        &cert_spec,
        &RelayIdentityKeypairSpecifier::new(),
        make_signing_cert,
    )?;

    Ok([
        link_generated.then_some(link_expiry),
        cert_generated.then_some(cert_expiry),
    ]
    .into_iter()
    .flatten()
    .min())
}

/// Remove any expired keys (and certs) that are expired.
///
/// Return (`removed`, `next_expiry`) where the `removed` indicates if at least one key has been
/// removed because it was expired. The `next_expiry` is the minimum value of all valid_until which
/// indicates the next closest expiry time.
fn remove_expired_keys(keymgr: &KeyMgr) -> anyhow::Result<(bool, Option<SystemTime>)> {
    let (relaysign_removed, relaysign_expiry) = remove_expired(
        keymgr,
        &RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_relaysign_ed",
        |key_path| Ok(RelaySigningKeypairSpecifier::try_from(key_path)?.valid_until()),
    )?;
    let (link_removed, link_expiry) = remove_expired(
        keymgr,
        &RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_link_ed",
        |key_path| Ok(RelayLinkSigningKeypairSpecifier::try_from(key_path)?.valid_until()),
    )?;

    // This should always be removed if the signing key above has been removed. However, we still
    // do a pass at the keystore considering the upcoming offline key feature that might have more
    // than one expired cert in the keystore.
    let (sign_cert_removed, sign_cert_expiry) = remove_expired(
        keymgr,
        &RelaySigningKeyCertSpecifierPattern::new_any().arti_pattern()?,
        "signing key cert",
        |key_path| {
            let spec: RelaySigningKeyCertSpecifier = key_path.try_into()?;
            let subject_key_path = KeyPath::Arti(spec.subject_key_specifier().arti_path()?);
            let subject_key_spec: RelaySigningPublicKeySpecifier =
                (&subject_key_path).try_into()?;
            Ok(subject_key_spec.valid_until())
        },
    )?;

    // Have we at least removed one?
    let removed = relaysign_removed || link_removed || sign_cert_removed;

    let next_expiry = [relaysign_expiry, link_expiry, sign_cert_expiry]
        .into_iter()
        .flatten()
        .min();

    Ok((removed, next_expiry))
}

/// Attempt to rotate all keys except identity keys.
///
/// Returns (rotated, next_expiry) where `rotated` indicates if any key was rotated and
/// `next_expiry` is the earliest expiry time across all keys.
fn try_rotate_keys(keymgr: &KeyMgr) -> anyhow::Result<(bool, SystemTime)> {
    // First do a pass to remove every expired key(s) or/and cert(s).
    let (have_rotated, min_expiry) = remove_expired_keys(keymgr)?;

    // Then attempt to generate keys. If at least one was generated, we'll get the min expiry time
    // which we need to consider "rotated" so the caller can know that a new key appeared.
    let gen_min_expiry = try_generate_all(keymgr)?;
    let have_rotated = have_rotated || gen_min_expiry.is_some();

    // We should never get no expiry time.
    let next_expiry = [min_expiry, gen_min_expiry]
        .into_iter()
        .flatten()
        .min()
        .ok_or(internal!("No relay keys after rotation task loop"))?;

    Ok((have_rotated, next_expiry))
}

/// Attempt to generate all keys. The list of keys is:
///
/// * Identity Ed25519 keypair [`RelayIdentityKeypair`].
/// * Identity RSA [`RelayIdentityRsaKeypair`].
/// * Relay signing keypair [`RelaySigningKeypair`].
/// * Relay link signing keypair [`RelayLinkSigningKeypair`].
///
/// This function is only called when our relay bootstraps in order to attempt to generate any
/// missing keys or/and rotate expired keys.
pub(crate) fn try_generate_keys(keymgr: &KeyMgr) -> anyhow::Result<RelayIdentities> {
    // Attempt to generate our identity keys (ed and RSA). Those keys DO NOT rotate. It won't be
    // replaced if they already exists.
    generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())?;
    generate_key::<RelayIdentityRsaKeypair>(keymgr, &RelayIdentityRsaKeypairSpecifier::new())?;

    // Attempt to rotate the keys. Any missing keys (and cert) will be generated.
    let _ = try_rotate_keys(keymgr)?;

    // Now that we have our up-to-date keys, build the RelayIdentities object.
    build_proto_identities(keymgr)
}

/// Task to rotate keys when they need to be rotated.
pub(crate) async fn rotate_keys_task<R: Runtime>(
    runtime: R,
    keymgr: Arc<KeyMgr>,
    chanmgr: Arc<ChanMgr<R>>,
) -> anyhow::Result<void::Void> {
    loop {
        // Attempt a rotation of all keys.
        let (have_rotated, next_expiry) = try_rotate_keys(&keymgr)?;
        if have_rotated {
            let ids = build_proto_identities(&keymgr)?;
            chanmgr
                .set_relay_identities(Arc::new(ids))
                .context("Failed to set relay identities on ChanMgr")?;
        }

        // Sleep until the earliest key expiry minus buffer so we rotate before it expires.
        // If the subtraction would underflow, wake up immediately to rotate the expired key.
        let next_wake = next_expiry
            .checked_sub(KEY_ROTATION_EXPIRE_BUFFER)
            .unwrap_or(SystemTime::now());
        runtime.sleep_until_wallclock(next_wake).await;
    }
}
