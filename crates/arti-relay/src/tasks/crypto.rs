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
    KeySpecifierPattern, Keygen, KeystoreEntry, KeystoreSelector, ToEncodableKey,
};
use tor_proto::RelayChannelAuthMaterial;
use tor_relay_crypto::{RelaySigningKeyCert, gen_link_cert, gen_signing_cert, gen_tls_cert};

use crate::keys::{
    RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier,
    RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
    RelayNtorKeypairSpecifier, RelayNtorKeypairSpecifierPattern, RelaySigningKeyCertSpecifier,
    RelaySigningKeyCertSpecifierPattern, RelaySigningKeypairSpecifier,
    RelaySigningKeypairSpecifierPattern, RelaySigningPublicKeySpecifier, Timestamp,
};
use tor_relay_crypto::pk::{
    RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayLinkSigningKeypair, RelayNtorKeypair,
    RelaySigningKeypair,
};
use tor_rtcompat::{Runtime, SleepProviderExt};

/// Buffer time before key expiry to trigger rotation. This ensures we rotate slightly before the
/// key actually expires rather than right at or after expiry.
///
/// C-tor uses 3 hours for the link/auth key and 1 day for the signing key. Let's use 3 hours here,
/// it should be plenty to make it happen even if hiccups happen.
const KEY_ROTATION_EXPIRE_BUFFER: Duration = Duration::from_secs(3 * 60 * 60);

// The following expiry durations have been taken from C-tor.

/// Lifetime of the link authentication key (KP_link_ed) certificate.
const LINK_CERT_LIFETIME: Duration = Duration::from_secs(2 * 24 * 60 * 60);
/// Lifetime of the relay signing key (KP_relaysign_ed) certificate.
const SIGNING_KEY_CERT_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Lifetime of the RSA identity key certificate.
const RSA_CROSSCERT_LIFETIME: Duration = Duration::from_secs(6 * 30 * 24 * 60 * 60);
/// Lifetime of the ntor circuit extension key (KP_ntor).
///
// TODO(relay): we should be using the "onion-key-rotation-days" consensus param
// instead of this hard-coded value.
const NTOR_KEY_LIFETIME: Duration = Duration::from_secs(28 * 24 * 60 * 60);

/// Default grace period for acceptance of an onion key (KP_ntor).
///
/// This represents the amount of time we are still willing to use this key
/// after it expires.
///
// TODO(relay): we should be using the "onion-key-grace-period-days" consensus param
// instead of this hard-coded value.
const NTOR_KEY_GRACE_PERIOD: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The result of an action that affects the relay keys in the keystore.
#[derive(Copy, Clone, Debug)]
struct KeyChange {
    /// Whether the chan auth material has changed.
    chan_auth: bool,
    /// Whether the ntor keys have changed.
    ntor: bool,
}

impl KeyChange {
    /// The combined result of two [`KeyChange`]s.
    fn or(&self, other: &KeyChange) -> KeyChange {
        KeyChange {
            chan_auth: self.chan_auth || other.chan_auth,
            ntor: self.ntor || other.ntor,
        }
    }
}

/// Build a fresh [`RelayChannelAuthMaterial`] object using a [`KeyMgr`].
///
/// The link cert and TLS certs are created in this function.
/// The signing key certificate is retrieved from the keymgr.
///
/// This function assumes that all required keys,
/// as well as the signing key certificate,
/// are already in the keystore.
fn build_proto_relay_auth_material(
    now: SystemTime,
    keymgr: &KeyMgr,
) -> anyhow::Result<RelayChannelAuthMaterial> {
    let mut rng = tor_llcrypto::rng::CautiousRng;

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
    let cert_id_sign_ed: RelaySigningKeyCert = keymgr
        .get_cert_entry::<RelaySigningKeyCertSpecifier, _, _>(
            keymgr
                .list_matching(&RelaySigningKeyCertSpecifierPattern::new_any().arti_pattern()?)?
                .first()
                .context("No store entry for signing key cert")?,
            &RelayIdentityKeypairSpecifier::new(),
        )
        .context("Failed to get signing key cert from key manager")?
        .context("Missing signing key cert")?;

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
        now,
        &issuer_hostname,
        rsa_id_kp.keypair(),
    )
    .context("Failed to create legacy RSA identity certificate")?;

    let cert_id_rsa = tor_cert::rsa::EncodedRsaCrosscert::encode_and_sign(
        rsa_id_kp.keypair(),
        &ed_id_kp.to_ed25519_id(),
        now + RSA_CROSSCERT_LIFETIME,
    )?;

    // Create the link cert and tls cert.
    let cert_sign_link_auth_ed =
        gen_link_cert(&kp_relaysign_id, &link_sign_kp, now + LINK_CERT_LIFETIME)?;
    let cert_sign_tls_ed = gen_tls_cert(
        &kp_relaysign_id,
        *tls_key_and_cert.link_cert_sha256(),
        now + LINK_CERT_LIFETIME,
    )?;

    Ok(RelayChannelAuthMaterial::new(
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

/// Go through keystore entries matching `pattern` and remove any that are
/// expired according to `is_expired`.
///
/// Returns `(removed, min_remaining)` where `removed` indicates whether any entry was deleted and
/// `min_remaining` is the minimum `valid_until` of the entries that were kept (if any).
fn remove_expired<F, E>(
    now: SystemTime,
    keymgr: &KeyMgr,
    pattern: &tor_keymgr::KeyPathPattern,
    label: &'static str,
    expiry_from_keypath: F,
    is_expired: E,
) -> anyhow::Result<(bool, Option<SystemTime>)>
where
    F: Fn(&KeyPath) -> anyhow::Result<Timestamp>,
    E: Fn(&Timestamp, SystemTime) -> bool,
{
    let entries = keymgr.list_matching(pattern)?;
    let mut removed = false;
    let mut min_valid_until: Option<Timestamp> = None;

    for entry in entries {
        let valid_until = expiry_from_keypath(entry.key_path())?;
        if is_expired(&valid_until, now) {
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
fn try_generate_key<K, P, F>(
    keymgr: &KeyMgr,
    spec: &dyn KeySpecifier,
    should_generate: F,
) -> anyhow::Result<bool>
where
    K: ToEncodableKey,
    K::Key: Keygen,
    P: KeySpecifierPattern,
    F: Fn(&[KeystoreEntry]) -> anyhow::Result<bool>,
{
    let mut generated = false;
    let mut rng = tor_llcrypto::rng::CautiousRng;
    let entries = keymgr.list_matching(&P::new_any().arti_pattern()?)?;
    if should_generate(&entries)? {
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
fn try_generate_all(
    now: SystemTime,
    keymgr: &KeyMgr,
) -> anyhow::Result<(KeyChange, Option<SystemTime>)> {
    let link_expiry = now + LINK_CERT_LIFETIME;
    let link_spec = RelayLinkSigningKeypairSpecifier::new(Timestamp::from(link_expiry));
    let link_generated =
        try_generate_key::<RelayLinkSigningKeypair, RelayLinkSigningKeypairSpecifierPattern, _>(
            keymgr,
            &link_spec,
            |entries: &[KeystoreEntry<'_>]| Ok(entries.is_empty()),
        )?;

    let cert_expiry = now + SIGNING_KEY_CERT_LIFETIME;

    // The make certificate function needed for the get_or_generate_key_and_cert(). It is a closure
    // so we can capture the runtime wallclock.
    let make_signing_cert = |subject_key: &RelaySigningKeypair,
                             signing_key: &RelayIdentityKeypair| {
        gen_signing_cert(signing_key, subject_key, cert_expiry)
            .expect("failed to generate relay signing cert")
    };

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

    let ntor_expiry = now + NTOR_KEY_LIFETIME;
    let ntor_spec = RelayNtorKeypairSpecifier::new(Timestamp::from(ntor_expiry));

    // We generate a new ntor key if all existing keys are expired `now`
    // (without taking into account the grace period)
    let should_generate_ntor = |entries: &[KeystoreEntry<'_>]| {
        let mut all_expired = true;
        for entry in entries {
            let key_path = entry.key_path();
            let valid_until =
                SystemTime::from(RelayNtorKeypairSpecifier::try_from(key_path)?.valid_until);

            // If *all* the ntor keys are expired (but still within the grace period),
            // we want to generate a new ntor key.
            //
            // Note: this needs to take the KEY_ROTATION_EXPIRE_BUFFER into account
            // because the main loop will wake us KEY_ROTATION_EXPIRE_BUFFER
            // *before* the valid_until elapses
            if valid_until > now + KEY_ROTATION_EXPIRE_BUFFER {
                all_expired = false;
                break;
            }
        }

        Ok(all_expired)
    };

    let ntor_generated = try_generate_key::<RelayNtorKeypair, RelayNtorKeypairSpecifierPattern, _>(
        keymgr,
        &ntor_spec,
        should_generate_ntor,
    )?;

    let change = KeyChange {
        chan_auth: link_generated || cert_generated,
        ntor: ntor_generated,
    };

    Ok((
        change,
        [
            link_generated.then_some(link_expiry),
            cert_generated.then_some(cert_expiry),
            ntor_generated.then_some(ntor_expiry),
        ]
        .into_iter()
        .flatten()
        .min(),
    ))
}

/// Remove any expired keys (and certs) that are expired.
///
/// Return (`removed`, `next_expiry`) where the `removed` indicates if at least one key has been
/// removed because it was expired. The `next_expiry` is the minimum value of all valid_until which
/// indicates the next closest expiry time.
fn remove_expired_keys(
    now: SystemTime,
    keymgr: &KeyMgr,
) -> anyhow::Result<(KeyChange, Option<SystemTime>)> {
    let is_expired_with_buffer = |valid_until: &Timestamp, now| {
        *valid_until <= Timestamp::from(now + KEY_ROTATION_EXPIRE_BUFFER)
    };
    let (relaysign_removed, relaysign_expiry) = remove_expired(
        now,
        keymgr,
        &RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_relaysign_ed",
        |key_path| Ok(RelaySigningKeypairSpecifier::try_from(key_path)?.valid_until),
        is_expired_with_buffer,
    )?;
    let (link_removed, link_expiry) = remove_expired(
        now,
        keymgr,
        &RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_link_ed",
        |key_path| Ok(RelayLinkSigningKeypairSpecifier::try_from(key_path)?.valid_until),
        is_expired_with_buffer,
    )?;

    // This should always be removed if the signing key above has been removed. However, we still
    // do a pass at the keystore considering the upcoming offline key feature that might have more
    // than one expired cert in the keystore.
    let (sign_cert_removed, sign_cert_expiry) = remove_expired(
        now,
        keymgr,
        &RelaySigningKeyCertSpecifierPattern::new_any().arti_pattern()?,
        "signing key cert",
        |key_path| {
            let spec: RelaySigningKeyCertSpecifier = key_path.try_into()?;
            let subject_key_path = KeyPath::Arti(spec.subject_key_specifier().arti_path()?);
            let subject_key_spec: RelaySigningPublicKeySpecifier =
                (&subject_key_path).try_into()?;
            Ok(subject_key_spec.valid_until)
        },
        is_expired_with_buffer,
    )?;

    // When deciding whether to remove the key,
    // we need to take into account the special grace period ntor keys have
    // (we need to keep the key around even if it's "expired",
    // because some clients might still be using an older consensus
    // and hence might not know about our new key yet).
    let is_expired_ntor = |valid_until: &Timestamp, now| {
        // Note: we need to take into account KEY_ROTATION_EXPIRE_BUFFER
        // because the main loop always subtracts KEY_ROTATION_EXPIRE_BUFFER
        // from the returned next_expiry, but ideally,
        // I don't think we should be using this buffer for the ntor keys,
        // because they have a grace period and don't get removed immediately
        // anyway
        *valid_until <= Timestamp::from(now - NTOR_KEY_GRACE_PERIOD + KEY_ROTATION_EXPIRE_BUFFER)
    };

    let (ntor_key_removed, ntor_key_expiry) = remove_expired(
        now,
        keymgr,
        &RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_ntor",
        |key_path| Ok(RelayNtorKeypairSpecifier::try_from(key_path)?.valid_until),
        is_expired_ntor,
    )?;

    // Have we at least removed one?
    let removed = KeyChange {
        chan_auth: relaysign_removed || link_removed || sign_cert_removed,
        ntor: ntor_key_removed,
    };

    // TODO: we could, in theory, return this from remove_expired(),
    // but I don't want to make it any more complicated than it already is,
    // especially for an operation that runs relatively infrequently.
    let ntor_key_count = keymgr
        .list_matching(&RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?)?
        .len();

    // This is a best effort check. There is no guarantee the
    // second key is the "successor" of this key,
    // but in general, it will be, unless an external process
    // is concurrently modifying the keystore
    // (which something we explicitly don't try to protect against).
    //
    // We could, in theory, check that the valid_until of the two
    // keys are adequately spaced, but in practice I don't think
    // it matters much.
    let next_key_exists = ntor_key_count >= 2;

    // Note: for each ntor key, we need to wake up twice
    //
    //   * at its expiry time, to generate the next ntor key
    //   * at its expiry time + GRACE_PERIOD, to remove the old ntor key
    let ntor_key_expiry = match ntor_key_expiry {
        None => {
            // We removed the last ntor key, the wakeup time will be
            // determined by try_generate_key() later
            None
        }
        // This special case may seem strange, but it's needed for
        // the specific scenario where there is only one ntor key
        // in the keystore with valid_until < now.
        //
        // Without it, there is no guarantee we will wake up at valid_until
        // to generate the new ntor key (when the key is generated,
        // we try to schedule a rotation task wakeup at valid_until,
        // but if the other keys have "sooner" `valid_until`s,
        // that wakeup will be lost.
        Some(valid_until) if !next_key_exists => {
            // The next key doesn't exist yet,
            // wake up at valid_until to generate it
            Some(valid_until)
        }
        Some(valid_until) => {
            // The next key exists, we only need to wake up
            // to garbage collect this one, after the grace period
            //
            // This avoids busy looping in the [valid_until, valid_until + grace_period]
            // time interval (if we don't add the grace period here, when
            // now = valid_until, we will keep waking up the main loop of the
            // key rotation task, and then not actually removing the key because
            // it's still within the grace period).
            Some(valid_until + NTOR_KEY_GRACE_PERIOD)
        }
    };

    let next_expiry = [
        relaysign_expiry,
        link_expiry,
        sign_cert_expiry,
        ntor_key_expiry,
    ]
    .into_iter()
    .flatten()
    .min();

    Ok((removed, next_expiry))
}

/// Attempt to rotate all keys except identity keys.
///
/// Returns (rotated, next_expiry) where `rotated` indicates if any key was rotated and
/// `next_expiry` is the earliest expiry time across all keys.
fn try_rotate_keys(now: SystemTime, keymgr: &KeyMgr) -> anyhow::Result<(KeyChange, SystemTime)> {
    // First do a pass to remove every expired key(s) or/and cert(s).
    let (have_removed, min_expiry) = remove_expired_keys(now, keymgr)?;

    // Then attempt to generate keys. If at least one was generated, we'll get the min expiry time
    // which we need to consider "rotated" so the caller can know that a new key appeared.
    let (generated, gen_min_expiry) = try_generate_all(now, keymgr)?;
    let have_rotated = have_removed.or(&generated);

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
/// * Relay ntor keypair [`RelayNtorKeypair`].
///
/// This function is only called when our relay bootstraps in order to attempt to generate any
/// missing keys or/and rotate expired keys.
pub(crate) fn try_generate_keys<R: Runtime>(
    runtime: &R,
    keymgr: &KeyMgr,
) -> anyhow::Result<RelayChannelAuthMaterial> {
    let now = runtime.wallclock();
    // Attempt to generate our identity keys (ed and RSA). Those keys DO NOT rotate. It won't be
    // replaced if they already exists.
    generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())?;
    generate_key::<RelayIdentityRsaKeypair>(keymgr, &RelayIdentityRsaKeypairSpecifier::new())?;

    // Attempt to rotate the keys. Any missing keys (and cert) will be generated.
    let _ = try_rotate_keys(now, keymgr)?;

    // Now that we have our up-to-date keys, build the relay channel auth material object.
    build_proto_relay_auth_material(now, keymgr)
}
/// Task to rotate keys when they need to be rotated.
pub(crate) async fn rotate_keys_task<R: Runtime>(
    runtime: R,
    keymgr: Arc<KeyMgr>,
    chanmgr: Arc<ChanMgr<R>>,
) -> anyhow::Result<void::Void> {
    loop {
        let now = runtime.wallclock();
        // Attempt a rotation of all keys.
        let (have_rotated, next_expiry) = try_rotate_keys(now, &keymgr)?;
        if have_rotated.chan_auth {
            let auth_material = build_proto_relay_auth_material(now, &keymgr)?;
            chanmgr
                .set_relay_auth_material(Arc::new(auth_material))
                .context("Failed to set relay auth material on ChanMgr")?;
        }

        if have_rotated.ntor {
            // Any keys left in the keystore at this point are considered to be usable
            // (either because they are newly generated, or because they are still
            // within the grace period).
            let ntor_keys = keymgr
                .list_matching(&RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?)?
                .into_iter()
                .map(|entry| {
                    keymgr
                        .get_entry::<RelayNtorKeypair>(&entry)
                        .context("failed to retrieve ntor key")?
                        .context("ntor key disappeared?!")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            // XXX update create handler with new keys
        }

        // Sleep until the earliest key expiry minus buffer so we rotate before it expires.
        // If the subtraction would underflow, wake up immediately to rotate the expired key.
        let next_wake = next_expiry
            .checked_sub(KEY_ROTATION_EXPIRE_BUFFER)
            .unwrap_or(now);
        runtime.sleep_until_wallclock(next_wake).await;
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

    use crate::keys::{
        RelayLinkSigningKeypairSpecifierPattern, RelaySigningKeypairSpecifierPattern,
    };
    use tor_keymgr::{ArtiEphemeralKeystore, KeyMgrBuilder, KeySpecifierPattern};
    use tor_rtcompat::SleepProvider;
    use tor_rtmock::MockRuntime;

    /// Generate the non-rotating identity keys so the rest of the key machinery can run.
    fn setup_identity_keys(keymgr: &KeyMgr) {
        use crate::keys::{RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier};
        use tor_relay_crypto::pk::{RelayIdentityKeypair, RelayIdentityRsaKeypair};
        generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())
            .unwrap();
        generate_key::<RelayIdentityRsaKeypair>(keymgr, &RelayIdentityRsaKeypairSpecifier::new())
            .unwrap();
    }

    /// Initialize test basics that is runtime and a KeyMgr.
    fn new_keymgr() -> KeyMgr {
        let store = Box::new(ArtiEphemeralKeystore::new("test".to_string()));
        KeyMgrBuilder::default()
            .primary_store(store)
            .build()
            .unwrap()
    }

    /// Initial setup of a test. Build a mock runtime, key manager and setup identity keys.
    fn setup() -> KeyMgr {
        let keymgr = new_keymgr();
        setup_identity_keys(&keymgr);
        keymgr
    }

    /// Return a [`Timestamp`] given a [`SystemTime`] rounded down to its nearest second.
    ///
    /// In other words, the `tv_nsec` of a [`SystemTime`] is dropped.
    fn to_timestamp_in_secs(valid_until: SystemTime) -> Timestamp {
        use std::time::UNIX_EPOCH;
        let seconds = valid_until.duration_since(UNIX_EPOCH).unwrap().as_secs();
        Timestamp::from(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    /// Return the number of keys matching the specified pattern
    fn count_keys(keymgr: &KeyMgr, pat: &dyn KeySpecifierPattern) -> usize {
        keymgr
            .list_matching(&pat.arti_pattern().unwrap())
            .unwrap()
            .len()
    }

    /// Return the number of link keys in the given KeyMgr.
    fn count_link_keys(keymgr: &KeyMgr) -> usize {
        count_keys(keymgr, &RelayLinkSigningKeypairSpecifierPattern::new_any())
    }

    /// Return the number of signing keys in the given KeyMgr.
    fn count_signing_keys(keymgr: &KeyMgr) -> usize {
        count_keys(keymgr, &RelaySigningKeypairSpecifierPattern::new_any())
    }

    /// Return the number of ntor keys in the given KeyMgr.
    fn count_ntor_keys(keymgr: &KeyMgr) -> usize {
        count_keys(keymgr, &RelayNtorKeypairSpecifierPattern::new_any())
    }

    /// Test the actual bootstrap function, `try_generate_keys()` which is in charge of
    /// initializing the auth material.
    #[test]
    fn test_bootstrap() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = new_keymgr();

            let _auth_material = match try_generate_keys(&runtime, &keymgr) {
                Ok(a) => a,
                Err(e) => {
                    panic!("Unable to bootstrap keys and generate RelayChannelAuthMaterial: {e}");
                }
            };
        });
    }

    /// Simulate the bootstrap when no keys exists. We should have one link key and one signing key
    /// after the first rotation.
    #[test]
    fn test_initial_key_generation() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            let now = runtime.wallclock();

            let (rotated, next_expiry) = try_rotate_keys(now, &keymgr).unwrap();

            assert!(
                rotated.chan_auth && rotated.ntor,
                "keys should be reported as generated on first rotation"
            );
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");
            assert_eq!(count_ntor_keys(&keymgr), 1, "expected one ntor key");

            // The earliest expiry should be the link key (~2 days out).
            let expected = runtime.wallclock() + LINK_CERT_LIFETIME;
            assert_eq!(
                next_expiry, expected,
                "next expiry should be ~{LINK_CERT_LIFETIME:?} from now, got {next_expiry:?}"
            );
        });
    }

    /// Calling rotate_keys a second time with fresh keys should indicate no rotation.
    #[test]
    fn test_rotation_on_fresh_keys() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            let now = runtime.wallclock();
            try_rotate_keys(now, &keymgr).unwrap();

            // Advance by 1 hour (inside 2 days of link key).
            runtime.advance_by(Duration::from_secs(60 * 60)).await;

            let (rotated, _) = try_rotate_keys(now, &keymgr).unwrap();

            assert!(
                !rotated.chan_auth && !rotated.ntor,
                "fresh keys must not trigger a rotation"
            );
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");
            assert_eq!(count_ntor_keys(&keymgr), 1, "expected one ntor key");
        });
    }

    /// Test rotation before and after rotation expiry buffer for the link key.
    #[test]
    fn test_rotation_link_key() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            // First rotation creates the keys.
            try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            // Advance to 1 second _before_ the rotation-buffer threshold. We should not rotate
            // with this.
            let just_before =
                LINK_CERT_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER - Duration::from_secs(1);
            runtime.advance_by(just_before).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            assert!(
                !rotated.chan_auth,
                "link key MUST NOT rotate before the expiry buffer threshold"
            );
            assert!(
                !rotated.ntor,
                "ntor key MUST NOT rotate before the expiry buffer threshold"
            );
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");

            // Move it just after the expiry buffer and expect a rotation.
            runtime.advance_by(Duration::from_secs(1)).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(
                rotated.chan_auth,
                "link key should rotate inside the expiry buffer threshold"
            );
        });
    }

    /// Test rotation before and after rotation expiry buffer for the signing key.
    #[test]
    fn test_rotation_signing_key() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            // First rotation creates the keys.
            try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            // Closure to get the relay signing key keystore entry.
            let get_key_spec = || {
                let entries = keymgr
                    .list_matching(
                        &RelaySigningKeypairSpecifierPattern::new_any()
                            .arti_pattern()
                            .unwrap(),
                    )
                    .unwrap();
                let entry = entries.first().unwrap();
                let spec: RelaySigningKeypairSpecifier = entry.key_path().try_into().unwrap();
                spec
            };

            // Advance to 1 second _before_ the rotation-buffer threshold. We should not rotate
            // with this.
            let just_before =
                SIGNING_KEY_CERT_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER - Duration::from_secs(1);
            runtime.advance_by(just_before).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(rotated.chan_auth, "Rotation must happen after 30 days");

            let spec = get_key_spec();
            assert_eq!(
                spec.valid_until,
                to_timestamp_in_secs(
                    runtime.wallclock() + KEY_ROTATION_EXPIRE_BUFFER + Duration::from_secs(1)
                ),
                "RelaySigningKeypairSpecifier should not have rotated"
            );

            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");

            // Move it just after the expiry buffer and expect a rotation.
            runtime.advance_by(Duration::from_secs(1)).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(rotated.chan_auth, "Rotation must happen after 30 days");

            let spec = get_key_spec();
            assert_eq!(
                spec.valid_until,
                to_timestamp_in_secs(runtime.wallclock() + SIGNING_KEY_CERT_LIFETIME),
                "RelaySigningKeypairSpecifier should have rotated"
            );
        });
    }

    /// Test rotation before and after rotation expiry buffer for the ntor key.
    #[test]
    fn test_rotation_ntor_key() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            // First rotation creates the keys.
            try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            // Advance to 1 second _before_ the rotation-buffer threshold. We should not rotate
            // with this.
            let just_before =
                NTOR_KEY_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER - Duration::from_secs(1);
            runtime.advance_by(just_before).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            assert!(
                !rotated.ntor,
                "Ntor key MUST NOT rotate before the expiry buffer threshold"
            );
            assert_eq!(count_ntor_keys(&keymgr), 1, "expected one ntor key");

            // Move it just after the expiry buffer and expect a rotation.
            runtime.advance_by(Duration::from_secs(1)).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(
                rotated.ntor,
                "ntor key should rotate inside the expiry buffer threshold"
            );

            assert_eq!(
                count_ntor_keys(&keymgr),
                2,
                "there should be 2 ntor keys in the grace period"
            );

            runtime.advance_by(NTOR_KEY_GRACE_PERIOD).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(
                rotated.ntor,
                "ntor key should rotate after the grace period"
            );

            assert_eq!(
                count_ntor_keys(&keymgr),
                1,
                "the old ntor key should have been removed after the grace period"
            );
        });
    }
}
