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
use tor_proto::RelayChannelAuthMaterial;
use tor_relay_crypto::{RelaySigningKeyCert, gen_link_cert, gen_signing_cert, gen_tls_cert};

use crate::keys::{
    RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier,
    RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
    RelaySigningKeyCertSpecifier, RelaySigningKeyCertSpecifierPattern,
    RelaySigningKeypairSpecifier, RelaySigningKeypairSpecifierPattern,
    RelaySigningPublicKeySpecifier, Timestamp,
};
use tor_relay_crypto::pk::{
    RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayLinkSigningKeypair, RelaySigningKeypair,
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

/// Build a fresh [`RelayChannelAuthMaterial`] object using a [`KeyMgr`].
///
/// Every single certificate is generated in this function.
///
/// This function assumes that all required keys are in the keymgr.
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

    // Create the signing key cert, link cert and tls cert.
    //
    // TODO(relay): We need to check the KeyMgr for the signing cert but for now the KeyMgr API
    // doesn't allow us to get it out. We will do a re-design of the cert API there. This is fine
    // as long as we don't support offline keys.
    let cert_id_sign_ed = gen_signing_cert(&ed_id_kp, &kp_relaysign_id, now + SIGNING_KEY_CERT_LIFETIME)?;
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

/// Go through keystore entries matching `pattern` and remove any that are within
/// [`KEY_ROTATION_EXPIRE_BUFFER`] of expiry.
///
/// Returns `(removed, min_remaining)` where `removed` indicates whether any entry was deleted and
/// `min_remaining` is the minimum `valid_until` of the entries that were kept (if any).
fn remove_expired<F>(
    now: SystemTime,
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
        if valid_until <= Timestamp::from(now + KEY_ROTATION_EXPIRE_BUFFER) {
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
fn try_generate_all(now: SystemTime, keymgr: &KeyMgr) -> anyhow::Result<Option<SystemTime>> {
    let link_expiry = now + LINK_CERT_LIFETIME;
    let link_spec = RelayLinkSigningKeypairSpecifier::new(Timestamp::from(link_expiry));
    let link_generated = try_generate_key::<
        RelayLinkSigningKeypair,
        RelayLinkSigningKeypairSpecifierPattern,
    >(keymgr, &link_spec)?;

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
fn remove_expired_keys(
    now: SystemTime,
    keymgr: &KeyMgr,
) -> anyhow::Result<(bool, Option<SystemTime>)> {
    let (relaysign_removed, relaysign_expiry) = remove_expired(
        now,
        keymgr,
        &RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_relaysign_ed",
        |key_path| Ok(RelaySigningKeypairSpecifier::try_from(key_path)?.valid_until),
    )?;
    let (link_removed, link_expiry) = remove_expired(
        now,
        keymgr,
        &RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_link_ed",
        |key_path| Ok(RelayLinkSigningKeypairSpecifier::try_from(key_path)?.valid_until),
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
fn try_rotate_keys(now: SystemTime, keymgr: &KeyMgr) -> anyhow::Result<(bool, SystemTime)> {
    // First do a pass to remove every expired key(s) or/and cert(s).
    let (have_rotated, min_expiry) = remove_expired_keys(now, keymgr)?;

    // Then attempt to generate keys. If at least one was generated, we'll get the min expiry time
    // which we need to consider "rotated" so the caller can know that a new key appeared.
    let gen_min_expiry = try_generate_all(now, keymgr)?;
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
        if have_rotated {
            let auth_material = build_proto_relay_auth_material(now, &keymgr)?;
            chanmgr
                .set_relay_auth_material(Arc::new(auth_material))
                .context("Failed to set relay auth material on ChanMgr")?;
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
    use tor_keymgr::{ArtiEphemeralKeystore, KeyMgrBuilder};
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

    /// Return the number of link keys in the given KeyMgr.
    fn count_link_keys(keymgr: &KeyMgr) -> usize {
        keymgr
            .list_matching(
                &RelayLinkSigningKeypairSpecifierPattern::new_any()
                    .arti_pattern()
                    .unwrap(),
            )
            .unwrap()
            .len()
    }

    /// Return the number of signing keys in the given KeyMgr.
    fn count_signing_keys(keymgr: &KeyMgr) -> usize {
        keymgr
            .list_matching(
                &RelaySigningKeypairSpecifierPattern::new_any()
                    .arti_pattern()
                    .unwrap(),
            )
            .unwrap()
            .len()
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
                rotated,
                "keys should be reported as generated on first rotation"
            );
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");

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

            assert!(!rotated, "fresh keys must not trigger a rotation");
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");
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
                !rotated,
                "link key MUST NOT rotate before the expiry buffer threshold"
            );
            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");

            // Move it just after the expiry buffer and expect a rotation.
            let just_after =
                LINK_CERT_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER + Duration::from_secs(1);
            runtime.advance_by(just_after).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(
                rotated,
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
            assert!(rotated, "Rotation must happen after 30 days");

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
            let just_after =
                SIGNING_KEY_CERT_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER + Duration::from_secs(1);
            runtime.advance_by(just_after).await;

            let (rotated, _) = try_rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert!(rotated, "Rotation must happen after 30 days");

            let spec = get_key_spec();
            assert_eq!(
                spec.valid_until,
                to_timestamp_in_secs(runtime.wallclock() + SIGNING_KEY_CERT_LIFETIME),
                "RelaySigningKeypairSpecifier should have rotated"
            );
        });
    }
}
