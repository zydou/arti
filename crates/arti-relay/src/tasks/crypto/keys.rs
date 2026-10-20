//! Key rotation tasks of the relay.

use anyhow::Context;
use std::borrow::Borrow;
use std::time::{Duration, SystemTime};

use tor_basic_utils::rand_hostname;
use tor_cert::x509::TlsKeyAndCert;
use tor_error::internal;
use tor_key_forge::ToEncodableCert;
use tor_keymgr::{
    CertSpecifierPattern, KeyCertificateSpecifier, KeyMgr, KeyPath, KeySpecifier,
    KeySpecifierPattern, Keygen, KeystoreEntry, KeystoreSelector, ToEncodableKey,
};
use tor_proto::RelayChannelAuthMaterial;
use tor_relay_crypto::pk::{
    RelayIdentityKeypair, RelayLinkSigningKeypair, RelayNtorKeypair, RelaySigningKeypair,
};
use tor_relay_crypto::{RelaySigningKeyCert, gen_link_cert, gen_signing_cert, gen_tls_cert};

use crate::{
    keys::{
        RelayIdentityKeypairSpecifier, RelayLinkSigningKeypairSpecifier,
        RelayLinkSigningKeypairSpecifierPattern, RelayNtorKeypairSpecifier,
        RelayNtorKeypairSpecifierPattern, RelaySigningKeyCertSpecifier,
        RelaySigningKeyCertSpecifierPattern, RelaySigningKeypairSpecifier,
        RelaySigningKeypairSpecifierPattern, RelaySigningPublicKeySpecifier, Timestamp,
    },
    tasks::crypto::{KeyRotationParams, views::FullKeyView},
};

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
/// The link cert and TLS certs are created in this function.
/// The signing key certificate is retrieved from the keymgr.
///
/// This function assumes that all required keys,
/// as well as the signing key certificate,
/// are already in the keystore.
pub(super) fn build_proto_relay_auth_material(
    now: SystemTime,
    view: &FullKeyView<impl Borrow<KeyMgr>>,
) -> anyhow::Result<RelayChannelAuthMaterial> {
    let mut rng = tor_llcrypto::rng::CautiousRng;

    let rsa_id_kp = view.ks_relayid_rsa()?;
    let ed_id_kp = view.ks_relayid_ed()?;
    let link_sign_kp = view.ks_link_ed()?;
    let kp_relaysign_id = view.ks_relaysign_ed()?;
    let cert_id_sign_ed = view.cert_relaysign_ed()?;

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
pub(super) fn generate_key<K>(
    keymgr: &KeyMgr,
    spec: &dyn KeySpecifier,
) -> Result<(), tor_keymgr::Error>
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

/// Go through keystore entries matching `pattern` and remove any that are expired according to
/// `is_expired`.
///
/// Returns `min_remaining` which is the minimum `valid_until` of the entries that were kept (if
/// any).
fn remove_expired<F, E>(
    now: SystemTime,
    keymgr: &KeyMgr,
    pattern: &tor_keymgr::KeyPathPattern,
    label: &'static str,
    expiry_from_keypath: F,
    is_expired: E,
) -> anyhow::Result<Option<SystemTime>>
where
    F: Fn(&KeyPath) -> anyhow::Result<Timestamp>,
    E: Fn(&Timestamp, SystemTime) -> bool,
{
    let entries = keymgr.list_matching(pattern)?;
    let mut min_valid_until: Option<Timestamp> = None;

    for entry in entries {
        let valid_until = expiry_from_keypath(entry.key_path())?;
        if is_expired(&valid_until, now) {
            tracing::debug!("Expired {} in keymgr. Removing it.", label);
            keymgr.remove_entry(&entry)?;
        } else {
            min_valid_until =
                Some(min_valid_until.map_or(valid_until, |current| current.min(valid_until)));
        }
    }

    Ok(min_valid_until.map(SystemTime::from))
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
/// Returns the minimum `valid_until` across newly generated keys, or `None` if nothing was generated.
fn try_generate_all(
    now: SystemTime,
    keymgr: &KeyMgr,
    params: KeyRotationParams,
) -> anyhow::Result<Option<SystemTime>> {
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

    let ntor_expiry = now + params.ntor_lifetime;
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

    Ok([
        link_generated.then_some(link_expiry),
        cert_generated.then_some(cert_expiry),
        ntor_generated.then_some(ntor_expiry),
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
    params: KeyRotationParams,
) -> anyhow::Result<Option<SystemTime>> {
    let is_expired_with_buffer = |valid_until: &Timestamp, now| {
        *valid_until <= Timestamp::from(now + KEY_ROTATION_EXPIRE_BUFFER)
    };
    let relaysign_expiry = remove_expired(
        now,
        keymgr,
        &RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_relaysign_ed",
        |key_path| Ok(RelaySigningKeypairSpecifier::try_from(key_path)?.valid_until),
        is_expired_with_buffer,
    )?;
    let link_expiry = remove_expired(
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
    let sign_cert_expiry = remove_expired(
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
        *valid_until <= Timestamp::from(now - params.ntor_grace_period + KEY_ROTATION_EXPIRE_BUFFER)
    };

    let ntor_key_expiry = remove_expired(
        now,
        keymgr,
        &RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?,
        "key KP_ntor",
        |key_path| Ok(RelayNtorKeypairSpecifier::try_from(key_path)?.valid_until),
        is_expired_ntor,
    )?;

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
            Some(valid_until + params.ntor_grace_period)
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

    Ok(next_expiry)
}

/// Attempt to rotate all keys except identity keys.
///
/// Returns the earliest expiry time across all keys.
pub(super) fn try_rotate_keys(
    now: SystemTime,
    keymgr: &KeyMgr,
    params: KeyRotationParams,
) -> anyhow::Result<SystemTime> {
    let min_expiry = remove_expired_keys(now, keymgr, params)?;
    // Then attempt to generate keys. If at least one was generated, we'll get the min expiry time
    // which we need to consider "rotated" so the caller can know that a new key appeared.
    let gen_min_expiry = try_generate_all(now, keymgr, params)?;

    // We should never get no expiry time.
    Ok([min_expiry, gen_min_expiry]
        .into_iter()
        .flatten()
        .min()
        .ok_or_else(|| internal!("No relay keys after rotation task loop"))?)
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    use crate::{
        keys::{RelayLinkSigningKeypairSpecifierPattern, RelaySigningKeypairSpecifierPattern},
        tasks::crypto::test::new_keymgr,
    };
    use tor_keymgr::KeySpecifierPattern;
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

    /// Call [`try_rotate_keys_no_lock`] with default consensus parameters.
    fn rotate_keys(now: SystemTime, keymgr: &KeyMgr) -> anyhow::Result<SystemTime> {
        try_rotate_keys(
            now,
            keymgr,
            KeyRotationParams::from(&tor_netdir::params::NetParameters::default()),
        )
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

    /// Simulate the bootstrap when no keys exists. We should have one link key and one signing key
    /// after the first rotation.
    #[test]
    fn test_initial_key_generation() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            let now = runtime.wallclock();

            let next_expiry = rotate_keys(now, &keymgr).unwrap();

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
            let _expiry = rotate_keys(now, &keymgr).unwrap();

            // Advance by 1 hour (inside 2 days of link key).
            runtime.advance_by(Duration::from_secs(60 * 60)).await;

            let _expiry = rotate_keys(now, &keymgr).unwrap();

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
            rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            // Advance to 1 second _before_ the rotation-buffer threshold. We should not rotate
            // with this.
            let just_before =
                LINK_CERT_LIFETIME - KEY_ROTATION_EXPIRE_BUFFER - Duration::from_secs(1);
            runtime.advance_by(just_before).await;

            let first_expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            assert_eq!(count_link_keys(&keymgr), 1, "expected one link key");
            assert_eq!(count_signing_keys(&keymgr), 1, "expected one signing key");

            // Move it just after the expiry buffer and expect a rotation.
            runtime.advance_by(Duration::from_secs(1)).await;

            let second_expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert_ne!(first_expiry, second_expiry);
        });
    }

    /// Test rotation before and after rotation expiry buffer for the signing key.
    #[test]
    fn test_rotation_signing_key() {
        MockRuntime::test_with_various(|runtime| async move {
            let keymgr = setup();
            // First rotation creates the keys.
            rotate_keys(runtime.wallclock(), &keymgr).unwrap();

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

            let _expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();

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

            let _expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();
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
            rotate_keys(runtime.wallclock(), &keymgr).unwrap();

            // Advance to 1 second _before_ the rotation-buffer threshold. We should not rotate
            // with this.
            let default_params =
                KeyRotationParams::from(&tor_netdir::params::NetParameters::default());
            let just_before =
                default_params.ntor_lifetime - KEY_ROTATION_EXPIRE_BUFFER - Duration::from_secs(1);
            runtime.advance_by(just_before).await;

            let _expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert_eq!(count_ntor_keys(&keymgr), 1, "expected one ntor key");

            // Move it just after the expiry buffer and expect a rotation.
            runtime.advance_by(Duration::from_secs(1)).await;

            let _expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert_eq!(
                count_ntor_keys(&keymgr),
                2,
                "there should be 2 ntor keys in the grace period"
            );

            runtime.advance_by(default_params.ntor_grace_period).await;

            let _expiry = rotate_keys(runtime.wallclock(), &keymgr).unwrap();
            assert_eq!(
                count_ntor_keys(&keymgr),
                1,
                "the old ntor key should have been removed after the grace period"
            );
        });
    }
}
