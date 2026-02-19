//! Key rotation tasks of the relay.

use anyhow::Context;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::task::JoinSet;
use tor_basic_utils::rand_hostname;
use tor_cert::x509::TlsKeyAndCert;
use tor_proto::RelayIdentities;

use tor_key_forge::ToEncodableCert;
use tor_keymgr::{
    KeyMgr, KeyPath, KeySpecifier, KeySpecifierPattern, Keygen, KeystoreSelector, ToEncodableKey,
};
use tor_relay_crypto::{
    gen_link_cert, gen_signing_cert, gen_tls_cert,
    pk::{
        RelayIdentityKeypair, RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypair,
        RelayIdentityRsaKeypairSpecifier, RelayLinkSigningKeypair,
        RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
        RelaySigningKeypair, RelaySigningKeypairSpecifier, RelaySigningKeypairSpecifierPattern,
        Timestamp,
    },
};
use tor_rtcompat::{Runtime, SleepProviderExt};

/// Sleep duration of the key rotation task.
const KEY_ROTATION_SLEEP_DURATION: Duration = Duration::from_secs(60);

/// Trait to help us specify what we need for key rotation. This allows us to have the generic
/// function `rotate_key()`.
trait RotatableKeySpec {
    /// Key specifier type.
    type Specifier: KeySpecifier;
    /// Key specifier pattern (for the ArtiPath).
    type Pattern: KeySpecifierPattern;

    /// Build a new specifier.
    fn key_specifier() -> Self::Specifier;
    /// For logs.
    fn label() -> &'static str;
    /// Build a specifier from a [`KeyPath`]
    fn spec_from_keypath(keypath: &KeyPath) -> Result<Self::Specifier, tor_keymgr::KeyPathError>;
    /// The key `valid_until`.
    fn valid_until() -> Timestamp;
    /// The `valid_until` of the given key specifier.
    fn valid_until_from_spec(spec: &Self::Specifier) -> Timestamp;
}

impl RotatableKeySpec for RelaySigningKeypair {
    type Specifier = RelaySigningKeypairSpecifier;
    type Pattern = RelaySigningKeypairSpecifierPattern;

    fn key_specifier() -> Self::Specifier {
        Self::Specifier::new(Self::valid_until())
    }
    fn label() -> &'static str {
        "KP_relaysign_ed"
    }
    fn spec_from_keypath(keypath: &KeyPath) -> Result<Self::Specifier, tor_keymgr::KeyPathError> {
        keypath.try_into()
    }
    fn valid_until() -> Timestamp {
        // Taken from C-tor.
        Timestamp::from(SystemTime::now() + Duration::from_secs(30 * 86400))
    }
    fn valid_until_from_spec(spec: &Self::Specifier) -> Timestamp {
        spec.valid_until()
    }
}

impl RotatableKeySpec for RelayLinkSigningKeypair {
    type Specifier = RelayLinkSigningKeypairSpecifier;
    type Pattern = RelayLinkSigningKeypairSpecifierPattern;

    fn key_specifier() -> Self::Specifier {
        Self::Specifier::new(Self::valid_until())
    }
    fn label() -> &'static str {
        "KP_link_ed"
    }
    fn spec_from_keypath(keypath: &KeyPath) -> Result<Self::Specifier, tor_keymgr::KeyPathError> {
        keypath.try_into()
    }
    fn valid_until() -> Timestamp {
        // Taken from C-tor.
        Timestamp::from(SystemTime::now() + Duration::from_secs(2 * 86400))
    }
    fn valid_until_from_spec(spec: &Self::Specifier) -> Timestamp {
        spec.valid_until()
    }
}

/// Start the rotation key task.
pub(crate) fn start_task<R: Runtime>(
    task_set: &mut JoinSet<Result<void::Void, anyhow::Error>>,
    runtime: R,
    keymgr: Arc<KeyMgr>,
) {
    task_set.spawn({
        async {
            rotate_keys_task(runtime, keymgr)
                .await
                .context("Failed to run key rotation task")
        }
    });
}

/// Generate a key implementing the [`RotatableKeySpec`] directly into the key manager.
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
        // Key already existing can happen due to wall clock strangeness,
        // so simply ignore it.
        Ok(_) | Err(tor_keymgr::Error::KeyAlreadyExists) => (),
        Err(e) => return Err(e),
    };
    Ok(())
}

/// Rotate a key implementing the [`RotatableKeySpec`] trait.
///
/// Rotation is done by listing all keys matching the key specifier pattern and validting the
/// valid_until value of the key store entry. If expired, the key is removed from the key manager.
fn rotate_key<K>(keymgr: &KeyMgr) -> anyhow::Result<()>
where
    K: RotatableKeySpec,
    <K::Keypair as ToEncodableKey>::Key: Keygen,
{
    // Select all signing keypair in the keystore because we need to inspect the valid_until
    // field and rotate if expired.
    let key_entries = keymgr.list_matching(&K::Pattern::new_any().arti_pattern()?)?;

    if key_entries.is_empty() {
        generate_key::<K::Keypair>(keymgr, &K::key_specifier())?;
        return Ok(());
    }

    for key in key_entries {
        let entry_key_spec: K::Specifier = K::spec_from_keypath(key.key_path())?;

        // Account for the sleep time of the task so we don't expire in between runs.
        if K::valid_until_from_spec(&entry_key_spec)
            <= Timestamp::from(SystemTime::now() + KEY_ROTATION_SLEEP_DURATION)
        {
            tracing::info!(
                "Rotating {} key. Next expiry timestamp {:?}",
                K::label(),
                K::valid_until()
            );
            keymgr.remove_entry(&key)?;
            generate_key::<K::Keypair>(keymgr, &K::key_specifier())?;
        };
    }

    Ok(())
}

/// Attempt to rotate all rotatable keys.
fn try_rotate_keys(keymgr: &KeyMgr) -> anyhow::Result<()> {
    // Attempt to rotate the KP_relaysign_ed.
    rotate_key::<RelaySigningKeypair>(keymgr)?;
    // Attempt to rotate the KP_link_ed.
    rotate_key::<RelayLinkSigningKeypair>(keymgr)?;
    Ok(())
}

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
        .get(&RelayIdentityRsaKeypairSpecifier::new())?
        .context("Missing RSA identity")?;
    let ed_id_kp: RelayIdentityKeypair = keymgr
        .get(&RelayIdentityKeypairSpecifier::new())?
        .context("Missing Ed25519 identity")?;
    // We have to list match here because the key specifier here uses a valid_until. We don't know
    // what it is so we list and take the first one.
    let link_sign_kp: RelayLinkSigningKeypair = keymgr
        .get_entry(
            keymgr
                .list_matching(&RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
                .first()
                .context("No store entry for link authentication key")?,
        )?
        .context("Missing link authentication key")?;
    let kp_relaysign_id: RelaySigningKeypair = keymgr
        .get_entry(
            keymgr
                .list_matching(&RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
                .first()
                .context("No store entry for signing key")?,
        )?
        .context("Missing signing key")?;

    // TLS key and cert. Random hostname like C-tor. We re-use the issuer_hostname for the RSA
    // legacy cert.
    let issuer_hostname = rand_hostname::random_hostname(&mut rng);
    let subject_hostname = rand_hostname::random_hostname(&mut rng);
    let tls_key_and_cert =
        TlsKeyAndCert::create(&mut rng, now, &issuer_hostname, &subject_hostname)?;

    // Create the RSA X509 certificate.
    let cert_id_x509_rsa = tor_cert::x509::create_legacy_rsa_id_cert(
        &mut rng,
        SystemTime::now(),
        &issuer_hostname,
        rsa_id_kp.keypair(),
    )?;

    // Taken from C-tor.
    let lifetime_2days = now + Duration::from_secs(2 * 24 * 60 * 60);
    let lifetime_30days = now + Duration::from_secs(30 * 24 * 60 * 60);
    let lifetime_6months = now + Duration::from_secs(6 * 30 * 24 * 60 * 60);

    let cert_id_rsa = tor_cert::rsa::EncodedRsaCrosscert::encode_and_sign(
        rsa_id_kp.keypair(),
        &ed_id_kp.to_ed25519_id(),
        lifetime_6months,
    )?;

    // Create the signing key cert, link cert and tls cert.
    //
    // TODO(relay): We need to check the KeyMgr for the signing cert but for now the KeyMgr API
    // doesn't allow us to get it out. We will do a re-design of the cert API there. This is fine
    // as long as we don't support offline keys.
    let cert_id_sign_ed = gen_signing_cert(&ed_id_kp, &kp_relaysign_id, lifetime_30days)?;
    let cert_sign_link_auth_ed = gen_link_cert(&kp_relaysign_id, &link_sign_kp, lifetime_2days)?;
    let cert_sign_tls_ed = gen_tls_cert(
        &kp_relaysign_id,
        *tls_key_and_cert.link_cert_sha256(),
        lifetime_2days,
    )?;

    Ok(RelayIdentities::new(
        rsa_id_kp.to_rsa_identity(),
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
    // Note that generate_key() won't error if the key already exists.

    // Attempt to generate our identity keys (ed and RSA). Those keys DO NOT rotate.
    generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())?;
    generate_key::<RelayIdentityRsaKeypair>(keymgr, &RelayIdentityRsaKeypairSpecifier::new())?;
    // Attempt to rotate the rotatable keys which will generate any missing.
    try_rotate_keys(keymgr)?;

    // Now that we have our up-to-date keys, build the RelayIdentities object.
    build_proto_identities(keymgr)
}

/// Task to rotate keys when they need to be rotated.
pub(crate) async fn rotate_keys_task<R: Runtime>(
    runtime: R,
    keymgr: Arc<KeyMgr>,
) -> anyhow::Result<void::Void> {
    loop {
        // Attempt a rotation of all keys.
        try_rotate_keys(&keymgr)?;

        // Wake up every minute.
        let next_wake = SystemTime::now() + KEY_ROTATION_SLEEP_DURATION;
        runtime.sleep_until_wallclock(next_wake).await;
    }
}
