//! Key rotation tasks of the relay.

use anyhow::Context;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::task::JoinSet;

use tor_keymgr::{
    KeyMgr, KeyPath, KeySpecifier, KeySpecifierPattern, Keygen, KeystoreSelector, ToEncodableKey,
};
use tor_relay_crypto::pk::{
    RelayIdentityKeypair, RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypair,
    RelayIdentityRsaKeypairSpecifier, RelayLinkSigningKeypair, RelayLinkSigningKeypairSpecifier,
    RelayLinkSigningKeypairSpecifierPattern, RelaySigningKeypair, RelaySigningKeypairSpecifier,
    RelaySigningKeypairSpecifierPattern, Timestamp,
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

/// Attempt to generate all keys.
///
/// This function is only called when our relay bootstraps in order to attempt to generate any
/// missing keys or/and rotate expired keys.
pub(crate) fn try_generate_keys(keymgr: &KeyMgr) -> anyhow::Result<()> {
    // Note that generate_key() won't error if the key already exists.

    // Attempt to generate our identity keys (ed and RSA). Those keys DO NOT rotate.
    generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())?;
    generate_key::<RelayIdentityRsaKeypair>(keymgr, &RelayIdentityRsaKeypairSpecifier::new())?;
    // Attempt to rotate the rotatable keys which will generate any missing.
    try_rotate_keys(keymgr)
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
