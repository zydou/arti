//! Views that restricts the access to only specific keys which are tailored for specific tasks.
//! The domain specific views use the generic view helper which wraps the [`KeyMgr`].

use anyhow::{Context, Result};
use std::borrow::Borrow;

use tor_keymgr::{KeyMgr, KeySpecifierPattern};
use tor_relay_crypto::{
    RelaySigningKeyCert,
    pk::{
        RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayLinkSigningKeypair, RelayNtorKeys,
        RelaySigningKeypair,
    },
};

use crate::keys::{
    RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier,
    RelayLinkSigningKeypairSpecifier, RelayLinkSigningKeypairSpecifierPattern,
    RelayNtorKeypairSpecifier, RelayNtorKeypairSpecifierPattern, RelaySigningKeyCertSpecifier,
    RelaySigningKeypairSpecifier, RelaySigningKeypairSpecifierPattern,
    RelaySigningPublicKeySpecifier, Timestamp,
};

/// Cache of `valid_until` timestamps for each expirable key type.
///
/// This is used in the [`FullKeyView`] to keep coherence between tasks. Updated by the crypto task
/// when keys are generated or rotated.
#[derive(Clone, Default)]
pub(super) struct ValidUntilKeys {
    /// Relay link authentication ed25519 keypair.
    pub(super) link_ed: Option<Timestamp>,
    /// Relay signing ed25519 keypair.
    pub(super) relaysign_ed: Option<Timestamp>,
    /// Ntor latest (current) keypair.
    pub(super) ntor_latest: Option<Timestamp>,
    /// Ntor previous keypair.
    pub(super) ntor_previous: Option<Timestamp>,
}

/// Indicates which valid_until cache entries changed.
///
/// This is used when recompute the valid_until cache to indicate to the caller what has changed.
#[derive(Default)]
pub(super) struct ValidUntilChanged {
    /// Relay link authentication ed25519 keypair changed.
    pub(super) link_ed: bool,
    /// Relay signing ed25519 keypair changed.
    pub(super) relaysign_ed: bool,
    /// Ntor latest (current) keypair changed.
    pub(super) ntor_latest: bool,
    /// Ntor previous keypair changed.
    pub(super) ntor_previous: bool,
}

impl ValidUntilChanged {
    /// Return true iff at least one key that is used for a relay descriptor has changed.
    ///
    /// The relay descriptor requires the relay signing key and the ntor key (onion key).
    pub(super) fn relay_desc_keys_changed(&self) -> bool {
        self.relaysign_ed || self.ntor_latest
    }
}

/// A full view of all relay keys within the [`KeyMgr`] it holds.
///
/// This keeps the key view that are used accross tasks coherent that is it keeps a cache of
/// valid_until value for expirable keys. Only keys of that valid_until are looked for which makes
/// that each task will always see the same key when doing a lookup.
///
/// That valid_until cache is updated by the crypto task when keys are generated/rotated.
///
/// Domain specific view wrap this view in order to restrict key access.
pub(super) struct FullKeyView<K: Borrow<KeyMgr>> {
    /// The relay key manager.
    keymgr: K,
    /// The keys' valid_until cache.
    ///
    /// This is so we can lookup directly any live key without walking all existing keys and find
    /// the earliest valid_until.
    keys_valid_until: ValidUntilKeys,
}

impl<K: Borrow<KeyMgr>> FullKeyView<K> {
    /// Constructor.
    pub(super) fn new(keymgr: K) -> anyhow::Result<Self> {
        let mut view = Self {
            keymgr,
            keys_valid_until: ValidUntilKeys::default(),
        };
        // Recompute now so we get a coherent cache from what exists in the KeyMgr.
        view.recompute_valid_until()?;

        Ok(view)
    }

    /// Return a reference to the key manager.
    pub(super) fn keymgr(&self) -> &KeyMgr {
        self.keymgr.borrow()
    }

    /// Rebuild the valid_until cache from the current keystore state.
    ///
    /// Reads all expirable key types from the keystore and replaces the cache. For ntor keys,
    /// entries are sorted descending so the newest is `ntor_latest` and the second (if any) is
    /// `ntor_previous`.
    ///
    /// Returns a view of which key valid_until has changed.
    pub(super) fn recompute_valid_until(&mut self) -> anyhow::Result<ValidUntilChanged> {
        let mut cache = ValidUntilKeys::default();

        if let Some(entry) = self
            .keymgr
            .borrow()
            .list_matching(&RelayLinkSigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .first()
        {
            cache.link_ed =
                Some(RelayLinkSigningKeypairSpecifier::try_from(entry.key_path())?.valid_until);
        }

        if let Some(entry) = self
            .keymgr
            .borrow()
            .list_matching(&RelaySigningKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .first()
        {
            cache.relaysign_ed =
                Some(RelaySigningKeypairSpecifier::try_from(entry.key_path())?.valid_until);
        }

        let mut ntor: Vec<Timestamp> = self
            .keymgr
            .borrow()
            .list_matching(&RelayNtorKeypairSpecifierPattern::new_any().arti_pattern()?)?
            .iter()
            .map(|entry| Ok(RelayNtorKeypairSpecifier::try_from(entry.key_path())?.valid_until))
            .collect::<anyhow::Result<_>>()?;
        // Sort in descending order.
        ntor.sort_by(|a, b| b.cmp(a));
        cache.ntor_latest = ntor.first().copied();
        cache.ntor_previous = ntor.get(1).copied();

        // Do we have another key after that and if yes, warn that too many exists.
        if ntor.get(2).is_some() {
            tracing::warn!(
                "Found more than 2 NTor keys in the keystore. This is not supposed to happen. Latest two will be used"
            );
        }

        let changed = ValidUntilChanged {
            link_ed: self.keys_valid_until.link_ed != cache.link_ed,
            relaysign_ed: self.keys_valid_until.relaysign_ed != cache.relaysign_ed,
            ntor_latest: self.keys_valid_until.ntor_latest != cache.ntor_latest,
            ntor_previous: self.keys_valid_until.ntor_previous != cache.ntor_previous,
        };

        self.keys_valid_until = cache;
        Ok(changed)
    }

    /// Return the relay ed25519 identity keypair (KS_relayid_ed).
    pub(super) fn ks_relayid_ed(&self) -> Result<RelayIdentityKeypair> {
        self.keymgr
            .borrow()
            .get(&RelayIdentityKeypairSpecifier::new())?
            .context("Missing Ed25519 identity")
    }

    /// Return the relay RSA identity keypair (KS_relayid_rsa).
    pub(super) fn ks_relayid_rsa(&self) -> Result<RelayIdentityRsaKeypair> {
        self.keymgr
            .borrow()
            .get(&RelayIdentityRsaKeypairSpecifier::new())?
            .context("Missing RSA identity")
    }

    /// Return the link authentication keypair (KS_link_ed).
    pub(super) fn ks_link_ed(&self) -> Result<RelayLinkSigningKeypair> {
        let valid_until = self
            .keys_valid_until
            .link_ed
            .ok_or(anyhow::anyhow!("No link authentication key"))?;
        self.keymgr
            .borrow()
            .get(&RelayLinkSigningKeypairSpecifier::new(valid_until))?
            .context("Missing link authentication key")
    }

    /// Return the latest and previous ntor keypairs from the keystore (KS_ntor).
    pub(super) fn ks_ntor_keys(&self) -> anyhow::Result<RelayNtorKeys> {
        let valid_until = self
            .keys_valid_until
            .ntor_latest
            .ok_or(anyhow::anyhow!("No latest ntor key"))?;
        let latest = self
            .keymgr
            .borrow()
            .get(&RelayNtorKeypairSpecifier::new(valid_until))?
            .context("Missing latest ntor key")?;
        let mut keys = RelayNtorKeys::new(latest);

        // Might not have a previous all the time.
        if let Some(valid_until) = self.keys_valid_until.ntor_previous {
            let previous = self
                .keymgr
                .borrow()
                .get(&RelayNtorKeypairSpecifier::new(valid_until))?
                .context("Missing previous ntor key")?;
            keys = keys.with_previous(previous);
        }
        Ok(keys)
    }

    /// Return the relay signing key (KS_relaysign_ed).
    pub(super) fn ks_relaysign_ed(&self) -> Result<RelaySigningKeypair> {
        let valid_until = self
            .keys_valid_until
            .relaysign_ed
            .ok_or(anyhow::anyhow!("No relay signing key"))?;
        self.keymgr
            .borrow()
            .get(&RelaySigningKeypairSpecifier::new(valid_until))?
            .context("Missing relay signing key")
    }

    /// Return the relay signing key certificate.
    pub(super) fn cert_relaysign_ed(&self) -> Result<RelaySigningKeyCert> {
        let valid_until = self
            .keys_valid_until
            .relaysign_ed
            .ok_or(anyhow::anyhow!("No relay signing key"))?;
        let (_key, cert) = self
            .keymgr
            .borrow()
            .get_key_and_cert::<RelaySigningKeypair, RelaySigningKeyCert>(
                &RelaySigningKeyCertSpecifier::new(RelaySigningPublicKeySpecifier::new(
                    valid_until,
                )),
                &RelayIdentityKeypairSpecifier::new(),
            )?
            .context("Missing relaysign_ed key and cert")?;
        Ok(cert)
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    //!
    use super::*;

    use tor_keymgr::{KeyMgr, KeystoreSelector};
    use tor_relay_crypto::pk::{RelayLinkSigningKeypair, RelayNtorKeypair, RelaySigningKeypair};

    use crate::{
        keys::{
            RelayLinkSigningKeypairSpecifier, RelayNtorKeypairSpecifier,
            RelaySigningKeypairSpecifier, Timestamp,
        },
        tasks::crypto::{keys::generate_key, test::new_keymgr},
    };

    fn ts(offset: u64) -> Timestamp {
        Timestamp::from(std::time::UNIX_EPOCH + std::time::Duration::from_secs(offset))
    }

    fn insert_link_key(keymgr: &KeyMgr, valid_until: Timestamp) {
        generate_key::<RelayLinkSigningKeypair>(
            keymgr,
            &RelayLinkSigningKeypairSpecifier::new(valid_until),
        )
        .unwrap();
    }

    fn insert_signing_key(keymgr: &KeyMgr, valid_until: Timestamp) {
        generate_key::<RelaySigningKeypair>(
            keymgr,
            &RelaySigningKeypairSpecifier::new(valid_until),
        )
        .unwrap();
    }

    fn insert_ntor_key(keymgr: &KeyMgr, valid_until: Timestamp) {
        generate_key::<RelayNtorKeypair>(keymgr, &RelayNtorKeypairSpecifier::new(valid_until))
            .unwrap();
    }

    /// Reconciling after keys are added should report them as changed.
    #[test]
    fn reconcile_new_keys() {
        let keymgr = new_keymgr();
        let mut view = FullKeyView::new(&keymgr).unwrap();

        insert_link_key(&keymgr, ts(1000));
        insert_signing_key(&keymgr, ts(2000));
        insert_ntor_key(&keymgr, ts(3000));

        let changed = view.recompute_valid_until().unwrap();

        assert!(changed.link_ed);
        assert!(changed.relaysign_ed);
        assert!(changed.ntor_latest);
        assert!(!changed.ntor_previous);
    }

    /// Reconciling twice without any keystore changes should report nothing.
    #[test]
    fn reconcile_no_change() {
        let keymgr = new_keymgr();
        let mut view = FullKeyView::new(&keymgr).unwrap();

        insert_link_key(&keymgr, ts(1000));
        insert_signing_key(&keymgr, ts(2000));
        insert_ntor_key(&keymgr, ts(3000));

        view.recompute_valid_until().unwrap();

        let changed = view.recompute_valid_until().unwrap();
        assert!(
            !changed.link_ed
                && !changed.relaysign_ed
                && !changed.ntor_latest
                && !changed.ntor_previous
        );
    }

    /// With two ntor keys, the one with the higher timestamp becomes ntor_latest and the
    /// lower one becomes ntor_previous.
    #[test]
    fn reconcile_ntor_keys() {
        let keymgr = new_keymgr();
        let mut view = FullKeyView::new(&keymgr).unwrap();

        let older_ts = ts(1000);
        let newer_ts = ts(2000);

        insert_ntor_key(&keymgr, older_ts);
        insert_ntor_key(&keymgr, newer_ts);

        let changed = view.recompute_valid_until().unwrap();

        assert!(changed.ntor_latest);
        assert!(changed.ntor_previous);
        assert_eq!(view.keys_valid_until.ntor_latest, Some(newer_ts));
        assert_eq!(view.keys_valid_until.ntor_previous, Some(older_ts));
    }

    /// After a key rotation the replaced key type appears in the changed set.
    #[test]
    fn reconcile_rotated_key() {
        let keymgr = new_keymgr();
        let mut view = FullKeyView::new(&keymgr).unwrap();

        insert_link_key(&keymgr, ts(1000));

        view.recompute_valid_until().unwrap();

        // Simulate rotation: old key is removed and a new one is inserted.
        keymgr
            .remove::<RelayLinkSigningKeypair>(
                &RelayLinkSigningKeypairSpecifier::new(ts(1000)),
                KeystoreSelector::default(),
            )
            .unwrap();
        insert_link_key(&keymgr, ts(5000));

        let changed = view.recompute_valid_until().unwrap();

        assert!(changed.link_ed);
        assert_eq!(view.keys_valid_until.link_ed, Some(ts(5000)));
    }
}
