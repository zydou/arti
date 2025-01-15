//! Entry point of a Tor relay that is the [`TorRelay`] objects

use std::sync::Arc;

use tor_chanmgr::Dormancy;
use tor_config_path::CfgPathResolver;
use tor_error::internal;
use tor_keymgr::{
    ArtiEphemeralKeystore, ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeystoreSelector,
};
use tor_memquota::ArcMemoryQuotaTrackerExt as _;
use tor_netdir::params::NetParameters;
use tor_proto::memquota::ToplevelAccount;
use tor_relay_crypto::pk::{RelayIdentityKeypair, RelayIdentityKeypairSpecifier};
use tor_rtcompat::Runtime;
use tracing::info;

use crate::config::TorRelayConfig;
use crate::err::ErrorDetail;

/// Represent an active Relay on the Tor network.
#[derive(Clone)]
pub(crate) struct TorRelay<R: Runtime> {
    /// Asynchronous runtime object.
    #[allow(unused)] // TODO RELAY remove
    runtime: R,
    /// Path resolver for expanding variables in [`CfgPath`](tor_config_path::CfgPath)s.
    #[allow(unused)] // TODO RELAY remove
    path_resolver: CfgPathResolver,
    /// Channel manager, used by circuits etc.,
    #[allow(unused)] // TODO RELAY remove
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    /// Key manager holding all relay keys and certificates.
    #[allow(unused)] // TODO RELAY remove
    keymgr: Arc<KeyMgr>,
}

impl<R: Runtime> TorRelay<R> {
    /// Create a new Tor relay with the given [runtime][tor_rtcompat] and configuration.
    pub(crate) fn new(
        runtime: R,
        config: &TorRelayConfig,
        path_resolver: CfgPathResolver,
    ) -> Result<Self, ErrorDetail> {
        let keymgr = Self::create_keymgr(config, &path_resolver)?;
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &config.channel,
            Dormancy::Active,
            &NetParameters::default(),
            ToplevelAccount::new_noop(), // TODO RELAY get mq from TorRelay
        ));

        Ok(Self {
            runtime,
            path_resolver,
            chanmgr,
            keymgr,
        })
    }

    /// Create the [key manager](KeyMgr).
    fn create_keymgr(
        config: &TorRelayConfig,
        path_resolver: &CfgPathResolver,
    ) -> Result<Arc<KeyMgr>, ErrorDetail> {
        let key_store_dir = config.storage.keystore_dir(path_resolver)?;
        let permissions = config.storage.permissions();

        // Store for the short-term keys that we don't need to keep on disk. The store identifier
        // is relay explicit because it can be used in other crates for channel and circuit.
        let ephemeral_store = ArtiEphemeralKeystore::new("relay-ephemeral".into());
        let persistent_store =
            ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)?;
        info!("Using relay keystore from {key_store_dir:?}");

        let keymgr = Arc::new(
            KeyMgrBuilder::default()
                .primary_store(Box::new(persistent_store))
                .set_secondary_stores(vec![Box::new(ephemeral_store)])
                .build()
                .map_err(|e| internal!("Failed to build KeyMgr: {e}"))?,
        );

        // Attempt to generate any missing keys/cert from the KeyMgr.
        Self::try_generate_keys(&keymgr)?;

        Ok(keymgr)
    }

    /// Generate the relay keys.
    fn try_generate_keys(keymgr: &KeyMgr) -> Result<(), ErrorDetail> {
        let mut rng = rand::thread_rng();

        // Attempt to get the relay long-term identity key from the key manager. If not present,
        // generate it. We need this key to sign the signing certificates.
        let _kp_relay_id = keymgr.get_or_generate::<RelayIdentityKeypair>(
            &RelayIdentityKeypairSpecifier::new(),
            KeystoreSelector::default(),
            &mut rng,
        )?;

        // TODO: Once certificate supports is added to the KeyMgr, we need to get/gen the
        // RelaySigning (KP_relaysign_ed) certs from the native persistent store.
        //
        // If present, rotate it if expired. Else, generate it. Rotation or creation require the
        // relay identity keypair (above) in order to sign the RelaySigning.
        //
        // We then need to generate the RelayLink (KP_link_ed) certificate which is in turn signed
        // by the RelaySigning cert.

        Ok(())
    }
}
