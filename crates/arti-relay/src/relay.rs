//! Entry point of a Tor relay that is the [`TorRelay`] objects

use std::sync::Arc;

use anyhow::Context;
use tor_chanmgr::Dormancy;
use tor_config_path::CfgPathResolver;
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

/// An initialized but unbootstrapped relay.
///
/// This intentionally does not have access to the runtime to prevent it from doing network io.
///
/// The idea is that we can build up the relay's components in an `InertTorRelay` without a runtime,
/// and then call `bootstrap()` on it and provide a runtime to turn it into a network-capable relay.
/// This gives us two advantages:
///
/// - We can initialize the internal data structures in the `InertTorRelay` (load the keystores,
///   configure memquota, etc), which leaves `TorRelay` to just "running" the relay (bootstrapping,
///   setting up listening sockets, etc). We don't need to combine the initialization and "running
///   the relay" all within the same object.
/// - We will likely want to share some of arti's key management subcommands in the future.
///   arti-client has an `InertTorClient` which is used so that arti subcommands can access the
///   keystore. If we do a similar thing here in arti-relay in the future, it might be nice to have
///   an `InertTorRelay` which has these internal data structures, but doesn't need a runtime or
///   have any networking capabilities.
///
/// Time will tell if this ends up being a bad design decision in practice, and we can always change
/// it later.
#[derive(Clone)]
pub(crate) struct InertTorRelay {
    /// The configuration options for the relay.
    config: TorRelayConfig,
    /// Path resolver for expanding variables in [`CfgPath`](tor_config_path::CfgPath)s.
    #[expect(unused)] // TODO RELAY remove
    path_resolver: CfgPathResolver,
    /// Key manager holding all relay keys and certificates.
    keymgr: Arc<KeyMgr>,
}

impl InertTorRelay {
    /// Create a new Tor relay with the given configuration.
    pub(crate) fn new(
        config: TorRelayConfig,
        path_resolver: CfgPathResolver,
    ) -> anyhow::Result<Self> {
        let keymgr =
            Self::create_keymgr(&config, &path_resolver).context("Failed to create key manager")?;

        Ok(Self {
            config,
            path_resolver,
            keymgr,
        })
    }

    /// Connect the [`InertTorRelay`] to the Tor network.
    pub(crate) async fn bootstrap<R: Runtime>(self, runtime: R) -> anyhow::Result<TorRelay<R>> {
        TorRelay::bootstrap(runtime, self).await
    }

    /// Create the [key manager](KeyMgr).
    fn create_keymgr(
        config: &TorRelayConfig,
        path_resolver: &CfgPathResolver,
    ) -> anyhow::Result<Arc<KeyMgr>> {
        let key_store_dir = config
            .storage
            .keystore_dir(path_resolver)
            .context("Failed to get key store directory")?;
        let permissions = config.storage.permissions();

        // Store for the short-term keys that we don't need to keep on disk. The store identifier
        // is relay explicit because it can be used in other crates for channel and circuit.
        let ephemeral_store = ArtiEphemeralKeystore::new("relay-ephemeral".into());
        let persistent_store =
            ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, permissions)
                .context("Failed to construct the native keystore")?;
        info!("Using relay keystore from {key_store_dir:?}");

        let keymgr = Arc::new(
            KeyMgrBuilder::default()
                .primary_store(Box::new(persistent_store))
                .set_secondary_stores(vec![Box::new(ephemeral_store)])
                .build()
                .context("Failed to build the 'KeyMgr'")?,
        );

        // Attempt to generate any missing keys/cert from the KeyMgr.
        Self::try_generate_keys(&keymgr).context("Failed to generate keys")?;

        Ok(keymgr)
    }

    /// Generate the relay keys.
    fn try_generate_keys(keymgr: &KeyMgr) -> anyhow::Result<()> {
        let mut rng = tor_llcrypto::rng::CautiousRng;

        // Attempt to get the relay long-term identity key from the key manager. If not present,
        // generate it. We need this key to sign the signing certificates.
        let _kp_relay_id = keymgr
            .get_or_generate::<RelayIdentityKeypair>(
                &RelayIdentityKeypairSpecifier::new(),
                KeystoreSelector::default(),
                &mut rng,
            )
            .context("Failed to get or generate the long-term identity key")?;

        // TODO #1598: We need to get_or_generate RSA keys here, but that currently fails because
        // upstream ssh-key doesn't support 1024 bit keys. Once they do, we should add that here.

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

/// Represent an active Relay on the Tor network.
#[derive(Clone)]
pub(crate) struct TorRelay<R: Runtime> {
    /// Asynchronous runtime object.
    #[expect(unused)] // TODO RELAY remove
    runtime: R,

    /// Channel manager, used by circuits etc.
    #[expect(unused)] // TODO RELAY remove
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,

    /// Key manager holding all relay keys and certificates.
    #[expect(unused)] // TODO RELAY remove
    keymgr: Arc<KeyMgr>,
}

impl<R: Runtime> TorRelay<R> {
    /// Create a new Tor relay with the given [`runtime`][tor_rtcompat].
    ///
    /// Expected to be called from [`InertTorRelay::bootstrap()`].
    async fn bootstrap(runtime: R, inert: InertTorRelay) -> anyhow::Result<Self> {
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &inert.config.channel,
            Dormancy::Active,
            &NetParameters::default(),
            ToplevelAccount::new_noop(), // TODO RELAY get mq from TorRelay
            Some(inert.keymgr.clone()),
        ));

        // TODO: missing the actual bootstrapping

        Ok(Self {
            runtime,
            chanmgr,
            keymgr: inert.keymgr,
        })
    }
}
