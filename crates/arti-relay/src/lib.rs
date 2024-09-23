pub mod builder;
mod config;
mod err;

pub use err::Error;

use std::sync::Arc;

use tor_chanmgr::Dormancy;
use tor_error::internal;
use tor_keymgr::{
    ArtiEphemeralKeystore, ArtiNativeKeystore, KeyMgr, KeyMgrBuilder, KeystoreSelector,
};
use tor_netdir::params::NetParameters;
use tor_relay_crypto::pk::{RelayIdentityKeySpecifier, RelayIdentityKeypair};
use tor_rtcompat::Runtime;
use tracing::info;

use crate::{builder::TorRelayBuilder, config::TorRelayConfig, err::ErrorDetail};

// Only rustls is supported.
#[cfg(all(feature = "rustls", any(feature = "async-std", feature = "tokio")))]
use tor_rtcompat::PreferredRuntime;

/// Represent an active Relay on the Tor network.
#[derive(Clone)]
pub struct TorRelay<R: Runtime> {
    /// Asynchronous runtime object.
    #[allow(unused)] // TODO RELAY remove
    runtime: R,
    /// Channel manager, used by circuits etc.,
    #[allow(unused)] // TODO RELAY remove
    chanmgr: Arc<tor_chanmgr::ChanMgr<R>>,
    /// Key manager holding all relay keys and certificates.
    #[allow(unused)] // TODO RELAY remove
    keymgr: Arc<KeyMgr>,
}

/// TorRelay can't be used with native-tls due to the lack of RFC5705 (keying material exporter).
#[cfg(all(feature = "rustls", any(feature = "async-std", feature = "tokio")))]
impl TorRelay<PreferredRuntime> {
    /// Return a new builder for creating a TorRelay object.
    ///
    /// # Panics
    ///
    /// If Tokio is being used (the default), panics if created outside the context of a currently
    /// running Tokio runtime. See the documentation for `tokio::runtime::Handle::current` for
    /// more information.
    ///
    /// If using `async-std`, either take care to ensure Arti is not compiled with Tokio support,
    /// or manually create an `async-std` runtime using [`tor_rtcompat`] and use it with
    /// [`TorRelay::with_runtime`].
    pub fn builder() -> TorRelayBuilder<PreferredRuntime> {
        let runtime = PreferredRuntime::current().expect(
            "TorRelay could not get an asynchronous runtime; are you running in the right context?",
        );
        TorRelayBuilder::new(runtime)
    }
}

impl<R: Runtime> TorRelay<R> {
    /// Return a new builder for creating TorRelay objects, with a custom provided [`Runtime`].
    ///
    /// See the [`tor_rtcompat`] crate for more information on custom runtimes.
    pub fn with_runtime(runtime: R) -> TorRelayBuilder<R> {
        TorRelayBuilder::new(runtime)
    }

    /// Return a TorRelay object.
    pub(crate) fn create_inner(runtime: R, config: &TorRelayConfig) -> Result<Self, ErrorDetail> {
        let keymgr = Self::create_keymgr(config)?;
        let chanmgr = Arc::new(tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &config.channel,
            Dormancy::Active,
            &NetParameters::from_map(&config.override_net_params),
        ));
        Ok(Self {
            runtime,
            chanmgr,
            keymgr,
        })
    }

    fn create_keymgr(config: &TorRelayConfig) -> Result<Arc<KeyMgr>, ErrorDetail> {
        let key_store_dir = config.storage.keystore_dir()?;
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

    fn try_generate_keys(keymgr: &KeyMgr) -> Result<(), ErrorDetail> {
        let mut rng = rand::thread_rng();

        // Attempt to get the relay long-term identity key from the key manager. If not present,
        // generate it. We need this key to sign the signing certificates.
        let _kp_relay_id = keymgr.get_or_generate::<RelayIdentityKeypair>(
            &RelayIdentityKeySpecifier::new(),
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
