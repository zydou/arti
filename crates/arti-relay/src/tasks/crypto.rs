//! Key rotation tasks of the relay.

mod keys;
mod views;

use anyhow::{Context, anyhow};
use base64ct::{Base64Unpadded, Encoding};
use futures::{FutureExt as _, StreamExt as _, channel::mpsc};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::trace;

use tor_async_utils::{mpsc_channel_no_memquota, oneshot};
use tor_chanmgr::ChanMgr;
use tor_error::warn_report;
use tor_keymgr::KeyMgr;
use tor_netdir::{DirEvent, NetDirProvider};
use tor_proto::RelayChannelAuthMaterial;
use tor_proto::relay::CreateRequestHandler;
use tor_relay_crypto::pk::{
    RelayIdentityKeypair, RelayIdentityRsaKeypair, RelayNtorKeys, RelayNtorPublicKey,
    RelaySigningKeypair,
};
use tor_rtcompat::{Runtime, SleepProviderExt};

use crate::{
    keys::{RelayIdentityKeypairSpecifier, RelayIdentityRsaKeypairSpecifier},
    tasks::{
        crypto::views::FullKeyView,
        descriptor::{DescriptorCommand, DescriptorCommandSender},
    },
};

/// Buffer time before key expiry to trigger rotation. This ensures we rotate slightly before the
/// key actually expires rather than right at or after expiry.
///
/// C-tor uses 3 hours for the link/auth key and 1 day for the signing key. Let's use 3 hours here,
/// it should be plenty to make it happen even if hiccups happen.
const KEY_ROTATION_EXPIRE_BUFFER: Duration = Duration::from_secs(3 * 60 * 60);

/// A command sent handled by the [`Reactor`] over a command channel.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum CryptoCommand {
    /// Request to get the latest ntor key.
    GetLatestNtorKey {
        /// Reply channel for the key.
        tx: oneshot::Sender<RelayNtorPublicKey>,
    },
    /// Request to get the relay signing key.
    GetSignKey {
        /// Reply channel for the key.
        tx: oneshot::Sender<RelaySigningKeypair>,
    },
}

/// The sending side of the [`DescriptorCommand`] channel.
pub(crate) type CryptoCommandSender = mpsc::Sender<CryptoCommand>;
/// The receiving side of the [`DescriptorCommand`] channel.
pub(crate) type CryptoCommandReceiver = mpsc::Receiver<CryptoCommand>;

/// Returns a new [`CryptoCommand`] channel.
///
/// This is a bounded to limit key request spamming (in case of a bug).
pub(crate) fn new_command_channel() -> (CryptoCommandSender, CryptoCommandReceiver) {
    mpsc_channel_no_memquota(128)
}

/// Key rotation parameters derived from the consensus.
#[derive(Copy, Clone, Debug)]
struct KeyRotationParams {
    /// How long a newly generated ntor key is valid.
    ntor_lifetime: Duration,
    /// How long after expiry the ntor key is still accepted for incoming circuits.
    ntor_grace_period: Duration,
}

impl From<&tor_netdir::params::NetParameters> for KeyRotationParams {
    fn from(params: &tor_netdir::params::NetParameters) -> Self {
        let rotation_days = params.onion_key_rotation_days.get() as u64;
        // Grace period is clamped to [1, rotation_days] per the spec.
        let grace_days = (params.onion_key_grace_period_days.get() as u64).min(rotation_days);
        Self {
            ntor_lifetime: Duration::from_secs(rotation_days * 24 * 60 * 60),
            ntor_grace_period: Duration::from_secs(grace_days * 24 * 60 * 60),
        }
    }
}

/// Key material generated/loaded at init.
///
/// This is specific to be at the relay startup and only returned by `try_generate_keys()` that is
/// only called before the relay starts.
pub(crate) struct InitKeyMaterial {
    /// Channel authentication key material.
    pub(crate) chan_auth_keys: RelayChannelAuthMaterial,
    /// Ntor keys.
    pub(crate) ntor_keys: RelayNtorKeys,
}

/// Attempt to initialize the key material needed for a relay to function. This function will
/// generate any missing keys or load them from the given [`KeyMgr`]. The keys are:
///
/// * Identity Ed25519 keypair.
/// * Identity RSA.
/// * Relay signing keypair.
/// * Relay link signing keypair.
/// * Relay ntor keypair.
///
/// This function is only called when our relay initializes in order to attempt to generate any
/// missing keys or/and rotate expired keys.
///
/// Returned the initialization key material.
pub(crate) fn init_keys<R: Runtime>(
    runtime: &R,
    keymgr: &KeyMgr,
) -> anyhow::Result<InitKeyMaterial> {
    let now = runtime.wallclock();

    // Attempt to generate our identity keys (ed and RSA). Those keys DO NOT rotate. It won't be
    // replaced if they already exists.
    keys::generate_key::<RelayIdentityKeypair>(keymgr, &RelayIdentityKeypairSpecifier::new())?;
    keys::generate_key::<RelayIdentityRsaKeypair>(
        keymgr,
        &RelayIdentityRsaKeypairSpecifier::new(),
    )?;

    // Attempt to rotate the keys. Any missing keys (and cert) will be generated. At bootstrap
    // there is no consensus yet, so we have to use the default parameters.
    let _ = keys::try_rotate_keys(
        now,
        keymgr,
        KeyRotationParams::from(&tor_netdir::params::NetParameters::default()),
    )?;

    // Throwaway full key view only for this purpose.
    let key_view = FullKeyView::new(keymgr)?;

    Ok(InitKeyMaterial {
        chan_auth_keys: keys::build_proto_relay_auth_material(now, &key_view)?,
        ntor_keys: key_view.ks_ntor_keys()?,
    })
}

/// Reactor object handling the rotation of relay crypto keys.
pub(crate) struct Reactor<R: Runtime> {
    /// Underlying runtime for a time provider.
    runtime: R,
    /// Reference to the arti-relay channel manager [`ChanMgr`]
    chanmgr: Arc<ChanMgr<R>>,
    /// Reference to the create request handler so we can update it.
    create_request_handler: Arc<CreateRequestHandler>,
    /// Full key view.
    view: FullKeyView<KeyMgr>,
    /// Net directory provider used to watch for consensus changes.
    netdir: Arc<dyn NetDirProvider>,
    /// Descriptor task TX channel.
    desc_tx: DescriptorCommandSender,
    /// Our crypto command RX channel.
    our_rx: CryptoCommandReceiver,
}

impl<R: Runtime> Reactor<R> {
    /// Constructor.
    pub(crate) fn new(
        runtime: R,
        chanmgr: Arc<ChanMgr<R>>,
        create_request_handler: Arc<CreateRequestHandler>,
        keymgr: KeyMgr,
        netdir: Arc<dyn NetDirProvider>,
        desc_tx: DescriptorCommandSender,
        our_rx: CryptoCommandReceiver,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            runtime,
            chanmgr,
            create_request_handler,
            view: FullKeyView::new(keymgr)?,
            netdir,
            desc_tx,
            our_rx,
        })
    }

    /// Log the relay's identities and public ntor key.
    fn log_public_keys(&self) -> anyhow::Result<()> {
        let rsa_id = self.view.ks_relayid_rsa()?.to_rsa_identity();
        let ed_id = self.view.ks_relayid_ed()?.to_ed25519_id();

        let ntor_keys = self.view.ks_ntor_keys()?;
        // Base64-encode the public ntor key.
        let ntor = Base64Unpadded::encode_string(ntor_keys.latest().public().inner().as_bytes());

        // Log the relay's identities.
        // TODO: We should also log this after a key rotation:
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3773#note_3367789
        // TODO: This is useful at info level while we're developing,
        // but the level should probably be lowered in the future.
        tracing::info!("RSA identity: {rsa_id}");
        tracing::info!("Ed25519 identity: {ed_id}");
        tracing::info!("Ntor public key: {ntor}");

        Ok(())
    }

    /// Handle a [`CryptoCommand`] received by the reactor.
    fn handle_command(&mut self, cmd: CryptoCommand) -> anyhow::Result<()> {
        match cmd {
            CryptoCommand::GetLatestNtorKey { tx } => {
                let pubkey = self.view.ks_ntor_keys()?.latest().public();
                tx.send(pubkey)
                    .map_err(|_| anyhow!("GetLatestNtorKey replay tx failed"))?;
            }
            CryptoCommand::GetSignKey { tx } => {
                let keypair = self.view.ks_relaysign_ed()?;
                tx.send(keypair)
                    .map_err(|_| anyhow!("GetSignKey replay tx failed"))?;
            }
        }

        Ok(())
    }

    /// Launch the reactor, and run until an error is encountered.
    pub(crate) async fn run(mut self) -> anyhow::Result<void::Void> {
        trace!("Starting crypto reactor task");

        // Subscribe before the first run_once() so we don't miss any events that arrive
        // between startup and entering the select loop.
        let mut consensus_events = self
            .netdir
            .events()
            .filter(|ev| std::future::ready(matches!(ev, DirEvent::NewConsensus)));

        // TODO: This is mostly useful for debugging.
        // We might want to remove this in the future, or move this somewhere else.
        self.log_public_keys()
            .context("Failed to log public keys")?;

        loop {
            let next_wake = self.run_once()?;
            futures::select! {
                // Sleep until next wake up.
                _ = self.runtime.sleep_until_wallclock(next_wake).fuse() => {}
                // New consensus arrived, might be new parameters. Run the loop, it will pickup the
                // latest.
                ev = consensus_events.next().fuse() => {
                    ev.context("NetDir event stream ended unexpectedly")?;
                }
                // Crypto command channel.
                cmd = self.our_rx.next().fuse() => {
                    let cmd = cmd.context("Crypto command channel closed")?;
                    if let Err(e) = self.handle_command(cmd) {
                        warn_report!(e, "Crypto task command failure");
                    }
                }
            }
        }
    }

    /// Helper: run once to handle a single rotation tick.
    fn run_once(&mut self) -> anyhow::Result<SystemTime> {
        let now = self.runtime.wallclock();
        // Attempt a rotation of all keys.
        let (changed, next_expiry) = self.try_rotate_keys(now)?;

        if changed.link_ed || changed.relaysign_ed {
            let auth_material = keys::build_proto_relay_auth_material(now, &self.view)?;
            self.chanmgr
                .set_relay_auth_material(Arc::new(auth_material))
                .context("Failed to set relay auth material on ChanMgr")?;
        }

        if changed.ntor_latest || changed.ntor_previous {
            let ntor_keys = self.view.ks_ntor_keys()?;
            self.create_request_handler.update_ntor_keys(ntor_keys);
        }

        // Notify the descriptor task that its keys have changed.
        if changed.relay_desc_keys_changed() {
            self.desc_tx
                .try_send(DescriptorCommand::Publish)
                .context("Desc task channel try_send failed")?;
            // Note, we can never wait for the publish to finish here because the
            // descriptor task upon receiving the command will send us commands to get
            // the keys it needs. Waiting here would lead to a deadlock.
        }

        // Sleep until the earliest key expiry minus buffer so we rotate before it expires.
        // If the subtraction would underflow, wake up immediately to rotate the expired key.
        Ok(next_expiry
            .checked_sub(KEY_ROTATION_EXPIRE_BUFFER)
            .unwrap_or(now))
    }

    /// Attempt to rotate all keys except identity keys.
    ///
    /// Holds the write lock for the entire rotate + reconcile to prevent the race where another
    /// task reads a key between the keymgr update and the cache update.
    ///
    /// Returns which key types changed and the earliest expiry time across all keys.
    fn try_rotate_keys(
        &mut self,
        now: SystemTime,
    ) -> anyhow::Result<(views::ValidUntilChanged, SystemTime)> {
        let rotation_params = KeyRotationParams::from(self.netdir.params().as_ref().as_ref());
        let next_expiry = keys::try_rotate_keys(now, self.view.keymgr(), rotation_params)?;
        let changed = self.view.recompute_valid_until()?;
        Ok((changed, next_expiry))
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

    use super::*;

    use tor_keymgr::{ArtiEphemeralKeystore, KeyMgrBuilder};
    use tor_rtmock::MockRuntime;

    /// Initialize test basics that is runtime and a KeyMgr.
    pub(super) fn new_keymgr() -> KeyMgr {
        let store = Box::new(ArtiEphemeralKeystore::new("test".to_string()));
        KeyMgrBuilder::default()
            .primary_store(store)
            .build()
            .unwrap()
    }

    /// Test the actual bootstrap function, `try_generate_keys()` which is in charge of
    /// initializing the auth material.
    #[test]
    fn test_bootstrap() {
        MockRuntime::test_with_various(|runtime| async move {
            let _auth_material = match init_keys(&runtime, &new_keymgr()) {
                Ok(a) => a,
                Err(e) => {
                    panic!("Unable to bootstrap keys and generate RelayChannelAuthMaterial: {e}");
                }
            };
        });
    }
}
