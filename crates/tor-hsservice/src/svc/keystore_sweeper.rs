//! Helpers for removing expired hidden service keys from the keystores.

use std::sync::Arc;

use crate::{
    BlindIdKeypairSpecifier, BlindIdPublicKeySpecifier, DescSigningKeypairSpecifier, HsNickname,
    StartupError,
};
use futures::task::SpawnExt;
use futures::StreamExt;
use tor_error::error_report;
use tor_keymgr::KeyMgr;
use tor_netdir::{DirEvent, NetDirProvider};
use tor_rtcompat::Runtime;

/// A helper for removing the expired keys of a hidden service.
///
/// [`KeystoreSweeper::launch`] starts a task that periodically removes expired keys from the key
/// store.
pub(crate) struct KeystoreSweeper<R: Runtime> {
    /// The runtime
    runtime: R,
    /// The nickname of the service for which to remove keys.
    nickname: HsNickname,
    /// A keymgr used to look up our keys and store new medium-term keys.
    keymgr: Arc<KeyMgr>,
    /// A netdir provider for watching for consensus changes.
    netdir_provider: Arc<dyn NetDirProvider>,
}

impl<R: Runtime> KeystoreSweeper<R> {
    /// Create a new, unlaunched, [`KeystoreSweeper`].
    pub(crate) fn new(
        runtime: R,
        nickname: HsNickname,
        keymgr: Arc<KeyMgr>,
        netdir_provider: Arc<dyn NetDirProvider>,
    ) -> Self {
        Self {
            runtime,
            nickname,
            keymgr,
            netdir_provider,
        }
    }

    /// Start a task for removing keys when they expire.
    pub(crate) fn launch(self) -> Result<(), StartupError> {
        let KeystoreSweeper {
            runtime,
            nickname,
            keymgr,
            netdir_provider,
        } = self;

        let () = runtime
            .spawn(async move {
                let match_all_arti_pat = tor_keymgr::KeyPathPattern::Arti("*".into());

                while let Some(event) = netdir_provider.events().next().await {
                    if event == DirEvent::NewConsensus {
                        let netdir = match netdir_provider.timely_netdir() {
                            Ok(netdir) => netdir,
                            Err(e) => {
                                error_report!(e, "failed to get a timely netdir");
                                continue;
                            }
                        };

                        let relevant_periods = netdir.hs_all_time_periods();
                        // The consensus changed, so we need to remove any expired keys.
                        let expire_keys = || -> tor_keymgr::Result<()> {
                            let all_arti_keys = keymgr.list_matching(&match_all_arti_pat)?;

                            for (key_path, key_type) in all_arti_keys {
                                /// Remove the specified key, if it's no longer relevant.
                                macro_rules! remove_if_expired {
                                    ($K:ty) => {{
                                        if let Ok(spec) = <$K>::try_from(&key_path) {
                                            // Only remove the keys of the hidden service that concerns us
                                            if &spec.nickname == &nickname {
                                                let is_expired = !relevant_periods.contains(&spec.period);
                                                // TODO: make the keystore selector configurable
                                                let selector = Default::default();

                                                if is_expired {
                                                    keymgr.remove_with_type(&key_path, &key_type, selector)?;
                                                }
                                            }
                                        }
                                    }};
                                }

                                // TODO: any invalid/malformed keys are ignored (rather than
                                // removed).
                                remove_if_expired!(BlindIdPublicKeySpecifier);
                                remove_if_expired!(BlindIdKeypairSpecifier);
                                remove_if_expired!(DescSigningKeypairSpecifier);
                            }

                            Ok(())
                        };

                        if let Err(e) = expire_keys() {
                            error_report!(e, "failed to remove expired keys");
                        }
                    }
                }
            })
            .map_err(|e| StartupError::Spawn {
                spawning: "keymgr monitor task",
                cause: e.into(),
            })?;

        Ok(())
    }
}
