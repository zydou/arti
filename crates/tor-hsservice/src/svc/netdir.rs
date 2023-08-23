//! Helpers for obtaining `NetDir`s.

use futures::StreamExt as _;
use std::sync::Arc;
use tor_linkspec::RelayIds;
use tor_netdir::{NetDir, NetDirProvider};

/// Get a NetDir from `provider`, waiting until one exists.
///
/// TODO: perhaps this function would be more generally useful if it were not here?
pub(crate) async fn wait_for_netdir(
    provider: &dyn NetDirProvider,
    timeliness: tor_netdir::Timeliness,
) -> Result<Arc<NetDir>, NetdirProviderShutdown> {
    if let Ok(nd) = provider.netdir(timeliness) {
        return Ok(nd);
    }

    let mut stream = provider.events();
    loop {
        // We need to retry `provider.netdir()` before waiting for any stream events, to
        // avoid deadlock.
        //
        // TODO HSS: propagate _some_ possible errors here.
        if let Ok(nd) = provider.netdir(timeliness) {
            return Ok(nd);
        }
        match stream.next().await {
            Some(_) => {}
            None => {
                return Err(NetdirProviderShutdown);
            }
        }
    }
}

/// Wait until `provider` lists `target`.
pub(crate) async fn wait_for_netdir_to_list(
    provider: &dyn NetDirProvider,
    target: &RelayIds,
) -> Result<(), NetdirProviderShutdown> {
    let mut events = provider.events();
    loop {
        // See if the desired relay is in the netdir.
        //
        // We do this before waiting for any events, to avoid race conditions.
        {
            let netdir = wait_for_netdir(provider, tor_netdir::Timeliness::Timely).await?;
            // TODO HSS: Perhaps we should distinguish Some(false) from None.
            //
            // Some(false) means "this relay is definitely not in the current
            // network directory" and None means "waiting for more info on this
            // network directory"
            if netdir.ids_listed(target) == Some(true) {
                return Ok(());
            }
        }
        // We didn't find the relay; wait for the provider to have a new netdir.
        if events.next().await.is_none() {
            // The event stream is closed; the provider has shut down.
            return Err(NetdirProviderShutdown);
        }
    }
}

/// The network directory provider is shutting down without giving us the
/// netdir we asked for.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Network directory provider is shutting down")]
pub(crate) struct NetdirProviderShutdown;
