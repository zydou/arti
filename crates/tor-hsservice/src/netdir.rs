//! Helpers for obtaining `NetDir`s.

use crate::internal_prelude::*;

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
        // We ignore all errors here: they can all potentially be fixed by
        // getting a fresh consensus, and they will all get warned about
        // by the NetDirProvider itself.
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
///
/// NOTE: This might potentially wait indefinitely, if `target` is never actually
/// becomes listed in the directory.  It will exit if the `NetDirProvider` shuts down.
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
            if netdir.ids_listed(target) == Some(true) {
                return Ok(());
            }
            // If we reach this point, then ids_listed returned `Some(false)`,
            // meaning "This relay is definitely not in the current directory";
            // or it returned `None`, meaning "waiting for more information
            // about this network directory.
            // In both cases, it's reasonable to just wait for another netdir
            // event and try again.
        }
        // We didn't find the relay; wait for the provider to have a new netdir
        // or more netdir information.
        if events.next().await.is_none() {
            // The event stream is closed; the provider has shut down.
            return Err(NetdirProviderShutdown);
        }
    }
}

/// The network directory provider is shutting down without giving us the
/// netdir we asked for.
//
// TODO maybe this (the error, or the module)
// wants to be moved to tor-netdir or something,
// since perhaps other clients there will want it.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Network directory provider is shutting down")]
#[non_exhaustive]
pub struct NetdirProviderShutdown;

impl tor_error::HasKind for NetdirProviderShutdown {
    fn kind(&self) -> ErrorKind {
        ErrorKind::ArtiShuttingDown
    }
}
