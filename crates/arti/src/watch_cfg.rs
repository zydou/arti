//! Code to watch configuration files for any changes.

use std::sync::mpsc::channel as std_channel;
use std::time::Duration;

use arti_client::config::Reconfigure;
use arti_client::TorClient;
use arti_config::ArtiConfig;
use notify::Watcher;
use tor_rtcompat::Runtime;
use tracing::{debug, info, warn};

/// How long (worst case) should we take to learn about configuration changes?
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Launch a thread to watch our configuration files.
///
/// Whenever one or more files in `files` changes, try to reload our
/// configuration from them and tell TorClient about it.
pub(crate) fn watch_for_config_changes<R: Runtime>(
    sources: arti_config::ConfigurationSources,
    original: ArtiConfig,
    client: TorClient<R>,
) -> anyhow::Result<()> {
    let (tx, rx) = std_channel();
    let mut watcher = notify::watcher(tx, POLL_INTERVAL)?;

    for file in sources.files() {
        // NOTE: The `notify` documentation says that we might want to be
        // watching the parent directories instead.  We should see if their
        // reasoning applies to us, and if so  we should do that instead.
        watcher.watch(file, notify::RecursiveMode::NonRecursive)?;
    }

    std::thread::spawn(move || {
        // Keep this around here so that we don't drop it and make it go away.
        let _w = watcher;
        debug!("Waiting for FS events");
        while let Ok(event) = rx.recv() {
            debug!("FS event {:?}: reloading configuration.", event);
            match reconfigure(&sources, &original, &client) {
                Ok(exit) => {
                    info!("Successfully reloaded configuration.");
                    if exit {
                        break;
                    }
                }
                Err(e) => warn!("Couldn't reload configuration: {}", e),
            }
        }
        debug!("Thread exiting");
    });

    Ok(())
}

/// Reload the configuration files, apply the runtime configuration, and
/// reconfigure the client as much as we can.
///
/// Return true if we should stop watching for configuration changes.
fn reconfigure<R: Runtime>(
    sources: &arti_config::ConfigurationSources,
    original: &ArtiConfig,
    client: &TorClient<R>,
) -> anyhow::Result<bool> {
    let config = sources.load()?;
    let config: ArtiConfig = config.try_into()?;
    if config.proxy() != original.proxy() {
        warn!("Can't (yet) reconfigure proxy settings while arti is running.");
    }
    if config.logging() != original.logging() {
        warn!("Can't (yet) reconfigure logging settings while arti is running.");
    }
    let client_config = config.tor_client_config()?;
    client.reconfigure(&client_config, Reconfigure::WarnOnFailures)?;

    if !config.application().watch_configuration() {
        // Stop watching for configuration changes.
        return Ok(true);
    }

    Ok(false)
}
