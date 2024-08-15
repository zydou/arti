//! Code to watch configuration files for any changes.

use std::sync::mpsc::{channel as std_channel};
use std::sync::Weak;
use std::time::Duration;

use anyhow::Context;
use arti_client::config::Reconfigure;
use arti_client::TorClient;
use tor_config::file_watcher::FileWatcherBuilder;
use tor_config::{sources::FoundConfigFiles, ConfigurationSource, ConfigurationSources, file_watcher::{Event, FileWatcher}};
use tor_rtcompat::Runtime;
use tracing::{debug, error, info, warn};

use crate::{ArtiCombinedConfig, ArtiConfig};

/// How long to wait after an event got received, before we try to process it.
const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// An object that can be reconfigured when our configuration changes.
///
/// We use this trait so that we can represent abstract modules in our
/// application, and pass the configuration to each of them.
//
// TODO: It is very likely we will want to refactor this even further once we
// have a notion of what our modules truly are.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) trait ReconfigurableModule: Send + Sync {
    /// Try to reconfigure this module according to a newly loaded configuration.
    ///
    /// By convention, this should only return fatal errors; any such error
    /// should cause the program to exit.  For other cases, we should just warn.
    //
    // TODO: This should probably take "how: Reconfigure" as an argument, and
    // pass it down as appropriate. See issue #1156.
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()>;
}

/// Launch a thread to reload our configuration files.
///
/// If current configuration requires it, watch for changes in `sources`
/// and try to reload our configuration. On unix platforms, also watch
/// for SIGHUP and reload configuration then.
///
/// The modules are `Weak` references to prevent this background task
/// from keeping them alive.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn watch_for_config_changes<R: Runtime>(
    #[cfg_attr(not(target_family = "unix"), allow(unused_variables))]
    runtime: &R,
    sources: ConfigurationSources,
    config: &ArtiConfig,
    modules: Vec<Weak<dyn ReconfigurableModule>>,
) -> anyhow::Result<()> {
    let watch_file = config.application().watch_configuration;

    let (tx, rx) = std_channel();
    let mut watcher = if watch_file {
        // If watching, we must reload the config once right away, because
        // we have set up the watcher *after* loading the config.
        // ignore send error, rx can't be disconnected if we are here
        let _ = tx.send(Event::Rescan);
        let mut watcher = FileWatcher::builder(runtime.clone());
        prepare(&mut watcher, &sources)?;
        Some(watcher.start_watching(tx.clone())?)
    } else {
        None
    };

    #[cfg(target_family = "unix")]
    {
        use futures::task::SpawnExt;
        use futures::StreamExt;

        use crate::process::sighup_stream;

        let mut sighup_stream = sighup_stream()?;
        let tx = tx.clone();
        runtime.spawn(async move {
            while let Some(()) = sighup_stream.next().await {
                info!("Received SIGHUP");
                if tx.send(Event::SigHup).is_err() {
                    warn!("Failed to reload configuration");
                    break;
                }
            }
        })?;
    }

    let runtime = runtime.clone();
    #[allow(clippy::cognitive_complexity)]
    std::thread::spawn(move || {
        // TODO: If someday we make this facility available outside of the
        // `arti` application, we probably don't want to have this thread own
        // the FileWatcher.
        debug!("Entering FS event loop");
        let mut iife = || -> Result<(), anyhow::Error> {
            while let Ok(event) = rx.recv() {
                // we are in a dedicated thread, it's safe to thread::sleep.
                std::thread::sleep(DEBOUNCE_INTERVAL);

                while let Ok(_ignore) = rx.try_recv() {
                    // Discard other events, so that we only reload once.
                    //
                    // We can afford to treat both error cases from try_recv [Empty
                    // and Disconnected] as meaning that we've discarded other
                    // events: if we're disconnected, we'll notice it when we next
                    // call recv() in the outer loop.
                }
                debug!("Config reload event {:?}: reloading configuration.", event);

                let found_files = if watcher.is_some() {
                    let mut new_watcher = FileWatcher::builder(runtime.clone());
                    let found_files = prepare(&mut new_watcher, &sources)
                        .context("FS watch: failed to rescan config and re-establish watch")?;
                    let new_watcher = new_watcher
                        .start_watching(tx.clone())
                        .context("FS watch: failed to rescan config and re-establish watch")?;
                    watcher = Some(new_watcher);
                    found_files
                } else {
                    sources
                        .scan()
                        .context("FS watch: failed to rescan config")?
                };

                match reconfigure(found_files, &modules) {
                    Ok(watch) => {
                        info!("Successfully reloaded configuration.");
                        if watch && watcher.is_none() {
                            info!("Starting watching over configuration.");
                            // If watching, we must reload the config once right away, because
                            // we have set up the watcher *after* loading the config.
                            // ignore send error, rx can't be disconnected if we are here
                            let _ = tx.send(Event::Rescan);
                            let mut new_watcher = FileWatcher::builder(runtime.clone());
                            let _found_files = prepare(&mut new_watcher, &sources).context(
                                "FS watch: failed to rescan config and re-establish watch: {}",
                            )?;
                            let new_watcher = new_watcher.start_watching(tx.clone()).context(
                                "FS watch: failed to rescan config and re-establish watch: {}",
                            )?;
                            watcher = Some(new_watcher);
                        } else if !watch && watcher.is_some() {
                            info!("Stopped watching over configuration.");
                            watcher = None;
                        }
                    }
                    // TODO: warn_report does not work on anyhow::Error.
                    Err(e) => warn!("Couldn't reload configuration: {}", tor_error::Report(e)),
                }
            }
            Ok(())
        };
        match iife() {
            Ok(()) => debug!("Thread exiting"),
            // TODO: warn_report does not work on anyhow::Error.
            Err(e) => error!("Config reload thread exiting: {}", tor_error::Report(e)),
        }
    });

    // Dropping the thread handle here means that we don't get any special
    // notification about a panic.  TODO: We should change that at some point in
    // the future.

    Ok(())
}

impl<R: Runtime> ReconfigurableModule for TorClient<R> {
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()> {
        TorClient::reconfigure(self, &new.1, Reconfigure::WarnOnFailures)?;
        Ok(())
    }
}

/// Internal type to represent the Arti application as a `ReconfigurableModule`.
pub(crate) struct Application {
    /// The configuration that Arti had at startup.
    ///
    /// We use this to check whether the user is asking for any impermissible
    /// transitions.
    original_config: ArtiConfig,
}

impl Application {
    /// Construct a new `Application` to receive configuration changes for the
    /// arti application.
    pub(crate) fn new(cfg: ArtiConfig) -> Self {
        Self {
            original_config: cfg,
        }
    }
}

impl ReconfigurableModule for Application {
    // TODO: This should probably take "how: Reconfigure" as an argument, and
    // pass it down as appropriate. See issue #1156.
    #[allow(clippy::cognitive_complexity)]
    fn reconfigure(&self, new: &ArtiCombinedConfig) -> anyhow::Result<()> {
        let original = &self.original_config;
        let config = &new.0;

        if config.proxy() != original.proxy() {
            warn!("Can't (yet) reconfigure proxy settings while arti is running.");
        }
        if config.logging() != original.logging() {
            warn!("Can't (yet) reconfigure logging settings while arti is running.");
        }
        if config.application().permit_debugging && !original.application().permit_debugging {
            warn!("Cannot disable application hardening when it has already been enabled.");
        }

        // Note that this is the only config transition we actually perform so far.
        if !config.application().permit_debugging {
            #[cfg(feature = "harden")]
            crate::process::enable_process_hardening()?;
        }

        Ok(())
    }
}

/// Find the configuration files and prepare the watcher
fn prepare<'a, R: Runtime>(
    watcher: &mut FileWatcherBuilder<R>,
    sources: &'a ConfigurationSources,
) -> anyhow::Result<FoundConfigFiles<'a>> {
    let sources = sources.scan()?;
    for source in sources.iter() {
        match source {
            ConfigurationSource::Dir(dir) => watcher.watch_dir(dir)?,
            ConfigurationSource::File(file) => watcher.watch_file(file)?,
            ConfigurationSource::Verbatim(_) => {}
        }
    }
    Ok(sources)
}

/// Reload the configuration files, apply the runtime configuration, and
/// reconfigure the client as much as we can.
///
/// Return true if we should be watching for configuration changes.
//
// TODO: This should probably take "how: Reconfigure" as an argument, and
// pass it down as appropriate. See issue #1156.
fn reconfigure(
    found_files: FoundConfigFiles<'_>,
    reconfigurable: &[Weak<dyn ReconfigurableModule>],
) -> anyhow::Result<bool> {
    let _ = reconfigurable;
    let config = found_files.load()?;
    let config = tor_config::resolve::<ArtiCombinedConfig>(config)?;

    // Filter out the modules that have been dropped
    let reconfigurable = reconfigurable.iter().flat_map(Weak::upgrade);
    // If there are no more modules, we should exit.
    let mut has_modules = false;

    for module in reconfigurable {
        has_modules = true;
        module.reconfigure(&config)?;
    }

    Ok(has_modules && config.0.application().watch_configuration)
}
