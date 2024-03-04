//! Code to watch configuration files for any changes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel as std_channel, Sender};
use std::sync::Weak;
use std::time::Duration;

use anyhow::Context;
use arti_client::config::Reconfigure;
use arti_client::TorClient;
use notify::Watcher;
use tor_config::{sources::FoundConfigFiles, ConfigurationSource, ConfigurationSources};
use tor_rtcompat::Runtime;
use tracing::{debug, error, info, warn};

use crate::{ArtiCombinedConfig, ArtiConfig};

/// How long to wait after an event got received, before we try to process it.
const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// Event possibly triggering a configuration reload
#[derive(Debug)]
enum Event {
    /// SIGHUP has been received.
    #[cfg(target_family = "unix")]
    SigHup,
    /// Some files may have been modified.
    FileChanged,
    /// Some filesystem events may have been missed.
    Rescan,
}

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
    sources: ConfigurationSources,
    config: &ArtiConfig,
    #[cfg_attr(not(target_family = "unix"), allow(unused_variables))]
    runtime: &R,
    modules: Vec<Weak<dyn ReconfigurableModule>>,
) -> anyhow::Result<()> {
    let watch_file = config.application().watch_configuration;

    let (tx, rx) = std_channel();
    let mut watcher = if watch_file {
        // If watching, we must reload the config once right away, because
        // we have set up the watcher *after* loading the config.
        // ignore send error, rx can't be disconnected if we are here
        let _ = tx.send(Event::Rescan);
        let mut watcher = FileWatcher::builder();
        watcher.prepare(&sources)?;
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
                    let mut new_watcher = FileWatcher::builder();
                    let found_files = new_watcher
                        .prepare(&sources)
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
                            let mut new_watcher = FileWatcher::builder();
                            let _found_files = new_watcher.prepare(&sources).context(
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

/// A wrapper around `notify::RecommendedWatcher` to watch a set of parent
/// directories in order to learn about changes in some specific files that they
/// contain.
///
/// The wrapper contains the `Watcher` and also the channel for receiving events.
///
/// The `Watcher` implementation in `notify` has a weakness: it gives sensible
/// results when you're watching directories, but if you start watching
/// non-directory files, it won't notice when those files get replaced.  That's
/// a problem for users who want to change their configuration atomically by
/// making new files and then moving them into place over the old ones.
///
/// For more background on the issues with `notify`, see
/// <https://github.com/notify-rs/notify/issues/165> and
/// <https://github.com/notify-rs/notify/pull/166>.
///
/// TODO: Someday we might want to make this code exported someplace.  If we do,
/// we should test it, and improve its API a lot.  Right now, the caller needs
/// to mess around with `std::sync::mpsc` and filter out the events they want
/// using `FileWatcher::event_matched`.
struct FileWatcher {
    /// An underlying `notify` watcher that tells us about directory changes.
    // this field is kept only so the watcher is not dropped
    _watcher: notify::RecommendedWatcher,
}

impl FileWatcher {
    /// Create a `FileWatcherBuilder`
    fn builder() -> FileWatcherBuilder {
        FileWatcherBuilder::new()
    }
}

/// Builder used to configure a [`FileWatcher`] before it starts watching for changes.
struct FileWatcherBuilder {
    /// The list of directories that we're currently watching.
    watching_dirs: HashSet<PathBuf>,
    /// The list of files we actually care about.
    watching_files: HashSet<PathBuf>,
}

impl FileWatcherBuilder {
    /// Create a `FileWatcherBuilder`
    fn new() -> Self {
        FileWatcherBuilder {
            watching_dirs: HashSet::new(),
            watching_files: HashSet::new(),
        }
    }

    /// Find the configuration files and prepare the watcher
    fn prepare<'a>(
        &mut self,
        sources: &'a ConfigurationSources,
    ) -> anyhow::Result<FoundConfigFiles<'a>> {
        let sources = sources.scan()?;
        for source in sources.iter() {
            match source {
                ConfigurationSource::Dir(dir) => self.watch_dir(dir)?,
                ConfigurationSource::File(file) => self.watch_file(file)?,
            }
        }
        Ok(sources)
    }

    /// Add a single file (not a directory) to the list of things to watch.
    ///
    /// Idempotent: does nothing if we're already watching that file.
    fn watch_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        self.watch_just_parents(path.as_ref())?;
        Ok(())
    }

    /// Add a directory (but not any subdirs) to the list of things to watch.
    ///
    /// Idempotent.
    fn watch_dir<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.watch_just_parents(path.as_ref())?;
        self.watch_just_abs_dir(&path);
        Ok(())
    }

    /// Add the parents of `path` to the list of things to watch.
    ///
    /// Returns the absolute path of `path`.
    ///
    /// Idempotent.
    fn watch_just_parents(&mut self, path: &Path) -> anyhow::Result<PathBuf> {
        // Make the path absolute (without necessarily making it canonical).
        //
        // We do this because `notify` reports all of its events in terms of
        // absolute paths, so if we were to tell it to watch a directory by its
        // relative path, we'd get reports about the absolute paths of the files
        // in that directory.
        let cwd = std::env::current_dir()?;
        let path = cwd.join(path);
        debug_assert!(path.is_absolute());

        // See what directory we should watch in order to watch this file.
        let watch_target = match path.parent() {
            // The file has a parent, so watch that.
            Some(parent) => parent,
            // The file has no parent.  Given that it's absolute, that means
            // that we're looking at the root directory.  There's nowhere to go
            // "up" from there.
            None => path.as_ref(),
        };

        self.watch_just_abs_dir(watch_target);

        // Note this file as one that we're watching, so that we can see changes
        // to it later on.
        self.watching_files.insert(path.clone());

        Ok(path)
    }

    /// Add just this (absolute) directory to the list of things to watch.
    ///
    /// Does not watch any of the parents.
    ///
    /// Idempotent.
    fn watch_just_abs_dir(&mut self, watch_target: &Path) {
        self.watching_dirs.insert(watch_target.into());
    }

    /// Build a `FileWatcher` and start sending events to `tx`.
    ///
    /// For the watching to be reliably effective (race-free), the config must be read
    /// *after* this point, using the `FoundConfigFiles` returned by `prepare`.
    fn start_watching(self, tx: Sender<Event>) -> anyhow::Result<FileWatcher> {
        let event_sender = move |event: notify::Result<notify::Event>| {
            let watching = |f| self.watching_files.contains(f);
            // filter events we don't want and map to event code
            let event = match event {
                Ok(event) => {
                    if event.need_rescan() {
                        Some(Event::Rescan)
                    } else if event.paths.iter().any(watching) {
                        Some(Event::FileChanged)
                    } else {
                        None
                    }
                }
                Err(error) => {
                    if error.paths.iter().any(watching) {
                        Some(Event::FileChanged)
                    } else {
                        None
                    }
                }
            };
            if let Some(event) = event {
                let _ = tx.send(event);
            };
        };

        let mut watcher = notify::RecommendedWatcher::new(event_sender, notify::Config::default())?;

        for dir in self.watching_dirs {
            watcher.watch(&dir, notify::RecursiveMode::NonRecursive)?;
        }

        Ok(FileWatcher { _watcher: watcher })
    }
}
