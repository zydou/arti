//! Code to watch configuration files for any changes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel as std_channel, Sender};
use std::time::Duration;

use arti_client::config::Reconfigure;
use arti_client::TorClient;
use notify::Watcher;
use tor_config::{sources::FoundConfigFiles, ConfigurationSource, ConfigurationSources};
use tor_rtcompat::Runtime;
use tracing::{debug, error, info, warn};

use futures::task::SpawnExt;

use crate::process::sighup_stream;
use crate::{ArtiCombinedConfig, ArtiConfig};

/// How long to wait after a file is created, before we try to read it.
const DEBOUNCE_INTERVAL: Duration = Duration::from_secs(1);

/// Unwrap first expression or break with the provided error message
macro_rules! ok_or_break {
    ($e:expr, $msg:expr $(,)?) => {
        match ($e) {
            Ok(y) => y,
            Err(e) => {
                error!($msg, e);
                break;
            }
        }
    };
}

/// Generate a rescan FS event
// TODO this function should be removed during a future refactoring; see #562
#[allow(clippy::unnecessary_wraps)]
fn rescan_event() -> notify::Result<notify::Event> {
    use notify::event::{EventAttributes, EventKind, Flag};

    let mut attrs = EventAttributes::default();
    attrs.set_flag(Flag::Rescan);
    Ok(notify::Event {
        kind: EventKind::Other,
        paths: Vec::new(),
        attrs,
    })
}

/// Launch a thread to reload our configuration files.
///
/// If current configuration requires it, watch for changes in `sources`
/// and try to reload our configuration. On unix platforms, also watch
/// for SIGHUP and reload configuration then.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn watch_for_config_changes<R: Runtime>(
    sources: ConfigurationSources,
    original: ArtiConfig,
    client: TorClient<R>,
) -> anyhow::Result<()> {
    let watch_file = original.application().watch_configuration;

    let (tx, rx) = std_channel();
    let mut watcher = if watch_file {
        // If watching, we must reload the config once right away, because
        // we have set up the watcher *after* loading the config.
        // ignore send error, rx can't be disconnected if we are here
        let _ = tx.send(rescan_event());
        let (watcher, _) = FileWatcher::new_prepared(tx.clone(), DEBOUNCE_INTERVAL, &sources)?;
        Some(watcher)
    } else {
        None
    };

    #[cfg(target_family = "unix")]
    {
        use futures::StreamExt;

        let mut sighup_stream = sighup_stream()?;
        let tx = tx.clone();
        client.runtime().spawn(async move {
            while let Some(()) = sighup_stream.next().await {
                info!("Received SIGHUP");
                if tx.send(rescan_event()).is_err() {
                    warn!("Failed to reload configuration");
                    break;
                }
            }
        })?;
    }

    std::thread::spawn(move || {
        // TODO: If someday we make this facility available outside of the
        // `arti` application, we probably don't want to have this thread own
        // the FileWatcher.
        debug!("Entering FS event loop");
        while let Ok(event) = rx.recv() {
            if !watcher.as_ref().map_or(true, |w| w.event_matched(&event)) {
                // NOTE: Sadly, it's not safe to log in this case.  If the user
                // has put a configuration file and a logfile in the same
                // directory, logging about discarded events will make us log
                // every time we log, and fill up the filesystem.
                continue;
            }
            while let Ok(_ignore) = rx.try_recv() {
                // Discard other events, so that we only reload once.
                //
                // We can afford to treat both error cases from try_recv [Empty
                // and Disconnected] as meaning that we've discarded other
                // events: if we're disconnected, we'll notice it when we next
                // call recv() in the outer loop.
            }
            debug!("FS event {:?}: reloading configuration.", event);

            let found_files = if watcher.is_some() {
                let (new_watcher, found_files) = ok_or_break!(
                    FileWatcher::new_prepared(tx.clone(), DEBOUNCE_INTERVAL, &sources),
                    "FS watch: failed to rescan config and re-establish watch: {}",
                );
                watcher = Some(new_watcher);
                found_files
            } else {
                ok_or_break!(sources.scan(), "FS watch: failed to rescan config: {}",)
            };

            match reconfigure(found_files, &original, &client) {
                Ok(watch) => {
                    info!("Successfully reloaded configuration.");
                    if watch && watcher.is_none() {
                        info!("Starting watching over configuration.");
                        // If watching, we must reload the config once right away, because
                        // we have set up the watcher *after* loading the config.
                        // ignore send error, rx can't be disconnected if we are here
                        let _ = tx.send(rescan_event());
                        let (new_watcher, _) = ok_or_break!(
                            FileWatcher::new_prepared(tx.clone(), DEBOUNCE_INTERVAL, &sources),
                            "FS watch: failed to rescan config and re-establish watch: {}",
                        );
                        watcher = Some(new_watcher);
                    } else if !watch && watcher.is_some() {
                        info!("Stopped watching over configuration.");
                        watcher = None;
                    }
                }
                Err(e) => warn!("Couldn't reload configuration: {}", e),
            }
        }
        debug!("Thread exiting");
    });

    // Dropping the thread handle here means that we don't get any special
    // notification about a panic.  TODO: We should change that at some point in
    // the future.

    Ok(())
}

/// Reload the configuration files, apply the runtime configuration, and
/// reconfigure the client as much as we can.
///
/// Return true if we should be watching for configuration changes.
fn reconfigure<R: Runtime>(
    found_files: FoundConfigFiles<'_>,
    original: &ArtiConfig,
    client: &TorClient<R>,
) -> anyhow::Result<bool> {
    let config = found_files.load()?;
    let (config, client_config) = tor_config::resolve::<ArtiCombinedConfig>(config)?;
    if config.proxy() != original.proxy() {
        warn!("Can't (yet) reconfigure proxy settings while arti is running.");
    }
    if config.logging() != original.logging() {
        warn!("Can't (yet) reconfigure logging settings while arti is running.");
    }
    if config.application().permit_debugging && !original.application().permit_debugging {
        warn!("Cannot disable application hardening when it has already been enabled.");
    }
    client.reconfigure(&client_config, Reconfigure::WarnOnFailures)?;

    if !config.application().permit_debugging {
        #[cfg(feature = "harden")]
        crate::process::enable_process_hardening()?;
    }

    Ok(config.application().watch_configuration)
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
    watcher: notify::RecommendedWatcher,
    /// The list of directories that we're currently watching.
    watching_dirs: HashSet<PathBuf>,
    /// The list of files we actually care about.
    watching_files: HashSet<PathBuf>,
}

impl FileWatcher {
    /// Like `notify::watcher`, but create a FileWatcher instead.
    fn new(tx: Sender<notify::Result<notify::Event>>, interval: Duration) -> anyhow::Result<Self> {
        let watcher = notify::RecommendedWatcher::new(
            tx,
            notify::Config::default().with_poll_interval(interval),
        )?;
        Ok(Self {
            watcher,
            watching_dirs: HashSet::new(),
            watching_files: HashSet::new(),
        })
    }

    /// Create a FileWatcher already watching files in `sources`
    fn new_prepared(
        tx: Sender<notify::Result<notify::Event>>,
        interval: Duration,
        sources: &ConfigurationSources,
    ) -> anyhow::Result<(Self, FoundConfigFiles)> {
        Self::new(tx, interval).and_then(|mut this| this.prepare(sources).map(|cfg| (this, cfg)))
    }

    /// Find the configuration files and prepare the watcher
    ///
    /// For the watching to be reliably effective (race-free), the config must be read
    /// *after* this point, using the returned `FoundConfigFiles`.
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

    /// Watch a single file (not a directory).
    ///
    /// Idempotent: does nothing if we're already watching that file.
    fn watch_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        self.watch_just_parents(path.as_ref())?;
        Ok(())
    }

    /// Watch a directory (but not any subdirs).
    ///
    /// Idempotent.
    fn watch_dir<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.watch_just_parents(path.as_ref())?;
        self.watch_just_abs_dir(&path)
    }

    /// Watch the parents of `path`.
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

        self.watch_just_abs_dir(watch_target)?;

        // Note this file as one that we're watching, so that we can see changes
        // to it later on.
        self.watching_files.insert(path.clone());

        Ok(path)
    }

    /// Watch just this (absolute) directory.
    ///
    /// Does not watch any of the parents.
    ///
    /// Idempotent.
    fn watch_just_abs_dir(&mut self, watch_target: &Path) -> anyhow::Result<()> {
        if !self.watching_dirs.contains(watch_target) {
            self.watcher
                .watch(watch_target, notify::RecursiveMode::NonRecursive)?;

            self.watching_dirs.insert(watch_target.into());
        }
        Ok(())
    }

    /// Return true if the provided event describes a change affecting one of
    /// the files that we care about.
    fn event_matched(&self, event: &notify::Result<notify::Event>) -> bool {
        let watching = |f| self.watching_files.contains(f);

        match event {
            Ok(event) => event.need_rescan() || event.paths.iter().any(watching),
            Err(error) => error.paths.iter().any(watching),
        }
    }
}
