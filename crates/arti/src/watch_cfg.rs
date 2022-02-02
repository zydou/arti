//! Code to watch configuration files for any changes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel as std_channel;
use std::time::Duration;

use arti_client::config::Reconfigure;
use arti_client::TorClient;
use arti_config::ArtiConfig;
use notify::Watcher;
use tor_rtcompat::Runtime;
use tracing::{debug, info, trace, warn};

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
    let mut watcher = FileWatcher::new(tx, POLL_INTERVAL)?;

    for file in sources.files() {
        watcher.watch_file(file)?;
    }

    std::thread::spawn(move || {
        debug!("Waiting for FS events");
        while let Ok(event) = rx.recv() {
            if !watcher.event_matched(&event) {
                trace!("Ignoring FS event {:?}: not a file we care about.", event);
                continue;
            }
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

/// A wrapper around `notify::RecommendedWatcher` to watch a set of parent
/// directories in order to learn about changes in some specific files that they
/// contain.
///
/// The `Watcher` implementation in `notify` has a weakness: it gives sensible
/// results when you're watching directories, but if you start watching
/// non-directory files, it won't notice when those files get replaced.  That's
/// a problem for users who want to change their configuration atomically by
/// making new files and then moving them into place over the old ones.
///
/// For more background on the issues with `notify`, see
/// https://github.com/notify-rs/notify/issues/165 and
/// https://github.com/notify-rs/notify/pull/166 .
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
    fn new(
        tx: std::sync::mpsc::Sender<notify::DebouncedEvent>,
        interval: Duration,
    ) -> anyhow::Result<Self> {
        let watcher = notify::watcher(tx, interval)?;
        Ok(Self {
            watcher,
            watching_dirs: HashSet::new(),
            watching_files: HashSet::new(),
        })
    }

    /// Watch a single file (not a directory).  Does nothing if we're already watching that file.
    fn watch_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        // Make the path absolute (without necessarily making it canonical).
        let cwd = std::env::current_dir()?;
        let path = cwd.join(path.as_ref());
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

        // Start watching this directory, if we're not already watching it.
        if !self.watching_dirs.contains(watch_target) {
            self.watcher
                .watch(watch_target, notify::RecursiveMode::NonRecursive)?;

            self.watching_dirs.insert(watch_target.into());
        }

        // Note this file as one that we're watching, so that we can see changes
        // to it later on.
        self.watching_files.insert(path);

        Ok(())
    }

    /// Return true if the provided event describes a change affecting one of
    /// the files that we care about.
    fn event_matched(&self, event: &notify::DebouncedEvent) -> bool {
        let watching = |f| self.watching_files.contains(f);

        match event {
            notify::DebouncedEvent::NoticeWrite(f) => watching(f),
            notify::DebouncedEvent::NoticeRemove(f) => watching(f),
            notify::DebouncedEvent::Create(f) => watching(f),
            notify::DebouncedEvent::Write(f) => watching(f),
            notify::DebouncedEvent::Chmod(f) => watching(f),
            notify::DebouncedEvent::Remove(f) => watching(f),
            notify::DebouncedEvent::Rename(f1, f2) => watching(f1) || watching(f2),
            notify::DebouncedEvent::Rescan => {
                // Not clear to me whether we need to do anything here.
                false
            }
            notify::DebouncedEvent::Error(_, Some(f)) => watching(f),
            notify::DebouncedEvent::Error(_, _) => false,
        }
    }
}
