//! Code to watch configuration files for any changes.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tor_rtcompat::Runtime;

use futures::lock::Mutex;
use notify::Watcher;
use postage::watch;

use futures::{SinkExt as _, Stream, StreamExt as _};

/// `Result` whose `Err` is [`FileWatcherBuildError`].
pub type Result<T> = std::result::Result<T, FileWatcherBuildError>;

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
/// <https://github.com/notify-rs/notify/issues/165> and
/// <https://github.com/notify-rs/notify/pull/166>.
///
/// TODO: Someday we might want to make this code exported someplace.  If we do,
/// we should test it, and improve its API a lot.
pub struct FileWatcher {
    /// An underlying `notify` watcher that tells us about directory changes.
    // this field is kept only so the watcher is not dropped
    _watcher: notify::RecommendedWatcher,
}

impl FileWatcher {
    /// Create a `FileWatcherBuilder`
    pub fn builder<R: Runtime>(runtime: R) -> FileWatcherBuilder<R> {
        FileWatcherBuilder::new(runtime)
    }
}

/// Event possibly triggering a configuration reload
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// SIGHUP has been received.
    #[cfg(target_family = "unix")]
    SigHup,
    /// Some files may have been modified.
    FileChanged,
    /// Some filesystem events may have been missed.
    Rescan,
}

/// Builder used to configure a [`FileWatcher`] before it starts watching for changes.
pub struct FileWatcherBuilder<R: Runtime> {
    /// The runtime.
    runtime: R,
    /// The list of directories that we're currently watching.
    watching_dirs: HashSet<PathBuf>,
    /// The list of files we actually care about.
    watching_files: HashSet<PathBuf>,
}

impl<R: Runtime> FileWatcherBuilder<R> {
    /// Create a `FileWatcherBuilder`
    pub fn new(runtime: R) -> Self {
        FileWatcherBuilder {
            runtime,
            watching_dirs: HashSet::new(),
            watching_files: HashSet::new(),
        }
    }

    /// Add a single file (not a directory) to the list of things to watch.
    ///
    /// Idempotent: does nothing if we're already watching that file.
    pub fn watch_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.watch_just_parents(path.as_ref())?;
        Ok(())
    }

    /// Add a directory (but not any subdirs) to the list of things to watch.
    ///
    /// Idempotent.
    pub fn watch_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = self.watch_just_parents(path.as_ref())?;
        self.watch_just_abs_dir(&path);
        Ok(())
    }

    /// Add the parents of `path` to the list of things to watch.
    ///
    /// Returns the absolute path of `path`.
    ///
    /// Idempotent.
    fn watch_just_parents(&mut self, path: &Path) -> Result<PathBuf> {
        // Make the path absolute (without necessarily making it canonical).
        //
        // We do this because `notify` reports all of its events in terms of
        // absolute paths, so if we were to tell it to watch a directory by its
        // relative path, we'd get reports about the absolute paths of the files
        // in that directory.
        let cwd = std::env::current_dir()
            .map_err(|e| FileWatcherBuildError::CurrentDirectory(Arc::new(e)))?;
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
    pub fn start_watching(self, tx: FileEventSender) -> Result<FileWatcher> {
        let runtime = self.runtime;
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
                // It *should* be alright to block_on():
                //   * on all platforms, the `RecommendedWatcher`'s event_handler is called from a
                //     separate thread
                //   * notify's own async_monitor example uses block_on() to run async code in the
                //     event handler
                runtime.block_on(async {
                    let _ = tx.0.lock().await.send(event).await;
                });
            }
        };

        let mut watcher = notify::RecommendedWatcher::new(event_sender, notify::Config::default())
            .map_err(Arc::new)?;

        for dir in self.watching_dirs {
            watcher
                .watch(&dir, notify::RecursiveMode::NonRecursive)
                .map_err(Arc::new)?;
        }

        Ok(FileWatcher { _watcher: watcher })
    }
}

/// The sender half of a watch channel used by a [`FileWatcher`] for sending [`Event`]s.
///
/// For use with [`FileWatcherBuilder::start_watching`].
///
/// **Important**: to avoid contention, avoid sharing clones of the same `FileEventSender`
/// with multiple [`FileWatcherBuilder`]s. This type is [`Clone`] to support creating new
/// [`FileWatcher`]s from an existing [`channel`], which enables existing receivers to receive
/// events from new `FileWatcher`s (any old `FileWatcher`s are supposed to be discarded).
#[derive(Clone)]
pub struct FileEventSender(Arc<Mutex<watch::Sender<Event>>>);

/// The receiver half of a watch channel used for receiving [`Event`]s sent by a [`FileWatcher`].
#[derive(Clone)]
pub struct FileEventReceiver(watch::Receiver<Event>);

impl Stream for FileEventReceiver {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_next_unpin(cx)
    }
}

impl FileEventReceiver {
    /// Try to read a message from the stream, without blocking.
    ///
    /// Returns `Some` if a message is ready.
    /// Returns `None` if the stream is open, but no messages are available,
    /// or if the stream is closed.
    pub fn try_recv(&mut self) -> Option<Event> {
        use postage::prelude::Stream;

        self.0.try_recv().ok()
    }
}

/// Create a new channel for use with a [`FileWatcher`].
//
// Note: the [`FileEventSender`] and [`FileEventReceiver`]  wrappers exist
// so we don't expose the channel's underlying type
// in our public API.
pub fn channel() -> (FileEventSender, FileEventReceiver) {
    let (tx, rx) = watch::channel_with(Event::Rescan);
    (
        FileEventSender(Arc::new(Mutex::new(tx))),
        FileEventReceiver(rx),
    )
}

/// An error coming from a [`FileWatcherBuilder`].
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum FileWatcherBuildError {
    /// Invalid current working directory.
    ///
    /// This error can happen if the current directory does not exist,
    /// or if we don't have the necessary permissions to access it.
    #[error("Invalid current working directory")]
    CurrentDirectory(#[source] Arc<io::Error>),

    /// Encountered a problem while creating a `Watcher`.
    #[error("Problem creating Watcher")]
    Notify(#[from] Arc<notify::Error>),
}
