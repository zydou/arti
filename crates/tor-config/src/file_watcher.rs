//! Code to watch configuration files for any changes.
//!
// TODO: perhaps this shouldn't live in tor-config? But it doesn't seem substantial enough to have
// its own crate, and it can't live in e.g. tor-basic-utils, because it depends on tor-rtcompat.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tor_rtcompat::Runtime;

use amplify::Getters;
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
#[derive(Getters)]
pub struct FileWatcher {
    /// An underlying `notify` watcher that tells us about directory changes.
    // this field is kept only so the watcher is not dropped
    #[getter(skip)]
    _watcher: notify::RecommendedWatcher,
    /// The list of directories that we're currently watching.
    watching_dirs: HashSet<PathBuf>,
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
    ///
    /// Each directory has a set of filters that indicates whether a given notify::Event
    /// is relevant or not.
    watching_dirs: HashMap<PathBuf, HashSet<DirEventFilter>>,
}

/// A filter for deciding what to do with a notify::Event pertaining
/// to files that are relative to one of the directories we are watching.
///
// Private, as this is an implementation detail.
// If/when we decide to make this public, this might need revisiting.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum DirEventFilter {
    /// Notify the caller about the event, if the file has the specified extension.
    MatchesExtension(String),
    /// Notify the caller about the event, if the file has the specified path.
    MatchesPath(PathBuf),
}

impl DirEventFilter {
    /// Check whether this filter accepts `path`.
    fn accepts_path(&self, path: &Path) -> bool {
        match self {
            DirEventFilter::MatchesExtension(ext) => path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|e| e == ext.as_str())
                .unwrap_or_default(),
            DirEventFilter::MatchesPath(p) => p == path,
        }
    }
}

impl<R: Runtime> FileWatcherBuilder<R> {
    /// Create a `FileWatcherBuilder`
    pub fn new(runtime: R) -> Self {
        FileWatcherBuilder {
            runtime,
            watching_dirs: HashMap::new(),
        }
    }

    /// Add a single path to the list of things to watch.
    ///
    /// Idempotent: does nothing if we're already watching that path.
    pub fn watch_path<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.watch_just_parents(path.as_ref())?;
        Ok(())
    }

    /// Add a directory (but not any subdirs) to the list of things to watch.
    ///
    /// The event receiver will be notified whenever a file with the specified `extension`
    /// from this directory is changed.
    ///
    /// Idempotent.
    pub fn watch_dir<P: AsRef<Path>, S: AsRef<str>>(
        &mut self,
        path: P,
        extension: S,
    ) -> Result<()> {
        let path = self.watch_just_parents(path.as_ref())?;
        self.watch_just_abs_dir(
            &path,
            DirEventFilter::MatchesExtension(extension.as_ref().into()),
        );
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

        // Note this file as one that we're watching, so that we can see changes
        // to it later on.
        self.watch_just_abs_dir(watch_target, DirEventFilter::MatchesPath(path.clone()));

        Ok(path)
    }

    /// Add just this (absolute) directory to the list of things to watch.
    ///
    /// Does not watch any of the parents.
    ///
    /// Idempotent.
    fn watch_just_abs_dir(&mut self, watch_target: &Path, filter: DirEventFilter) {
        match self.watching_dirs.entry(watch_target.to_path_buf()) {
            Entry::Occupied(mut o) => {
                let _: bool = o.get_mut().insert(filter);
            }
            Entry::Vacant(v) => {
                let _ = v.insert(HashSet::from([filter]));
            }
        }
    }

    /// Build a `FileWatcher` and start sending events to `tx`.
    pub fn start_watching(self, tx: FileEventSender) -> Result<FileWatcher> {
        let runtime = self.runtime;
        let watching_dirs = self.watching_dirs.clone();
        let event_sender = move |event: notify::Result<notify::Event>| {
            let event = handle_event(event, &watching_dirs);
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

        let watching_dirs: HashSet<_> = self.watching_dirs.keys().cloned().collect();
        for dir in &watching_dirs {
            watcher
                .watch(dir, notify::RecursiveMode::NonRecursive)
                .map_err(Arc::new)?;
        }

        Ok(FileWatcher {
            _watcher: watcher,
            watching_dirs,
        })
    }
}

/// Map a `notify` event to the [`Event`] type returned by [`FileWatcher`].
fn handle_event(
    event: notify::Result<notify::Event>,
    watching_dirs: &HashMap<PathBuf, HashSet<DirEventFilter>>,
) -> Option<Event> {
    let watching = |f: &PathBuf| {
        // For paths with no parent (i.e. root), the watcher is added for the path itself,
        // so we do the same here.
        let parent = f.parent().unwrap_or_else(|| f.as_ref());

        // Find the filters that apply to this directory
        match watching_dirs
            .iter()
            .find_map(|(dir, filters)| (dir == parent).then_some(filters))
        {
            Some(filters) => {
                // This event is interesting, if any of the filters apply.
                filters.iter().any(|filter| filter.accepts_path(f.as_ref()))
            }
            None => false,
        }
    };

    // filter events we don't want and map to event code
    match event {
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use test_temp_dir::{test_temp_dir, TestTempDir};

    /// Write `data` to file `name` within `dir`.
    fn write_file(dir: &TestTempDir, name: &str, data: &[u8]) -> PathBuf {
        let path = dir.as_path_untracked().join(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    /// Return an event that has the Rescan flag set
    fn rescan_event() -> notify::Event {
        let event = notify::Event::new(notify::EventKind::Any);
        event.set_flag(notify::event::Flag::Rescan)
    }

    #[test]
    fn notify_event_handler() {
        // The EventKind doesn't matter, the handler doesn't use it.
        let mut event = notify::Event::new(notify::EventKind::Any);

        let mut watching_dirs = Default::default();
        assert_eq!(handle_event(Ok(event.clone()), &watching_dirs), None);
        assert_eq!(
            handle_event(Ok(rescan_event()), &watching_dirs),
            Some(Event::Rescan)
        );

        // Watch some directories
        watching_dirs.insert(
            "/foo/baz".into(),
            HashSet::from([DirEventFilter::MatchesExtension("auth".into())]),
        );
        assert_eq!(handle_event(Ok(event.clone()), &watching_dirs), None);
        assert_eq!(
            handle_event(Ok(rescan_event()), &watching_dirs),
            Some(Event::Rescan)
        );

        event = event.add_path("/foo/bar/alice.authh".into());
        assert_eq!(handle_event(Ok(event.clone()), &watching_dirs), None);

        event = event.add_path("/foo/bar/alice.auth".into());
        assert_eq!(handle_event(Ok(event.clone()), &watching_dirs), None);

        event = event.add_path("/foo/baz/bob.auth".into());
        assert_eq!(
            handle_event(Ok(event.clone()), &watching_dirs),
            Some(Event::FileChanged)
        );

        // Watch some files within /foo/bar
        watching_dirs.insert(
            "/foo/bar".into(),
            HashSet::from([DirEventFilter::MatchesPath("/foo/bar/abc".into())]),
        );

        assert_eq!(
            handle_event(Ok(event), &watching_dirs),
            Some(Event::FileChanged)
        );
        assert_eq!(
            handle_event(Ok(rescan_event()), &watching_dirs),
            Some(Event::Rescan)
        );

        // Watch some other files
        let event = notify::Event::new(notify::EventKind::Any).add_path("/a/b/c/d".into());
        let watching_dirs = [(
            "/a/b/c/".into(),
            HashSet::from([DirEventFilter::MatchesPath("/a/b/c/d".into())]),
        )]
        .into_iter()
        .collect();
        assert_eq!(
            handle_event(Ok(event), &watching_dirs),
            Some(Event::FileChanged)
        );
        assert_eq!(
            handle_event(Ok(rescan_event()), &watching_dirs),
            Some(Event::Rescan)
        );

        // Errors can also trigger an event
        let err = notify::Error::path_not_found();
        assert_eq!(handle_event(Err(err), &watching_dirs), None);
        let mut err = notify::Error::path_not_found();
        err = err.add_path("/a/b/c/d".into());
        assert_eq!(
            handle_event(Err(err), &watching_dirs),
            Some(Event::FileChanged)
        );
    }

    #[test]
    fn watch_dirs() {
        tor_rtcompat::test_with_one_runtime!(|rt| async move {
            let temp_dir = test_temp_dir!();
            let (tx, mut rx) = channel();
            // Watch for changes in .foo files from temp_dir
            let mut builder = FileWatcher::builder(rt.clone());
            builder
                .watch_dir(temp_dir.as_path_untracked(), "foo")
                .unwrap();
            let watcher = builder.start_watching(tx).unwrap();

            // On startup, the watcher sends a Event::Rescan event.
            // This is because the watcher is often set up after loading
            // the files or directories it is watching.
            assert_eq!(rx.try_recv(), Some(Event::Rescan));
            assert_eq!(rx.try_recv(), None);

            // Write a file with extension "foo".
            write_file(&temp_dir, "bar.foo", b"hello");

            assert_eq!(rx.next().await, Some(Event::FileChanged));

            drop(watcher);
            // The write might trigger more than one event
            while let Some(ev) = rx.next().await {
                assert_eq!(ev, Event::FileChanged);
            }
        });
    }
}
