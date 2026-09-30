#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![allow(clippy::cognitive_complexity)] // See arti#2556
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
#![allow(clippy::collapsible_if)] // See arti#2342
#![deny(clippy::unused_async)]
#![deny(clippy::string_slice)] // See arti#2571
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use async_trait::async_trait;
use futures::{
    StreamExt as _,
    task::{Spawn, SpawnError},
};
use postage::watch;
use std::{collections::HashSet, fmt::Debug, hash::Hash, sync::Arc, sync::Mutex, time::Duration};
use tor_rtcompat::SpawnExt as _;

mod err;
mod reactor;

pub mod http;

pub use err::{Rejection, UploadError};

/// An object that can upload documents of a given type to targets of a given type.
///
/// See type and method documentation for details on how to implement this type correctly.
#[async_trait]
pub trait Uploader: Send + Sync + 'static {
    /// The type of document we are uploading.
    ///
    /// Typically, this will be `str` or `[u8]`,
    /// but other types are possible.
    ///
    /// We pass this around in an [`Arc`],
    /// so it is allowed to be quite large.
    type Doc: ?Sized;

    /// A single target to which we're uploading a document.
    ///
    /// For a simple HTTP(S) upload this could be a `Vec` of addresses.
    ///
    /// In a Tor context, it could be a ChanTarget or a CircTarget.
    ///
    /// We pass this around in an [`Arc`],
    /// so the size doesn't much matter.
    ///
    /// We require that this type implements Eq and Hash,
    /// so that we can tell when a target has changed.
    type Target: ?Sized;

    /// Try to upload `document` to `target`.
    ///
    /// Return Ok(()) on success; return an error on failure.
    ///
    /// If it is possible for the target to reject a document,
    /// this method must return [`UploadError::Rejected`]
    /// in that case.
    ///
    /// If it is possible for the target to say
    /// "I am overloaded, come back later",
    /// the implementor must return [`UploadError::Deferred`]
    /// in that case.
    ///
    /// It is the implementor's responsibility to provide:
    /// - Timeout behavior, if desired.
    /// - [Happy-eyeballs] address selection, if desired.
    ///
    /// [Happy-eyeballs]: https://en.wikipedia.org/wiki/Happy_Eyeballs
    async fn upload(
        &self,
        target: Arc<Self::Target>,
        document: Arc<Self::Doc>,
    ) -> Result<(), UploadError>;
}

/// A handle to a publisher object that manages uploading a document to a set of targets.
///
/// See the [crate documentation](crate) for more information on this type and how to use it.
pub struct Publisher<D, T>
where
    T: Hash + Eq + Send + Sync + Debug + 'static + ?Sized,
    D: Send + Sync + 'static + ?Sized,
{
    /// A sender that we use to tell the reactor what actions to take.
    directive: Mutex<watch::Sender<PublishDirective<D, T>>>,

    /// A receiver to tell us about publication progress.
    status: watch::Receiver<PublishStatus>,
}

impl<D, T> Publisher<D, T>
where
    T: Hash + Eq + Send + Sync + Debug + 'static + ?Sized,
    D: Send + Sync + 'static + ?Sized,
{
    /// Create and launch a new [`Publisher`] to deliver `initial_document` to `initial_targets`.
    ///
    /// `description` should be a string describing what we're publishing, for the benefit of logs.
    ///
    /// (This method launches a background task.)
    pub fn launch<R, UP>(
        runtime: &R,
        description: String,
        initial_document: Option<Arc<D>>,
        initial_targets: HashSet<Arc<T>>,
        initial_retry_delay: Duration,
        uploader: Arc<UP>,
    ) -> Result<Arc<Self>, SpawnError>
    where
        UP: Uploader<Doc = D, Target = T>,
        R: tor_rtcompat::SleepProvider + Spawn,
    {
        let n_targets = initial_targets.len();
        let action = PublishDirective::new(initial_document, initial_targets);
        let status = PublishStatus::new(action.document.version, n_targets);

        let (action, action_rcv) = watch::channel_with(action);
        let (status_snd, status) = watch::channel_with(status);
        let action = Mutex::new(action);

        let reactor = reactor::PublishReactor::new(
            runtime.clone(),
            description,
            action_rcv,
            status_snd,
            initial_retry_delay,
            uploader,
        );

        runtime.spawn(reactor.run())?;

        Ok(Arc::new(Self {
            directive: action,
            status,
        }))
    }

    /// Change the current document and publish something else instead.
    ///
    /// - Any currently in-flight attempts to publish the old document will be allowed to finish,
    ///   but we will not wait for them before launching attempts to publish the new one.
    /// - If any target has rejected or accepted the old document,
    ///   we will try sending it the new one.
    ///
    /// If `reset_failing_targets` is true, then any targets that are currently waiting before they retry
    /// will be told to retry immediately.
    pub fn set_document(&self, new_document: Option<Arc<D>>, reset_failing_targets: bool) {
        let mut action_guard = self.directive.lock().expect("poisoned lock");
        let mut action = action_guard.borrow_mut();
        let version = action.document.version.next();
        action.document = Document {
            contents: new_document,
            version,
        };
        if reset_failing_targets {
            action.reset_failures_count += 1;
        }
    }

    /// Reset the failure counters and timeouts for all targets that are currently failing.
    ///
    /// Ordinarily, once a target has failed, we wait a while before we try it again.
    /// Calling this function makes the next attempt happen right away.
    pub fn reset_failing_targets(&self) {
        let mut action_guard = self.directive.lock().expect("poisoned lock");
        let mut action = action_guard.borrow_mut();
        action.reset_failures_count += 1;
    }

    /// Change the current set of targets by calling `modify` on it.
    ///
    /// If targets are added, upload attempts will be launched for them.
    ///
    /// If targets are removed, then any in-flight attempts to upload to them will be allowed to finish,
    /// but no further attempts will be launched.
    ///
    /// (As a consequence, if the set of targets is cleared completely,
    /// then all in-flight attempts will be allowed to finish, and no further attempts will be made.)
    pub fn adjust_targets<F>(&self, modify: F)
    where
        F: FnOnce(&mut HashSet<Arc<T>>),
    {
        let mut action_guard = self.directive.lock().expect("poisoned lock");
        let mut action = action_guard.borrow_mut();
        modify(&mut action.targets);
    }

    /// Tell the underlying reactor to stop.
    ///
    /// All inflight attempts to upload will be halted immediately.  This [`Publisher`] object will no
    /// longer be usable.
    ///
    /// This method will return right away.
    pub fn stop(&self) {
        let mut action_guard = self.directive.lock().expect("poisoned lock");
        let mut action = action_guard.borrow_mut();
        action.shutdown = true;
    }

    /// Tell the underlying reactor to stop, and wait for it to shut down.
    ///
    /// All inflight attempts to upload will be halted immediately.
    /// This [`Publisher`] object will no longer be usable.
    ///
    /// This method will wait for the underlying reactor task to report that it has exited.
    pub async fn shutdown(&self) {
        self.stop();
        let mut status = self.status.clone();
        while status.next().await.is_some() {}
    }

    /// Return the current document that we are trying to publish.
    pub fn document(&self) -> Option<Arc<D>> {
        self.directive
            .lock()
            .expect("poisoned lock")
            .borrow()
            .document
            .contents
            .clone()
    }

    /// Return the current targets to which we are trying to publish.
    pub fn targets(&self) -> HashSet<Arc<T>> {
        self.directive
            .lock()
            .expect("poisoned lock")
            .borrow()
            .targets
            .clone()
    }

    /// Return a [`Stream`](futures::Stream) of [`PublishStatus`] objects
    /// representing changes to this publisher's status.
    ///
    /// Intermediate states may be omitted if the state changes more frequently
    /// than this stream is polled.
    pub fn watch_status(&self) -> impl futures::Stream<Item = PublishStatus> {
        self.status.clone()
    }

    /// Return a [`Stream`](futures::Stream) of [`PublishStatus`] objects
    /// representing changes to this publisher's status with respect to the current
    /// document.
    ///
    /// Intermediate states may be omitted if the state changes more frequently
    /// than this stream is polled.
    pub fn watch_current_document_status(&self) -> impl futures::Stream<Item = PublishStatus> {
        use futures::future::ready;
        let cur_doc_version = self
            .directive
            .lock()
            .expect("Lock poisoned")
            .borrow()
            .document
            .version;

        self.status
            .clone()
            // This combination of take_while and filter is a little subtle!
            // The "take_while" causes the stream to be done (and return None) whenever the
            // status publisher is talking about a _later_ version of the document.
            // The "filter" discards all the values from the stream for which cur_doc_version
            // is _less_ than the current version.
            //
            // It might be nice to have a single tor-async-utils implementation for this
            // kind of thing, if we find that we're using it regularly.
            .take_while(move |s| ready(s.document_version <= cur_doc_version))
            .filter(move |s| ready(s.document_version == cur_doc_version))
    }

    /// Return this publisher's current [`PublishStatus`].
    pub fn status(&self) -> PublishStatus {
        self.status.borrow().clone()
    }
}

/// A description of the current operation that the [`Publisher`] is telling
/// the [`PublishReactor`](reactor::PublishReactor) to perform.
///
/// We use [`postage::watch`] to share changes in this object.
#[derive(educe::Educe, Debug)]
#[educe(Clone)]
struct PublishDirective<D: ?Sized, T: Hash + Eq + ?Sized> {
    /// If true, the reactor should shut down right away.
    shutdown: bool,

    /// The current document we're trying to publish, and its associated version number.
    document: Document<D>,

    /// A set of targets to which we want to publish.
    targets: HashSet<Arc<T>>,

    /// A counter that we increment whenever we want to reset
    /// the failure status for every target.
    ///
    /// Whenever the reactor sees that this value has changed,
    /// it marks every target as ready to try uploading again.
    reset_failures_count: usize,
}

impl<D: ?Sized, T: Hash + Eq + ?Sized> PublishDirective<D, T> {
    /// Construct a new [`PublishDirective`].
    fn new(document: Option<Arc<D>>, targets: HashSet<Arc<T>>) -> Self {
        Self {
            shutdown: false,
            document: Document {
                version: DocVersion(0.into()),
                contents: document,
            },
            targets,
            reset_failures_count: 0,
        }
    }
}

/// The version of a document.
///
/// (We use versions rather than Eq on documents, since they are allowed to be quite large.)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct DocVersion(
    // This is sensitive because we may want to use it for hsdesc uploads.
    safelog::Sensitive<u64>,
);

impl DocVersion {
    /// Return the next document version in sequence.
    fn next(&self) -> Self {
        let n = (*self.0) + 1;
        Self(n.into())
    }
}

/// A document we're trying to publish.
#[derive(educe::Educe, Debug)]
#[educe(Clone)]
struct Document<D: ?Sized> {
    /// The version of this document.
    ///
    /// Versions are scoped to a single [`Publisher`].
    version: DocVersion,

    /// The document itself.
    ///
    /// This may be None to indicate that we have nothing to publish at present.
    contents: Option<Arc<D>>,
}

/// The current status of a [`Publisher`]'s attempt to publish the current document.
//
// This information is as reported by the [`PublishReactor`](reactor::PublishReactor)
// to the [`Publisher`].
//
// We use [`postage::watch`] to share changes in this object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishStatus {
    /// The version of the document that we're trying to upload.
    ///
    /// All the counters in this struct are with respect to _this_ version of the document.
    document_version: DocVersion,

    /// The number of targets we are configured to publish to.
    n_targets: usize,

    /// The number of targets that have acknowledged that there is no document to publish.
    n_inert: usize,

    /// The number of targets we have successfully published to.
    n_published: usize,

    /// The number of targets that rejected this document.
    n_rejected: usize,

    /// The number of targets that have failed in some non-retriable way.
    n_failed_permanently: usize,

    /// The number of targets for which we have encountered at least one retriable failure,
    /// and are still trying to upload to.
    n_failing: usize,

    /// The number of targets that we are trying to upload the document to for the first time.
    n_pending: usize,

    /// True if the reactor has begun running.
    initialized: bool,

    /// True if the reactor has shut down.
    shutdown: bool,
}

// TODO: Right now the accessors for this struct are fairly coarse.
// We may want to provide better ones.
impl PublishStatus {
    /// Construct a new PublishStatus.
    fn new(document_version: DocVersion, n_targets: usize) -> Self {
        Self {
            document_version,
            n_targets,
            n_inert: 0,
            n_published: 0,
            n_rejected: 0,
            n_failed_permanently: 0,
            n_failing: 0,
            n_pending: 0,
            initialized: false,
            shutdown: false,
        }
    }

    /// Return true if there is any activity in progress, according to this status.
    ///
    /// This function returns true if we are uploading to any target,
    /// or waiting to upload to any target.
    pub fn is_active(&self) -> bool {
        if self.shutdown {
            return false;
        }
        if !self.initialized {
            return true;
        }

        self.n_failing > 0 || self.n_pending > 0
    }
}

impl std::fmt::Display for PublishStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            document_version,
            n_targets,
            n_inert,
            n_published,
            n_rejected,
            n_failed_permanently,
            n_failing,
            n_pending,
            initialized,
            shutdown,
        } = self;
        let n = n_targets;
        let status = if !*initialized {
            "not initialized"
        } else if *shutdown {
            "shut down"
        } else if self.is_active() {
            "in progress"
        } else if self.n_inert == self.n_targets {
            "paused"
        } else if self.n_published == self.n_targets {
            "successful"
        } else if self.n_published == 0 {
            "failed"
        } else {
            "partially successful"
        };
        let version = document_version.0;

        write!(
            f,
            "Document {version} upload {status}. Of {n} upload targets",
        )?;

        let mut w = |n, s| {
            if n != 0 {
                write!(f, ", {n} {s}")
            } else {
                Ok(())
            }
        };

        w(*n_inert, "are paused")?;
        w(*n_published, "have succeeded")?;
        w(*n_rejected, "have rejected the document")?;
        w(*n_failed_permanently, "have failed non-retriably")?;
        w(*n_failing, "are failing")?;
        w(*n_pending, "are pending")?;
        Ok(())
    }
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use std::collections::HashMap;
    use tor_rtmock::MockRuntime;

    /// State for a single target in our tests.
    #[derive(Clone, Debug, Default)]
    struct TState {
        should_reject: bool,
        should_fail: u8,
        #[allow(clippy::rc_buffer)]
        document: Option<Arc<String>>,
    }

    struct TestUploader {
        state: Arc<Mutex<HashMap<u32, TState>>>,
    }

    #[async_trait]
    impl Uploader for TestUploader {
        type Doc = String;
        type Target = u32;
        async fn upload(&self, target: Arc<u32>, document: Arc<String>) -> Result<(), UploadError> {
            let mut map = self.state.lock().unwrap();
            let entry: &mut TState = map.entry(*target).or_default();
            if entry.should_reject {
                Err(UploadError::Rejected(Rejection::from_message(
                    "document refused".into(),
                )))
            } else if entry.should_fail > 0 {
                entry.should_fail -= 1;
                Err(UploadError::Timeout) // This is a pretend error, but it'll work fine.
            } else {
                entry.document = Some(document);
                Ok(())
            }
        }
    }

    #[test]
    fn successful_upload() {
        MockRuntime::test_with_various(|rt| async move {
            let state = Arc::new(Mutex::new(HashMap::new()));
            let uploader = TestUploader {
                state: Arc::clone(&state),
            };

            let targets = [1, 2, 3].into_iter().map(Arc::new).collect();

            let publisher = Publisher::launch(
                &rt,
                "Testing".into(),
                None,
                targets,
                Duration::new(1, 0),
                Arc::new(uploader),
            )
            .unwrap();

            // Kick off an initial upload.
            publisher.set_document(Some(Arc::new("hello world".into())), false);
            let mut status = publisher.watch_current_document_status();
            while let Some(s) = status.next().await {
                if !s.is_active() {
                    break;
                }
            }

            assert_eq!(state.lock().unwrap().len(), 3);
            for n in 1..=3 {
                let map = state.lock().unwrap();
                assert_eq!(
                    map.get(&n).unwrap().document,
                    Some(Arc::new("hello world".into()))
                );
            }

            // Add a target 4.
            publisher.adjust_targets(|targets| {
                targets.insert(Arc::new(4));
            });
            while let Some(s) = status.next().await {
                if !s.is_active() {
                    break;
                }
            }
            assert_eq!(
                state.lock().unwrap().get(&4).unwrap().document,
                Some(Arc::new("hello world".into()))
            );

            // Drop target 1, then replace the document.
            publisher.adjust_targets(|targets| {
                targets.remove(&1);
            });
            publisher.set_document(Some(Arc::new("HELLO WORLD".into())), false);

            let mut status = publisher.watch_current_document_status();
            while let Some(s) = status.next().await {
                if !s.is_active() {
                    break;
                }
            }

            for n in 1..=4 {
                let map = state.lock().unwrap();
                let s = if n == 1 { "hello world" } else { "HELLO WORLD" };
                assert_eq!(map.get(&n).unwrap().document, Some(Arc::new(s.into())));
            }
        });
    }

    #[test]
    fn test_with_retries() {
        MockRuntime::test_with_various(|rt| async move {
            let state = Arc::new(Mutex::new(HashMap::new()));
            let uploader = TestUploader {
                state: Arc::clone(&state),
            };

            let targets = [1, 2, 3].into_iter().map(Arc::new).collect();
            for t in 1..=3 {
                state.lock().unwrap().insert(
                    t,
                    TState {
                        should_reject: false,
                        should_fail: t as u8,
                        document: None,
                    },
                );
            }

            let publisher = Publisher::launch(
                &rt,
                "Testing".into(),
                Some(Arc::new("hello world".into())),
                targets,
                Duration::new(1, 0),
                Arc::new(uploader),
            )
            .unwrap();

            while publisher.status().is_active() {
                rt.advance_by(Duration::new(1, 0)).await;
            }

            for n in 1..=3 {
                let map = state.lock().unwrap();
                let e = map.get(&n).unwrap();
                assert_eq!(e.document, Some(Arc::new("hello world".into())));
                assert_eq!(e.should_fail, 0);
            }
        });
    }
}
