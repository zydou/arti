//! Backend logic to upload a document to multiple targets
use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{self, AtomicUsize},
    },
    time::Duration,
};

use futures::{
    FutureExt as _, StreamExt as _, future::BoxFuture, select_biased, stream::Fuse,
    stream::FuturesUnordered,
};
use postage::watch;
use tor_basic_utils::retry::RetryDelay;
use tor_error::warn_report;
use tor_rtcompat::SleepProvider;
use tracing::{Level, debug, span, trace, warn};
use web_time_compat::Instant;

use crate::{
    DocVersion, Document, PublishDirective, PublishStatus, Rejection, UploadError, Uploader,
};

/// Identifier for a single action that we have queued for a target.
///
/// (Actions can currently be "try to upload" or "wait till later.")
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
struct ActionNum(NonZeroUsize);

impl ActionNum {
    /// Return a new identifier.
    ///
    /// We do not guarantee that these are permanently unique:
    /// only that there are very unlikely to be two actions with the same ActionNum
    /// active at once.
    fn next() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        loop {
            let val = NEXT.fetch_add(1, atomic::Ordering::Relaxed);
            if let Some(nz) = NonZeroUsize::new(val) {
                return ActionNum(nz);
            }
        }
    }
}

/// Mutable status for a single target.
#[derive(Debug)]
struct TargetStatus {
    /// The current state of this target.
    state: TargetState,

    /// How many times has this target failed since we last received an answer from it?
    /// ("Published" and "Rejected" both count as answers; "Try again later" does not.)
    n_failures: usize,

    /// State of our retry-timing algorithm.
    retry: RetryDelay,

    /// Identifier for the most recent action that we launched for this target.
    ///
    /// (Multiple actions can be pending at once.
    /// We call an action "the latest action for a target"
    /// if its ActionNum matches this value.)
    latest_action: Option<ActionNum>,
}

/// The current state for a single target.
#[derive(Debug)]
#[expect(unused)] // TODO: we don't use all these fields yet; we should remove or expose them.
enum TargetState {
    /// There is no document to upload, so we don't have anything to do.
    NoDocument,

    /// We are ready to try uploading the most recent document to this target.
    Ready,

    /// We are trying to upload the most recent document to this target.
    ///
    /// (Invariant: If a target is in this state, there is an Upload future
    /// among our pending actions for that target.)
    Inflight {
        /// The time when we began trying to upload.
        since: Instant,
    },

    /// An upload attempt has failed; we are waiting for a while before we try again.
    ///
    /// (Invariant: If a target is in this state, there is a Sleep future
    /// among our pending actions for that target.)
    Waiting {
        /// The time until which we are waiting.
        until: Instant,
    },

    /// We have published the most recent document to this target.
    Published,

    /// We have failed permanently for some reason.
    /// We won't retry until the document changes.
    PermanentlyFailed(UploadError),

    /// The target told us that it will not accept the most recent document,
    /// and so we should not try that document again.
    Rejected(Rejection),
}

/// An enum to declare whether a document is present.
//
// (We don't use bool here because bools are error-prone.)
#[derive(Clone, Copy, Debug)]
enum DocumentPresent {
    /// We have a document.
    Present,
    /// We do not currently have a document to upload
    Absent,
}

impl DocumentPresent {
    /// Return the initial state that new targets should enter.
    fn initial_target_state(self) -> TargetState {
        match self {
            DocumentPresent::Present => TargetState::Ready,
            DocumentPresent::Absent => TargetState::NoDocument,
        }
    }
}

impl<D: ?Sized> super::Document<D> {
    /// Return a DocumentPresent for this document.
    fn present(&self) -> DocumentPresent {
        if self.contents.is_some() {
            DocumentPresent::Present
        } else {
            DocumentPresent::Absent
        }
    }
}

impl TargetStatus {
    /// Construct a new TargetStatus in the Ready state.
    fn new(initial_delay: Duration, document_present: DocumentPresent) -> Self {
        Self {
            n_failures: 0,
            retry: RetryDelay::from_duration(initial_delay),
            latest_action: None,
            state: document_present.initial_target_state(),
        }
    }

    /// Called after the latest action for a target has failed:
    /// increments the failure count, and returns the interval for which we should wait.
    ///
    /// If `suggested_delay` is provided, it is an amount that the target
    /// told us to wait before retrying.   We will treat this amount
    /// as a _minimum_.  A `suggested_delay` will not prevent us
    /// from retrying immediately if our failure status is reset.
    fn set_waiting(
        &mut self,
        now: Instant,
        suggested_delay: Option<Duration>,
        action: ActionNum,
    ) -> Duration {
        self.n_failures += 1;
        self.latest_action = Some(action);

        let d = self.retry.next_delay(&mut rand::rng());
        let suggested = suggested_delay.unwrap_or_default();
        let d = std::cmp::max(d, suggested);

        self.state = TargetState::Waiting { until: now + d };
        d
    }

    /// Called after we have decided to launch an upload for a target.
    fn set_inflight(&mut self, now: Instant, action: ActionNum) {
        self.state = TargetState::Inflight { since: now };
        self.latest_action = Some(action);
    }

    /// Change this action's state to Ready.
    fn set_ready(&mut self) {
        self.state = TargetState::Ready;
    }

    /// Reset the failure count and timeout for this target.
    fn reset_failures(&mut self) {
        self.n_failures = 0;
        self.retry.reset();
    }

    /// Called after the latest action for a target has succeeded
    /// in uploading the most recent document.
    fn set_published(&mut self) {
        self.reset_failures();
        self.state = TargetState::Published;
    }

    /// Called after the latest action for a target has been rejected
    /// in uploading the most recent document.
    fn set_rejected(&mut self, rejection: Rejection) {
        self.reset_failures();
        self.state = TargetState::Rejected(rejection);
    }

    /// Mark this target as permanently unable to receive the current
    /// document because of some error `e`.
    fn set_permanently_failed(&mut self, e: UploadError) {
        self.state = TargetState::PermanentlyFailed(e);
    }
}

/// The result of a single action.
#[derive(Debug)]
enum ActionOutcome {
    /// A sleep action has expired.
    DoneSleeping,

    /// An upload action has succeeded.
    Published,

    /// An upload action has been rejected.
    Rejected(Rejection),

    /// An upload action has failed with some error.
    Err(UploadError),
}

impl ActionOutcome {
    /// Construct an [`ActionOutcome`] from the result of [`Uploader::upload()`].
    fn from_upload_result(r: Result<(), UploadError>) -> Self {
        match r {
            Ok(()) => Self::Published,
            Err(UploadError::Rejected(rejection)) => Self::Rejected(rejection),
            Err(e) => Self::Err(e),
        }
    }
}

/// The type returned by one of the action futures in `PublishReactor.inflight`.
struct TaskResult<T: ?Sized> {
    /// Which target were we taking this action for?
    target: Arc<T>,
    /// An `ActionNum` to identify whether the action was the latest one for the target.
    action: ActionNum,
    /// Which document was the most recent when the action was launched?
    doc_version: DocVersion,
    /// The result of the action.
    outcome: ActionOutcome,
}

/// Backend data that we use to publish a document (or series of documents).
pub(crate) struct PublishReactor<R: SleepProvider, D: ?Sized, T, UP: ?Sized>
where
    T: Hash + Eq + ?Sized,
{
    /// A sleep provider used to launch wait actions.
    runtime: R,

    /// A description of what we're uploading, for log messages.
    description: String,

    /// The current actions that the [`Publisher`](crate::Publisher) has told us to take.
    ///
    /// We watch for changes in this directive and adjust our behavior accordingly.
    directive: Fuse<watch::Receiver<PublishDirective<D, T>>>,

    /// A channel we use to report our current status to the [`Publisher`](crate::Publisher).
    status: watch::Sender<PublishStatus>,

    /// The document which we are currently trying to upload.
    latest_document: Document<D>,

    /// The initial retry delay for a failed target.
    ///
    /// (Used to seed our retry delay algorithm.)
    initial_retry_delay: Duration,

    /// The most recent value we've seen for the `reset_count` field of our `PublishDirective`.
    latest_reset_count: usize,

    /// The [`Uploader`] object we use to upload documents.
    uploader: Arc<UP>,

    /// A set of all our pending actions.
    ///
    /// Actions are either upload attempts, or sleep actions.
    ///
    /// Additionally, this `FuturesUnordered` contains a single future that is always
    /// pending, to guarantee that `inflight.next()` never returns None.
    ///
    /// Multiple actions may be inflight for a given target at a time.
    /// This is deliberate:
    /// If we change our document while the upload of an older document is inflight,
    /// we do not want to stop the inflight upload in the middle.
    ///
    /// TODO: We _could_ cancel any Sleep action that is superseded.
    /// That's a fair amount of effort, though, since FuturesUnordered doesn't have
    /// very nice accessors nor does Sleep have a good way to make it cancellable.
    inflight: FuturesUnordered<BoxFuture<'static, TaskResult<T>>>,

    /// The current status for each of our live targets.
    target_status: HashMap<Arc<T>, TargetStatus>,
}

/// Return type used to tell the reactor loop to exit.
#[derive(Debug)]
struct ExitLoop;

impl<R: SleepProvider, D, T, UP> PublishReactor<R, D, T, UP>
where
    D: ?Sized + Send + Sync + 'static,
    T: Hash + Eq + Send + Sync + Debug + ?Sized + 'static,
    UP: Uploader<Doc = D, Target = T> + ?Sized,
{
    /// Construct a new reactor.
    ///
    /// (Does not launch any background task or do any work).
    pub(crate) fn new(
        runtime: R,
        description: String,
        action: watch::Receiver<PublishDirective<D, T>>,
        status: watch::Sender<PublishStatus>,
        initial_retry_delay: Duration,
        publisher: Arc<UP>,
    ) -> Self {
        let (latest_document, latest_reset_count, targets) = {
            let cur_action = action.borrow();
            (
                cur_action.document.clone(),
                cur_action.reset_failures_count,
                cur_action.targets.clone(),
            )
        };

        let inflight = FuturesUnordered::new();
        // Add a never-finished future to keep FuturesUnordered from saying it's done.
        inflight.push(Box::pin(std::future::pending()) as _);
        let document_present = latest_document.present();

        let target_status = targets
            .into_iter()
            .map(|t| (t, TargetStatus::new(initial_retry_delay, document_present)))
            .collect();

        Self {
            runtime,
            description,
            directive: action.fuse(),
            status,
            latest_document,
            initial_retry_delay,
            latest_reset_count,
            uploader: publisher,
            inflight,
            target_status,
        }
    }

    /// Run forever, handling changes in the [`PublishDirective`], uploading documents, and reporting status.
    pub(crate) async fn run(mut self) {
        let _span = span!(Level::TRACE, "Publishing {}", self.description);

        // The first time we start, we begin uploading.
        self.launch_ready_requests(self.runtime.now());
        self.recalculate_status();

        'mainloop: loop {
            select_biased! {
                // We've been told to do something new, _or_ the last handle to the Publisher has
                // been dropped.
                directive_changed = self.directive.next() => {
                    let Some(directive) = directive_changed else {
                        // The watch::Receiver stream returned None,
                        // so we know that the last handle has been dropped.
                        trace!("directive stream dropped; exiting");
                        break 'mainloop;
                    };

                    // Process any change in the action.
                    if let Err(ExitLoop) = self.directive_changed(&directive) {
                        trace!("directive is shutdown: exiting");
                        break 'mainloop;
                    }

                    // Update our `PublishStatus`.
                    self.recalculate_status();
                }

                // Some action has finished; update accordingly.
                publication_result = self.inflight.next() => {
                    let task_result = publication_result.expect("Stream ended unexpectedly.");
                    self.handle_task_result(task_result);
                }
            }
        }

        self.status.borrow_mut().shutdown = true;
    }

    /// Called when a task in `self.inflight` produces a result.
    ///
    /// Update our status and launch new tasks as appropriate.
    fn handle_task_result(&mut self, task_result: TaskResult<T>) {
        let TaskResult {
            target,
            action,
            doc_version,
            outcome,
        } = task_result;

        let Some(status) = self.target_status.get_mut(&target) else {
            // The target isn't here, so we don't care about what happened with it.
            trace!(?target, ?outcome, "Ignoring result for removed target.");
            return;
        };
        if Some(action) != status.latest_action {
            // There is a more recent inflight action for this target;
            // ignore the results of this one.
            //
            // (See note on `Publish.inflight` about why we can have multiple inflight
            // actions.)
            //
            // We use a != comparison here rather than < since we allow the action
            // identifier space to wrap around.
            trace!(?target, ?outcome, "Ignoring result for superseded action.");
            return;
        }

        match outcome {
            ActionOutcome::Published => {
                if doc_version != self.latest_document.version {
                    // We aren't tracking this particular document any more;
                    // this was a stale upload.
                    return;
                }

                trace!(?target, "Document published");
                status.set_published();
            }
            ActionOutcome::Rejected(rejection) => {
                if doc_version != self.latest_document.version {
                    // We aren't tracking this particular document any more;
                    // this was a stale upload.
                    return;
                }

                warn!(
                    "{} upload rejected. The target ({:?}) said {}",
                    &self.description, &target, &rejection
                );

                status.set_rejected(rejection);
            }
            ActionOutcome::DoneSleeping => {
                // It's time to try a new upload to this target.
                self.launch_one(&target, self.runtime.now());
            }
            ActionOutcome::Err(e) if !e.is_retriable() => {
                warn_report!(
                    &e,
                    "Attempt to publish {} to {:?} failed. Not retriable.",
                    &self.description,
                    &target
                );
                status.set_permanently_failed(e);
            }
            ActionOutcome::Err(e) => {
                // We failed to upload: we log the error and wait until it's time to
                // retry.

                // TODO: This might need to be downgraded, but for now we'll leave it as-is.
                warn_report!(
                    &e,
                    "Attempt to publish {} to {:?} failed. We'll retry later.",
                    &self.description,
                    &target
                );
                self.begin_sleeping(target, e.suggested_delay(), self.runtime.now());
            }
        }

        self.recalculate_status();
    }

    /// Called when we have received a new [`PublishDirective`] from the publisher.
    ///
    /// Update the status of all of our targets, and launch new uploads as appropriate.
    fn directive_changed(&mut self, directive: &PublishDirective<D, T>) -> Result<(), ExitLoop> {
        use TargetState::*;

        if directive.shutdown {
            // We're supposed to shut down.  Just go ahead and do that.
            return Err(ExitLoop);
        }

        // Check to see if any targets have been added or removed;
        // update target_status accordingly.
        let document_present = directive.document.present();
        for new_target in directive.targets.iter() {
            self.target_status
                .entry(new_target.clone())
                .or_insert_with(|| TargetStatus::new(self.initial_retry_delay, document_present));
        }
        self.target_status
            .retain(|t, _| directive.targets.contains(t));

        // Have gotten a new document?  Have we been told to reset failing targets?
        //
        // (We use != rather than > here since we want to allow these counters to wrap around.)
        let document_changed = directive.document.version != self.latest_document.version;
        let reset_failing_targets = directive.reset_failures_count != self.latest_reset_count;
        // Update our own versions of the counters from the PublishDirective.
        if document_changed {
            self.latest_document = directive.document.clone();
        }
        self.latest_reset_count = directive.reset_failures_count;

        let no_document = directive.document.contents.is_none();
        if document_changed {
            let v = self.latest_document.version;
            if no_document {
                trace!("Publisher paused (version {v:?})");
            } else {
                trace!("New document (version {v:?})");
            }
        }

        // Reset failure timings if appropriate,
        // and mark targets ready if we want to launch a new upload to them.
        for status in self.target_status.values_mut() {
            if reset_failing_targets {
                status.reset_failures();
            }

            if no_document {
                status.state = NoDocument;
                continue;
            }

            let should_reset = match &status.state {
                // If this target is waiting, then we should let it continue
                // waiting unless we've been told to reset failing targets.
                Waiting { .. } => reset_failing_targets,

                // If the target is ready, there's no point in making it ready.
                Ready => false,

                // If we're currently uploading to a target,
                // we only want to launch a new upload if the document changed.
                Inflight { .. } => document_changed,

                // If we've published successfully,
                // or if we have been rejected,
                // or if we had nothing to do,
                // we only want to launch a new upload if the document changed.
                Published | Rejected(_) | PermanentlyFailed(_) => document_changed,

                // If we had no document, we want to launch now that we have one.
                NoDocument => true,
            };

            if should_reset {
                status.set_ready();
            }
        }

        self.launch_ready_requests(self.runtime.now());

        Ok(())
    }

    /// Launch a new upload for every Ready target,
    /// making its status Inflight.
    fn launch_ready_requests(&mut self, now: Instant) {
        // Build a list of the ready targets.
        //
        // This is a separate step to avoid a concurrent mutable/immutable borrow.
        let to_launch: Vec<Arc<T>> = self
            .target_status
            .iter()
            .filter(|(_target, status)| matches!(&status.state, TargetState::Ready))
            .map(|(target, _status)| Arc::clone(target))
            .collect();

        // Launch an upload for each of them.
        for target in to_launch {
            self.launch_one(&target, now);
        }
    }

    /// Compute a new [`PublishStatus`] reflecting our progress uploading the current document,
    /// and deliver it to the Publisher.
    fn recalculate_status(&mut self) {
        use TargetState::*;

        let n_targets = self.target_status.len();
        let mut n_inert = 0;
        let mut n_pending = 0;
        let mut n_failing = 0;
        let mut n_failed = 0;
        let mut n_published = 0;
        let mut n_rejected = 0;

        for status in self.target_status.values() {
            match &status.state {
                NoDocument => n_inert += 1,
                Published => n_published += 1,
                Rejected(_) => n_rejected += 1,
                Ready => {}
                PermanentlyFailed(_) => n_failed += 1,
                Inflight { .. } | Waiting { .. } => {
                    if status.n_failures > 0 {
                        n_failing += 1;
                    } else {
                        n_pending += 1;
                    }
                }
            }
        }

        let new_status = PublishStatus {
            document_version: self.latest_document.version,
            n_targets,
            n_inert,
            n_published,
            n_rejected,
            n_failed_permanently: n_failed,
            n_failing,
            n_pending,
            initialized: true,
            shutdown: false,
        };
        debug!("Publishing {}: {}", &self.description, &new_status);

        {
            *self.status.borrow_mut() = new_status;
        }
    }

    /// Launch an upload action for a given `target`, changing its status to Inflight.
    fn launch_one(&mut self, target: &Arc<T>, now: Instant) {
        // Launch the publish request, and add it to inflight.
        let Some(status) = self.target_status.get_mut(target) else {
            return;
        };
        let Some(document) = &self.latest_document.contents else {
            // There's no document, so we can't upload it.
            return;
        };

        trace!(?target, "Launching {} upload request", &self.description);

        let doc_version = self.latest_document.version;
        let action = ActionNum::next();

        let uploader = Arc::clone(&self.uploader);
        let target = Arc::clone(target);
        let document = Arc::clone(document);
        let future = async move {
            uploader
                .upload(Arc::clone(&target), document)
                .map(move |res| TaskResult {
                    target,
                    action,
                    doc_version,
                    outcome: ActionOutcome::from_upload_result(res),
                })
                .await
        };
        self.inflight.push(Box::pin(future));

        status.set_inflight(now, action);
    }

    /// Launch a sleep action for a given `target`, changing its status to `Waiting`.
    fn begin_sleeping(&mut self, target: Arc<T>, suggested_delay: Option<Duration>, now: Instant) {
        // Launch the publish request, and add it to inflight.
        let Some(status) = self.target_status.get_mut(&target) else {
            return;
        };

        let action = ActionNum::next();
        let delay = status.set_waiting(now, suggested_delay, action);

        trace!(
            ?target,
            ?delay,
            "Waiting for next {} upload attempt.",
            &self.description
        );

        let doc_version = self.latest_document.version;
        let future = self.runtime.sleep(delay).map(move |()| TaskResult {
            target,
            action,
            doc_version,
            outcome: ActionOutcome::DoneSleeping,
        });
        self.inflight.push(Box::pin(future));
    }
}
