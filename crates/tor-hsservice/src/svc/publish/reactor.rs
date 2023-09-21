//! The onion service publisher reactor.
//!
//! TODO HSS: write the docs

use std::fmt::Debug;
use std::iter;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::task::{SpawnError, SpawnExt};
use futures::{select_biased, FutureExt, SinkExt, StreamExt};
use postage::sink::SendError;
use postage::watch;
use retry_error::RetryError;
use tor_basic_utils::retry::RetryDelay;
use tor_hscrypto::RevisionCounter;
use tracing::{debug, error, trace};

use tor_bytes::EncodeError;
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_dirclient::request::HsDescUploadRequest;
use tor_dirclient::request::Requestable;
use tor_dirclient::{send_request, Error as DirClientError, RequestError};
use tor_error::{internal, into_internal, warn_report};
use tor_hscrypto::pk::{HsBlindId, HsId, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_linkspec::{CircTarget, HasRelayIds, OwnedCircTarget, RelayIds};
use tor_netdir::{NetDir, NetDirProvider, Relay, Timeliness};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

use crate::config::OnionServiceConfig;
use crate::ipt_set::IptsPublisherView;
use crate::svc::netdir::{wait_for_netdir, NetdirProviderShutdown};
use crate::svc::publish::backoff::{BackoffError, BackoffSchedule, RetriableError, Runner};
use crate::svc::publish::descriptor::{build_sign, DescriptorStatus, VersionedDescriptor};

/// The upload rate-limiting threshold.
///
/// Before initiating an upload, the reactor checks if the last upload was at least
/// `UPLOAD_RATE_LIM_THRESHOLD` seconds ago. If so, it uploads the descriptor to all HsDirs that
/// need it. If not, it schedules the upload to happen `UPLOAD_RATE_LIM_THRESHOLD` seconds from the
/// current time.
//
// TODO HSS: this value is probably not right.
const UPLOAD_RATE_LIM_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// The maximum number of concurrent upload tasks per time period.
//
// TODO HSS: this value was arbitrarily chosen and may not be optimal.
//
// The uploads for all TPs happen in parallel.  As a result, the actual limit for the maximum
// number of concurrent upload tasks is multiplied by a number which depends on the TP parameters
// (currently 2, which means the concurrency limit will, in fact, be 32).
//
// We should try to decouple this value from the TP parameters.
const MAX_CONCURRENT_UPLOADS: usize = 16;

/// A reactor for the HsDir [`Publisher`](super::Publisher).
///
/// The entrypoint is [`Reactor::run`].
//
// TODO HSS: We need to make sure we don't end up reuploading an identical descriptor
// Upon receiving an `Event`, the publisher shouldn't update its `DescriptorBuilder` or mark the
// descriptor dirty unless it actually changed.
//
// If the value of the `DescriptorBuilder` field the `Event` would've updated is the same as the
// new one read from the `Event`, the publisher should simply not update it (or mark the descriptor
// dirty).
#[must_use = "If you don't call run() on the reactor, it won't publish any descriptors."]
pub(super) struct Reactor<R: Runtime, M: Mockable> {
    /// The immutable, shared inner state.
    imm: Arc<Immutable<R, M>>,
    /// The public key of the service.
    hsid_key: HsIdKey,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// The mutable inner state,
    inner: Arc<Mutex<Inner>>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    /// A channel for receiving updates regarding our [`PublishStatus`].
    ///
    /// The main loop of the reactor watches for updates on this channel.
    ///
    /// When the [`PublishStatus`] changes to [`UploadScheduled`](PublishStatus::UploadScheduled),
    /// we can start publishing descriptors.
    ///
    /// If the [`PublishStatus`] is [`AwaitingIpts`](PublishStatus::AwaitingIpts), publishing is
    /// paused until we receive a notification on `ipt_watcher` telling us the IPT manager has
    /// established some introduction points.
    publish_status_rx: watch::Receiver<PublishStatus>,
    /// A sender for updating our [`PublishStatus`].
    ///
    /// When our [`PublishStatus`] changes to [`UploadScheduled`](PublishStatus::UploadScheduled),
    /// we can start publishing descriptors.
    publish_status_tx: watch::Sender<PublishStatus>,
    /// A channel for the telling the upload reminder task (spawned in [`Reactor::run`]) when to
    /// remind us that we need to retry a rate-limited upload.
    ///
    /// The [`Instant`] sent on this channel represents the earliest time when the upload can be
    /// rescheduled. The receiving end of this channel will initially observe `None` (the default
    /// value of the inner type), which indicates there are no pending uploads to reschedule.
    ///
    /// Note: this can't be a non-optional `Instant` because:
    ///   * [`postage::watch`] channels require an inner type that implements `Default`, which
    ///   `Instant` does not implement
    ///   * `Receiver`s are always observe an initial value, even if nothing was sent on the
    ///   channel. Since we don't want to reschedule the upload until we receive a notification
    ///   from the sender, we `None` as a special value that tells the upload reminder task to
    ///   block until it receives a non-default value
    ///
    /// This field is initialized in [`Reactor::run`].
    ///
    // TODO HSS: decide if this is the right approach for implementing rate-limiting
    rate_lim_upload_tx: Option<watch::Sender<Option<Instant>>>,
    /// A channel for sending upload completion notifications.
    ///
    /// This channel is polled in the main loop of the reactor.
    upload_task_complete_rx: Receiver<TimePeriodUploadResult>,
    /// A channel for receiving upload completion notifications.
    ///
    /// A copy of this sender is handed to each upload task.
    upload_task_complete_tx: Sender<TimePeriodUploadResult>,
}

/// The immutable, shared state of the descriptor publisher reactor.
#[derive(Clone)]
struct Immutable<R: Runtime, M: Mockable> {
    /// The runtime.
    runtime: R,
    /// Mockable state.
    ///
    /// This is used for launching circuits and for obtaining random number generators.
    mockable: M,
    /// The service for which we're publishing descriptors.
    hsid: HsId,
}

/// Mockable state for the descriptor publisher reactor.
///
/// This enables us to mock parts of the [`Reactor`] for testing purposes.
#[async_trait]
pub(super) trait Mockable: Clone + Send + Sync + Sized + 'static {
    /// The type of random number generator.
    type Rng: rand::Rng + rand::CryptoRng;

    /// Return a random number generator.
    fn thread_rng(&self) -> Self::Rng;

    /// Create a circuit of the specified `kind` to `target`.
    async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<Arc<ClientCirc>, tor_circmgr::Error>
    where
        T: CircTarget + Send + Sync;
}

/// The mockable state of the reactor.
#[derive(Clone)]
pub(super) struct ReactorState<R: Runtime>(Arc<HsCircPool<R>>);

impl<R: Runtime> ReactorState<R> {
    /// Create a new `ReactorState`.
    pub(super) fn new(circpool: Arc<HsCircPool<R>>) -> Self {
        Self(circpool)
    }
}

#[async_trait]
impl<R: Runtime> Mockable for ReactorState<R> {
    type Rng = rand::rngs::ThreadRng;

    fn thread_rng(&self) -> Self::Rng {
        rand::thread_rng()
    }

    async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<Arc<ClientCirc>, tor_circmgr::Error>
    where
        T: CircTarget + Send + Sync,
    {
        self.0.get_or_launch_specific(netdir, kind, target).await
    }
}

/// The mutable state of a [`Reactor`].
struct Inner {
    /// The onion service config.
    config: Arc<OnionServiceConfig>,
    /// The relevant time periods.
    ///
    /// This includes the current time period, as well as any other time periods we need to be
    /// publishing descriptors for.
    time_periods: Vec<TimePeriodContext>,
    /// Our most up to date netdir.
    netdir: Arc<NetDir>,
    /// The timestamp of our last upload.
    ///
    /// Note: This is only used for deciding when to reschedule a rate-limited upload. It is _not_
    /// used for retrying failed uploads (these are handled internally by
    /// [`Reactor::upload_descriptor_with_retries`]).
    //
    // TODO HSS: maybe we should implement rate-limiting on a per-hsdir basis? It's probably not
    // necessary though.
    last_uploaded: Option<Instant>,
}

/// The part of the reactor state that changes with every time period.
struct TimePeriodContext {
    /// The time period.
    period: TimePeriod,
    /// The blinded HsId.
    blind_id: HsBlindId,
    /// The HsDirs to use in this time period.
    ///
    // We keep a list of `RelayIds` because we can't store a `Relay<'_>` inside the reactor
    // (the lifetime of a relay is tied to the lifetime of its corresponding `NetDir`. To
    // store `Relay<'_>`s in the reactor, we'd need a way of atomically swapping out both the
    // `NetDir` and the cached relays, and to convince Rust what we're doing is sound)
    hs_dirs: Vec<(RelayIds, DescriptorStatus)>,
    /// The current version of the descriptor.
    revision_counter: u64,
    /// The revision counter of the last successful upload, if any.
    last_successful: Option<RevisionCounter>,
}

impl TimePeriodContext {
    /// Create a new `TimePeriodContext`.
    fn new(
        period: TimePeriod,
        blind_id: HsBlindId,
        netdir: &Arc<NetDir>,
    ) -> Result<Self, ReactorError> {
        Ok(Self {
            period,
            blind_id,
            hs_dirs: Self::compute_hsdirs(period, blind_id, netdir, iter::empty())?,
            // The revision counter is set back to 0 each time we get a new blinded public key/time
            // period. According to rend-spec-v3 Appendix F. this shouldn't be an issue:
            //
            //   Implementations MAY generate revision counters in any way they please,
            //   so long as they are monotonically increasing over the lifetime of each
            //   blinded public key
            revision_counter: 0,
            last_successful: None,
        })
    }

    /// Recompute the HsDirs for this time period.
    ///
    /// This function should be called whenever there the consensus/NetDir changes.
    ///
    /// Note: Our set of HsDirs for this time period only changes if the new consensus:
    ///
    ///   * removes relays that we're currently using as HsDirs, or
    ///   * adds or removes relays in a way that changes our starting index for selecting
    ///   `spread_store` HsDirs on the hash ring (`hs_service_index`)
    fn recompute_hs_dirs(&mut self, netdir: &Arc<NetDir>) -> Result<(), ReactorError> {
        self.hs_dirs =
            Self::compute_hsdirs(self.period, self.blind_id, netdir, self.hs_dirs.iter())?;

        Ok(())
    }

    /// Recompute the HsDirs for this time period.
    fn compute_hsdirs<'r>(
        period: TimePeriod,
        blind_id: HsBlindId,
        netdir: &Arc<NetDir>,
        mut old_hsdirs: impl Iterator<Item = &'r (RelayIds, DescriptorStatus)>,
    ) -> Result<Vec<(RelayIds, DescriptorStatus)>, ReactorError> {
        let hs_dirs = netdir.hs_dirs_upload([(blind_id, period)].into_iter())?;

        Ok(hs_dirs
            .map(|(_, hs_dir)| {
                let mut builder = RelayIds::builder();
                if let Some(ed_id) = hs_dir.ed_identity() {
                    builder.ed_identity(*ed_id);
                }

                if let Some(rsa_id) = hs_dir.rsa_identity() {
                    builder.rsa_identity(*rsa_id);
                }

                let relay_id = builder.build().unwrap_or_else(|_| RelayIds::empty());

                // Have we uploaded the descriptor to thiw relay before? If so, we don't need to
                // reupload it unless it was already dirty and due for a reupload.
                let status = match old_hsdirs.find(|(id, _)| *id == relay_id) {
                    Some((_, status)) => *status,
                    None => DescriptorStatus::Dirty,
                };

                (relay_id, status)
            })
            .collect::<Vec<_>>())
    }

    /// Mark the descriptor dirty for all HSDirs of this time period.
    fn mark_all_dirty(&mut self) {
        self.hs_dirs
            .iter_mut()
            .for_each(|(_relay_id, status)| *status = DescriptorStatus::Dirty);
    }

    /// Return the revision counter for this time period.
    fn current_revision_counter(&self) -> RevisionCounter {
        self.revision_counter.into()
    }

    /// Increment the revision counter for this time period, returning the new value.
    fn inc_revision_counter(&mut self) -> RevisionCounter {
        self.revision_counter += 1;

        self.revision_counter.into()
    }
}

/// A reactor error
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ReactorError {
    /// Failed to get network directory
    #[error("failed to get a network directory")]
    Netdir(#[from] tor_netdir::Error),

    /// The network directory provider is shutting down without giving us the
    /// netdir we asked for.
    #[error("{0}")]
    NetdirProviderShutdown(#[from] NetdirProviderShutdown),

    /// Failed to build a descriptor.
    #[error("could not build a hidden service descriptor")]
    HsDescBuild(#[from] EncodeError),

    /// Failed to publish a descriptor.
    #[error("failed to publish a descriptor")]
    PublishFailure(RetryError<UploadError>),

    /// Unable to spawn task
    //
    // TODO lots of our Errors have a variant exactly like this.
    // Maybe we should make a struct tor_error::SpawnError.
    #[error("Unable to spawn {spawning}")]
    Spawn {
        /// What we were trying to spawn.
        spawning: &'static str,
        /// What happened when we tried to spawn it.
        #[source]
        cause: Arc<SpawnError>,
    },

    /// A fatal error that caused the reactor to shut down.
    //
    // TODO HSS: add more context to this error?
    #[error("publisher reactor is shutting down")]
    ShuttingDown,

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl ReactorError {
    /// Construct a new `ReactorError` from a `SpawnError`.
    //
    // TODO lots of our Errors have a function exactly like this.
    pub(super) fn from_spawn(spawning: &'static str, err: SpawnError) -> ReactorError {
        ReactorError::Spawn {
            spawning,
            cause: Arc::new(err),
        }
    }
}

/// An error that occurs while trying to upload a descriptor.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum UploadError {
    /// An error that has occurred after we have contacted a directory cache and made a circuit to it.
    #[error("descriptor upload request failed")]
    Request(#[from] RequestError),

    /// Failed to establish circuit to hidden service directory
    #[error("circuit failed")]
    Circuit(#[from] tor_circmgr::Error),

    /// Failed to establish stream to hidden service directory
    #[error("stream failed")]
    Stream(#[source] tor_proto::Error),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl<R: Runtime, M: Mockable> Reactor<R, M> {
    /// Create a new `Reactor`.
    pub(super) async fn new(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: M,
        config: Arc<OnionServiceConfig>,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    ) -> Result<Self, ReactorError> {
        /// The maximum size of the upload completion notifier channel.
        ///
        /// The channel we use this for is a futures::mpsc channel, which has a capacity of
        /// `UPLOAD_CHAN_BUF_SIZE + num-senders`. We don't need the buffer size to be non-zero, as
        /// each sender will send exactly one message.
        const UPLOAD_CHAN_BUF_SIZE: usize = 0;

        let hsid_key: HsIdKey = hsid
            .try_into()
            .expect("failed to recover ed25519 public key from hsid?!");
        let netdir = wait_for_netdir(dir_provider.as_ref(), Timeliness::Timely).await?;

        let time_periods = Self::compute_time_periods(&netdir, &hsid_key)?;

        let (upload_task_complete_tx, upload_task_complete_rx) =
            mpsc::channel(UPLOAD_CHAN_BUF_SIZE);

        let (publish_status_tx, publish_status_rx) = watch::channel();

        let imm = Immutable {
            runtime,
            mockable,
            hsid,
        };

        let inner = Inner {
            time_periods,
            config,
            netdir,
            last_uploaded: None,
        };

        Ok(Self {
            imm: Arc::new(imm),
            inner: Arc::new(Mutex::new(inner)),
            hsid_key,
            dir_provider,
            ipt_watcher,
            config_rx,
            publish_status_rx,
            publish_status_tx,
            rate_lim_upload_tx: None,
            upload_task_complete_rx,
            upload_task_complete_tx,
        })
    }

    /// Start the reactor.
    ///
    /// Under normal circumstances, this function runs indefinitely.
    ///
    /// Note: this also spawns the "reminder task" that we use to reschedule uploads whenever we
    /// get rate-limited.
    pub(super) async fn run(mut self) -> Result<(), ReactorError> {
        debug!("starting descriptor publisher reactor");

        // There will be at most one pending upload.
        let (rate_lim_upload_tx, mut rate_lim_upload_rx) = watch::channel();
        let (mut schedule_upload_tx, mut schedule_upload_rx) = watch::channel();

        self.rate_lim_upload_tx = Some(rate_lim_upload_tx);

        let rt = self.imm.runtime.clone();
        // Spawn the task that will remind us to retry any rate-limited uploads.
        let _ = self.imm.runtime.spawn(async move {
            // The sender tells us how long to wait until to schedule the upload
            while let Some(scheduled_time) = rate_lim_upload_rx.next().await {
                let Some(scheduled_time) = scheduled_time else {
                    // `None` is the initially observed, default value of this postage::watch
                    // channel, and it means there are no pending uploads to reschedule.
                    continue;
                };

                // Check how long we have to sleep until we're no longer rate-limited.
                let duration = scheduled_time.checked_duration_since(rt.now());

                // If duration is `None`, it means we're past `scheduled_time`, so we don't need to
                // sleep at all.
                if let Some(duration) = duration {
                    rt.sleep(duration).await;
                }

                // Enough time has elapsed. Remind the reactor to retry the upload.
                if let Err(e) = schedule_upload_tx.send(()).await {
                    // TODO HSS: update publisher state
                    debug!("failed to notify reactor to reattempt upload");
                }
            }

            debug!("reupload task channel closed!");
        });

        let err = loop {
            if let Err(e) = self.run_once(&mut schedule_upload_rx).await {
                break e;
            }
        };

        debug!("reactor stoped: {err}");

        Err(err)
    }

    /// Run one iteration of the reactor loop.
    async fn run_once(
        &mut self,
        schedule_upload_rx: &mut watch::Receiver<()>,
    ) -> Result<(), ReactorError> {
        let mut netdir_events = self.dir_provider.events();

        select_biased! {
            res = self.upload_task_complete_rx.next().fuse() => {
                let upload_res = res.ok_or(ReactorError::ShuttingDown)?;

                self.handle_upload_results(upload_res);
            }
            netidr_event = netdir_events.next().fuse() => {
                // The consensus changed. Grab a new NetDir.
                let netdir = self.dir_provider.netdir(Timeliness::Timely)?;

                self.handle_consensus_change(netdir).await?;
            }
            update = self.ipt_watcher.await_update().fuse() => {
                self.handle_ipt_change(update).await?;
            },
            config = self.config_rx.next().fuse() => {
                let config = config.ok_or(ReactorError::ShuttingDown)?;
                self.handle_svc_config_change(config).await?;
            },
            res = schedule_upload_rx.next().fuse() => {
                let _: () = res.ok_or(ReactorError::ShuttingDown)?;

                // Unless we're waiting for IPTs, reattempt the rate-limited upload in the next
                // iteration.
                self.update_publish_status(PublishStatus::UploadScheduled).await?;
            },
            should_upload = self.publish_status_rx.next().fuse() => {
                let should_upload = should_upload.ok_or(ReactorError::ShuttingDown)?;

                // Our PublishStatus changed -- are we ready to publish?
                if should_upload == PublishStatus::UploadScheduled {
                    // TODO HSS: if upload_all fails, we don't reattempt the upload until a state
                    // change is triggered by an external event (such as a consensus or IPT change)
                    self.update_publish_status(PublishStatus::Idle).await?;
                    self.upload_all().await?;
                }
            }
        }

        Ok(())
    }

    /// Returns the current status of the publisher
    fn status(&self) -> PublishStatus {
        *self.publish_status_rx.borrow()
    }

    /// Handle a batch of upload outcomes,
    /// possibly updating the status of the descriptor for the corresponding HSDirs.
    fn handle_upload_results(&self, results: TimePeriodUploadResult) {
        let mut inner = self.inner.lock().expect("poisoned lock");
        inner.last_uploaded = Some(self.imm.runtime.now());

        // Check which time period these uploads pertain to.
        let period = inner
            .time_periods
            .iter_mut()
            .find(|ctx| ctx.period == results.time_period);

        let Some(period) = period else {
            // The uploads were for a time period that is no longer relevant, so we
            // can ignore the result.
            return;
        };

        for upload_res in results.hsdir_result {
            let relay = period
                .hs_dirs
                .iter_mut()
                .find(|(relay_ids, _status)| relay_ids == &upload_res.relay_ids);

            let Some((relay, status)) = relay else {
                // This HSDir went away, so the result doesn't matter.
                return;
            };

            if upload_res.upload_res == UploadStatus::Success {
                let update_last_successful = match period.last_successful {
                    None => true,
                    Some(counter) => counter <= results.revision_counter,
                };

                if update_last_successful {
                    period.last_successful = Some(results.revision_counter);
                    // TODO HSS: Is it possible that this won't update the statuses promptly
                    // enough. For example, it's possible for the reactor to see a Dirty descriptor
                    // and start an upload task for a descriptor has already been uploaded (or is
                    // being uploaded) in another task, but whose upload results have not yet been
                    // processed.
                    //
                    // This is probably made worse by the fact that the statuses are updated in
                    // batches (grouped by time period), rather than one by one as the upload tasks
                    // complete (updating the status involves locking the inner mutex, and I wanted
                    // to minimize the locking/unlocking overheads). I'm not sure handling the
                    // updates in batches was the correct decision here.
                    *status = DescriptorStatus::Clean;
                }
            }

            // TODO HSS: maybe the failed uploads should be rescheduled at some point.
        }
    }

    /// Maybe update our list of HsDirs.
    async fn handle_consensus_change(&mut self, netdir: Arc<NetDir>) -> Result<(), ReactorError> {
        let _old: Arc<NetDir> = self.replace_netdir(netdir);

        self.recompute_hs_dirs()?;
        self.update_publish_status(PublishStatus::UploadScheduled)
            .await?;

        Ok(())
    }

    /// Recompute the HsDirs for all relevant time periods.
    fn recompute_hs_dirs(&self) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let inner = &mut *inner;

        // Update our list of relevant time periods.
        inner.time_periods = Self::compute_time_periods(&inner.netdir, &self.hsid_key)?;

        for period in inner.time_periods.iter_mut() {
            period.recompute_hs_dirs(&inner.netdir)?;
        }

        Ok(())
    }

    /// Compute the [`TimePeriodContext`]s for the time periods from the specified [`NetDir`].
    fn compute_time_periods(
        netdir: &Arc<NetDir>,
        hsid_key: &HsIdKey,
    ) -> Result<Vec<TimePeriodContext>, ReactorError> {
        netdir
            .hs_all_time_periods()
            .iter()
            .map(|period| {
                let (blind_id, _subcredential) = hsid_key
                    .compute_blinded_key(*period)
                    .expect("failed to compute blinded key?!"); // TODO HSS: perhaps this should be an Err
                TimePeriodContext::new(*period, blind_id.into(), netdir)
            })
            .collect::<Result<Vec<TimePeriodContext>, ReactorError>>()
    }

    /// Replace the old netdir with the new, returning the old.
    fn replace_netdir(&self, new_netdir: Arc<NetDir>) -> Arc<NetDir> {
        std::mem::replace(
            &mut self.inner.lock().expect("poisoned lock").netdir,
            new_netdir,
        )
    }

    /// Replace our view of the service config with `new_config` if `new_config` contains changes
    /// that would cause us to generate a new descriptor.
    fn replace_config_if_changed(&self, new_config: Arc<OnionServiceConfig>) -> bool {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let old_config = &mut inner.config;

        // The fields we're interested in haven't changed, so there's no need to update
        // `inner.config`.
        //
        // TODO HSS: maybe `Inner` should only contain the fields we're interested in instead of
        // the entire config.
        //
        // Alternatively, a less error-prone solution would be to introduce a separate
        // `DescriptorConfigView` as described in
        // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1603#note_2944902

        // TODO HSS: Temporarily disabled while we figure out how we want the client auth config to
        // work; see #1028
        /*
        if old_config.anonymity == new_config.anonymity
            && old_config.encrypt_descriptor == new_config.encrypt_descriptor
        {
            return false;
        }
        */

        let _old: Arc<OnionServiceConfig> = std::mem::replace(old_config, new_config);

        true
    }

    /// Read the intro points from `ipt_watcher`, and decide whether we're ready to start
    /// uploading.
    fn note_ipt_change(&self) -> PublishStatus {
        let inner = self.inner.lock().expect("poisoned lock");

        let mut ipts = self.ipt_watcher.borrow_for_publish();
        match ipts.deref_mut() {
            Some(ipts) => PublishStatus::UploadScheduled,
            None => PublishStatus::AwaitingIpts,
        }
    }

    /// Update our list of introduction points.
    #[allow(clippy::unnecessary_wraps)]
    #[allow(unreachable_code, unused_mut, clippy::diverging_sub_expression)] // TODO HSS remove
    async fn handle_ipt_change(
        &mut self,
        update: Option<Result<(), crate::FatalError>>,
    ) -> Result<(), ReactorError> {
        match update {
            Some(Ok(())) => {
                let should_upload = self.note_ipt_change();

                self.mark_all_dirty();
                self.update_publish_status(should_upload).await
            }
            Some(Err(_)) | None => Err(ReactorError::ShuttingDown),
        }
    }

    /// Update the `PublishStatus` of the reactor with `new_state`,
    /// unless the current state is `AwaitingIpts`.
    async fn update_publish_status(
        &mut self,
        new_state: PublishStatus,
    ) -> Result<(), ReactorError> {
        // Only update the state if we're not waiting for intro points.
        if self.status() != PublishStatus::AwaitingIpts {
            self.publish_status_tx
                .send(new_state)
                .await
                .map_err(|_: SendError<_>| internal!("failed to send upload notification?!"))?;
        }

        Ok(())
    }

    /// Use the new keys.
    async fn handle_new_keys(&self) -> Result<(), ReactorError> {
        todo!()
    }

    /// Update the descriptors based on the config change.
    async fn handle_svc_config_change(
        &mut self,
        config: Arc<OnionServiceConfig>,
    ) -> Result<(), ReactorError> {
        if self.replace_config_if_changed(config) {
            self.mark_all_dirty();

            // Schedule an upload, unless we're still waiting for IPTs.
            self.update_publish_status(PublishStatus::UploadScheduled)
                .await?;
        }

        Ok(())
    }

    /// Mark the descriptor dirty for all time periods.
    fn mark_all_dirty(&self) {
        self.inner
            .lock()
            .expect("poisoned lock")
            .time_periods
            .iter_mut()
            .for_each(|tp| tp.mark_all_dirty());
    }

    /// Try to upload our descriptor to the HsDirs that need it.
    ///
    /// If we've recently uploaded some descriptors, we return immediately and schedule the upload
    /// to happen N minutes from now.
    ///
    /// Any failed uploads are retried (TODO HSS: document the retry logic when we implement it, as
    /// well as in what cases this will return an error).
    //
    // TODO HSS: what is N?
    #[allow(unreachable_code)] // TODO HSS: remove
    #[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
    async fn upload_all(&mut self) -> Result<(), ReactorError> {
        let last_uploaded = self.inner.lock().expect("poisoned lock").last_uploaded;
        let now = self.imm.runtime.now();
        // Check if we should rate-limit this upload.
        if let Some(last_uploaded) = last_uploaded {
            let duration_since_upload = last_uploaded.duration_since(now);

            if duration_since_upload < UPLOAD_RATE_LIM_THRESHOLD {
                return self.schedule_pending_upload().await;
            }
        }

        let inner = self.inner.lock().expect("poisoned lock");

        let netdir = Arc::clone(&inner.netdir);

        let imm = Arc::clone(&self.imm);
        let hsid_key = self.hsid_key.clone();
        let upload_task_complete_tx = self.upload_task_complete_tx.clone();

        let upload_tasks = inner
            .time_periods
            .iter()
            .map(|period| {
                // Figure out which HsDirs we need to upload the descriptor to (some of them might already
                // have our latest descriptor, so we filter them out).
                let hs_dirs = period
                    .hs_dirs
                    .iter()
                    .filter_map(|(relay_id, status)| {
                        if *status == DescriptorStatus::Dirty {
                            Some(relay_id.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                let blind_id_kp = todo!();

                // We're about to generate a new version of the descriptor: increment the revision
                // counter.
                //
                // TODO HSS: to avoid fingerprinting, we should do what C-Tor does and make the
                // revision counter a timestamp encrypted using an OPE cipher
                let revision_counter = period.inc_revision_counter();
                // This scope exists because rng is not Send, so it needs to fall out of scope before we
                // await anything.
                let hsdesc = {
                    let mut rng = imm.mockable.thread_rng();

                    let mut ipt_set = self.ipt_watcher.borrow_for_publish();
                    let Some(mut ipt_set) = ipt_set.as_mut() else {
                        return Ok(());
                    };

                    let desc = build_sign(
                        inner.config,
                        hsid_key,
                        blind_id_kp,
                        ipt_set,
                        period.period,
                        revision_counter,
                        &mut rng,
                    )?;

                    let worst_case_end = todo!();
                    ipt_set
                        .note_publication_attempt(worst_case_end)
                        .map_err(|_| internal!("failed to note publication attempt"))?;

                    desc
                };

                let _handle: () = imm
                    .runtime
                    .spawn(async {
                        let hsdesc = VersionedDescriptor {
                            desc: hsdesc.clone(),
                            revision_counter,
                        };
                        if let Err(_e) = Self::upload_for_time_period(
                            hsdesc,
                            hs_dirs,
                            &netdir,
                            period.period,
                            imm,
                            upload_task_complete_tx,
                        )
                        .await
                        {
                            // TODO HSS
                        }
                    })
                    .map_err(|e| ReactorError::from_spawn("upload_for_time_period task", e))?;

                Ok::<_, ReactorError>(())
            })
            .collect::<Result<Vec<_>, ReactorError>>()?;

        Ok(())
    }

    /// Tell the "upload reminder" task to remind us to retry an upload that was rate-limited.
    async fn schedule_pending_upload(&mut self) -> Result<(), ReactorError> {
        if let Err(e) = self
            .rate_lim_upload_tx
            .as_mut()
            .ok_or(internal!(
                "channel not initialized (schedule_pending_upload called before run?!)"
            ))?
            .send(Some(self.imm.runtime.now() + UPLOAD_RATE_LIM_THRESHOLD))
            .await
        {
            // TODO HSS: return an error
            debug!("failed to schedule upload reattempt");
        }

        Ok(())
    }

    /// Upload the descriptor for the specified time period.
    ///
    /// Any failed uploads are retried (TODO HSS: document the retry logic when we implement it, as
    /// well as in what cases this will return an error).
    async fn upload_for_time_period(
        hsdesc: VersionedDescriptor,
        hs_dirs: Vec<RelayIds>,
        netdir: &Arc<NetDir>,
        time_period: TimePeriod,
        imm: Arc<Immutable<R, M>>,
        mut upload_task_complete_tx: Sender<TimePeriodUploadResult>,
    ) -> Result<(), ReactorError> {
        let VersionedDescriptor {
            desc,
            revision_counter,
        } = &hsdesc;

        let upload_results = futures::stream::iter(hs_dirs)
            .map(|relay_ids| {
                let netdir = netdir.clone();
                let imm = Arc::clone(&imm);

                async move {
                    let run_upload = || async {
                        let Some(hsdir) = netdir.by_ids(&relay_ids) else {
                            // This should never happen (all of our relay_ids are from the stored netdir).
                            return Err::<(), ReactorError>(
                                internal!(
                                    "tried to upload descriptor to relay not found in consensus?"
                                )
                                .into(),
                            );
                        };

                        Self::upload_descriptor_with_retries(
                            desc.clone(),
                            &netdir,
                            &hsdir,
                            Arc::clone(&imm),
                        )
                        .await
                    };

                    let upload_res = match run_upload().await {
                        Ok(()) => UploadStatus::Success,
                        Err(e) => {
                            let ed_id = relay_ids
                                .rsa_identity()
                                .map(|id| id.to_string())
                                .unwrap_or_else(|| "unknown".into());
                            let rsa_id = relay_ids
                                .rsa_identity()
                                .map(|id| id.to_string())
                                .unwrap_or_else(|| "unknown".into());

                            // TODO: extend warn_report to support key-value fields like warn!
                            warn_report!(
                                e,
                                "failed to upload descriptor for hsid={} (hsdir_id={}, hsdir_rsa_id={})",
                                imm.hsid, ed_id, rsa_id
                            );

                            UploadStatus::Failure
                        }
                    };

                    HsDirUploadStatus {
                        relay_ids,
                        upload_res,
                    }
                }
            })
            // This fails to compile unless the stream is boxed. See https://github.com/rust-lang/rust/issues/104382
            .boxed()
            .buffer_unordered(MAX_CONCURRENT_UPLOADS)
            .collect::<Vec<_>>()
            .await;

        let (succeeded, failed): (Vec<_>, Vec<_>) = upload_results
            .iter()
            .partition(|res| res.upload_res == UploadStatus::Success);

        trace!(hsid=%imm.hsid, "{}/{} descriptors were successfully uploaded", succeeded.len(), failed.len());

        if let Err(e) = upload_task_complete_tx
            .send(TimePeriodUploadResult {
                revision_counter: *revision_counter,
                time_period,
                hsdir_result: upload_results,
            })
            .await
        {
            return Err(internal!(
                "failed to notify reactor of upload completion (reactor shut down)"
            )
            .into());
        }

        Ok(())
    }

    /// Upload a descriptor to the specified HSDir.
    ///
    /// If an upload fails, this returns an `Err`. This function does not handle retries. It is up
    /// to the caller to retry on failure.
    async fn upload_descriptor(
        hsdesc: String,
        netdir: &Arc<NetDir>,
        hsdir: &Relay<'_>,
        imm: Arc<Immutable<R, M>>,
    ) -> Result<(), UploadError> {
        let request = HsDescUploadRequest::new(hsdesc);

        trace!(hsid=%imm.hsid, hsdir_id=%hsdir.id(), hsdir_rsa_id=%hsdir.rsa_id(), request=?request,
            "trying to upload descriptor. HTTP request:\n{:?}",
            request.make_request()
        );

        let circuit = imm
            .mockable
            .get_or_launch_specific(
                netdir,
                HsCircKind::SvcHsDir,
                OwnedCircTarget::from_circ_target(hsdir),
            )
            .await?;

        let mut stream = circuit
            .begin_dir_stream()
            .await
            .map_err(UploadError::Stream)?;

        let response = send_request(&imm.runtime, &request, &mut stream, None)
            .await
            .map_err(|dir_error| -> UploadError {
                match dir_error {
                    DirClientError::RequestFailed(e) => e.error.into(),
                    DirClientError::CircMgr(e) => into_internal!(
                        "tor-dirclient complains about circmgr going wrong but we gave it a stream"
                    )(e)
                    .into(),
                    e => into_internal!("unexpected error")(e).into(),
                }
            })?;

        trace!(
            hsid=%imm.hsid, hsdir_id=%hsdir.id(), hsdir_rsa_id=%hsdir.rsa_id(),
            "successfully uploaded descriptor"
        );

        Ok(())
    }

    /// Upload a descriptor to the specified HSDir, retrying if appropriate.
    ///
    /// TODO HSS: document the retry logic when we implement it.
    async fn upload_descriptor_with_retries(
        hsdesc: String,
        netdir: &Arc<NetDir>,
        hsdir: &Relay<'_>,
        imm: Arc<Immutable<R, M>>,
    ) -> Result<(), ReactorError> {
        use BackoffError as BE;

        /// The base delay to use for the backoff schedule.
        const BASE_DELAY_MSEC: u32 = 1000;

        let runner = {
            let schedule = PublisherBackoffSchedule {
                retry_delay: RetryDelay::from_msec(BASE_DELAY_MSEC),
                mockable: imm.mockable.clone(),
            };
            Runner::new(
                "upload a hidden service descriptor".into(),
                schedule,
                imm.runtime.clone(),
            )
        };

        let fallible_op = || async {
            Self::upload_descriptor(hsdesc.clone(), netdir, hsdir, Arc::clone(&imm)).await
        };

        let res = runner.run(fallible_op).await;

        let err = match res {
            Ok(res) => return Ok(res),
            Err(e) => e,
        };

        match err {
            BE::FatalError(e)
            | BE::MaxRetryCountExceeded(e)
            | BE::Timeout(e)
            | BE::ExplicitStop(e) => Err(ReactorError::PublishFailure(e)),
            BE::Spawn { .. } | BE::Bug(_) => Err(into_internal!(
                "internal error while attempting to publish descriptor"
            )(err)
            .into()),
        }
    }
}

/// Whether the reactor should initiate an upload.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
enum PublishStatus {
    /// We need to call upload_all.
    UploadScheduled,
    /// We are idle and waiting for external events.
    ///
    /// We have enough information to build the descriptor, but since we have already called
    /// upload_all to upload it to all relevant HSDirs, there is nothing for us to do right nbow.
    Idle,
    /// We are waiting for the IPT manager to establish some introduction points.
    ///
    /// No descriptors will be published until the `PublishStatus` of the reactor is changed to
    /// `UploadScheduled`.
    #[default]
    AwaitingIpts,
}

/// The backoff schedule for the task that publishes descriptors.
#[derive(Clone, Debug)]
struct PublisherBackoffSchedule<M: Mockable> {
    /// The delays
    retry_delay: RetryDelay,
    /// The mockable reactor state, needed for obtaining an rng.
    mockable: M,
}

impl<M: Mockable> BackoffSchedule for PublisherBackoffSchedule<M> {
    fn max_retries(&self) -> Option<usize> {
        None
    }

    fn timeout(&self) -> Option<Duration> {
        // TODO HSS: pick a less arbitrary timeout
        Some(Duration::from_secs(30))
    }

    fn next_delay<E: RetriableError>(&mut self, _error: &E) -> Option<Duration> {
        Some(self.retry_delay.next_delay(&mut self.mockable.thread_rng()))
    }
}

impl RetriableError for UploadError {
    fn should_retry(&self) -> bool {
        match self {
            UploadError::Request(_) | UploadError::Circuit(_) | UploadError::Stream(_) => true,
            UploadError::Bug(_) => false,
        }
    }
}

/// The outcome of uploading a descriptor to the HSDirs from a particular time period.
#[derive(Debug, Clone)]
struct TimePeriodUploadResult {
    /// The revision counter of the descriptor we tried to upload.
    revision_counter: RevisionCounter,
    /// The time period.
    time_period: TimePeriod,
    /// The upload results.
    hsdir_result: Vec<HsDirUploadStatus>,
}

/// The outcome of uploading a descriptor to a particular HsDir.
#[derive(Clone, Debug, PartialEq)]
struct HsDirUploadStatus {
    /// The identity of the HsDir we attempted to upload the descriptor to.
    relay_ids: RelayIds,
    /// The outcome of this attempt.
    upload_res: UploadStatus,
}

/// The outcome of uploading a descriptor.
#[derive(Copy, Clone, Debug, PartialEq)]
enum UploadStatus {
    /// The descriptor upload succeeded.
    Success,
    /// The descriptor upload failed.
    Failure,
}

impl<T, E> From<Result<T, E>> for UploadStatus {
    fn from(res: Result<T, E>) -> Self {
        if res.is_ok() {
            Self::Success
        } else {
            Self::Failure
        }
    }
}
