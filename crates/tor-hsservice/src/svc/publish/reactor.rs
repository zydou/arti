//! The onion service publisher reactor.
//!
//! TODO HSS: write the docs

use std::fmt::Debug;
use std::iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::channel::mpsc::{self, Receiver, Sender};
use futures::lock::Mutex;
use futures::task::SpawnExt;
use futures::{select_biased, FutureExt, SinkExt, StreamExt};
use postage::watch;
use tor_hscrypto::RevisionCounter;
use tracing::{debug, error, trace};

use tor_bytes::EncodeError;
use tor_circmgr::hspool::{HsCircKind, HsCircPool};
use tor_dirclient::request::HsDescUploadRequest;
use tor_dirclient::request::Requestable;
use tor_dirclient::{send_request, Error as DirClientError, RequestError};
use tor_error::{internal, into_internal};
use tor_hscrypto::pk::{HsBlindId, HsId, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_linkspec::{CircTarget, HasRelayIds, OwnedCircTarget, RelayIds};
use tor_netdir::{NetDir, NetDirProvider, Relay, Timeliness};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::Runtime;

use crate::config::OnionServiceConfig;
use crate::ipt_set::{IptSet, IptsPublisherView, PublishIptSet};
use crate::svc::netdir::{wait_for_netdir, NetdirProviderShutdown};
use crate::svc::publish::descriptor::{DescriptorBuilder, DescriptorStatus, VersionedDescriptor};

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
pub(super) struct Reactor<R: Runtime, M: Mockable<R>> {
    /// The runtime.
    runtime: R,
    /// The service for which we're publishing descriptors.
    hsid: HsId,
    /// The public key of the service.
    hsid_key: HsIdKey,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// Mockable state.
    ///
    /// This is used for launching circuits and for obtaining random number generators.
    mockable: M,
    /// The mutable inner state,
    inner: Arc<Mutex<Inner>>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<OnionServiceConfig>,
    /// A channel for the telling the upload reminder task when to remind us we need to upload
    /// some descriptors.
    ///
    /// This is initialized in [`Reactor::run`].
    pending_upload_tx: Option<Sender<Duration>>,
    /// A channel for sending upload completion notifications.
    ///
    /// This channel is polled in the main loop of the reactor.
    upload_task_complete_rx: Receiver<TimePeriodUploadResult>,
    /// A channel for receiving upload completion notifications.
    ///
    /// A copy of this sender is handed to each upload task.
    upload_task_complete_tx: Sender<TimePeriodUploadResult>,
}

/// Mockable state for the descriptor publisher reactor.
///
/// This enables us to mock parts of the [`Reactor`] for testing purposes.
#[async_trait]
pub(super) trait Mockable<R>: Clone + Send + Sync + Sized + 'static {
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
impl<R: Runtime> Mockable<R> for ReactorState<R> {
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
    /// The descriptor to upload.
    ///
    /// Note: this may be partially built. If incomplete, [`DescriptorBuilder::build`] will return
    /// an error.
    ///
    /// This field is only expected to be incomplete on startup. Once the introduction points are
    /// established, we should have enough information to generate and upload the descriptor.
    descriptor: DescriptorBuilder,
    /// The onion service config.
    config: OnionServiceConfig,
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
#[must_use = "If you don't call run() on the reactor, it won't publish any descriptors."]
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(super) enum ReactorError {
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

    /// An error that has occurred after we have contacted a directory cache and made a circuit to it.
    #[error("descriptor upload request failed")]
    UploadRequestFailed(#[from] RequestError),

    /// Failed to establish circuit to hidden service directory
    #[error("circuit failed")]
    Circuit(#[from] tor_circmgr::Error),

    /// Failed to establish stream to hidden service directory
    #[error("stream failed")]
    Stream(#[source] tor_proto::Error),

    /// A fatal error that caused the reactor to shut down.
    //
    // TODO HSS: add more context to this error?
    #[error("publisher reactor is shutting down")]
    ShuttingDown,

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl<R: Runtime, M: Mockable<R>> Reactor<R, M> {
    /// Create a new `Reactor`.
    pub(super) async fn new(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: M,
        config: OnionServiceConfig,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<OnionServiceConfig>,
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

        let inner = Inner {
            descriptor: DescriptorBuilder::default(),
            time_periods,
            config,
            netdir,
            last_uploaded: None,
        };

        Ok(Self {
            runtime,
            inner: Arc::new(Mutex::new(inner)),
            hsid,
            hsid_key,
            dir_provider,
            mockable,
            ipt_watcher,
            config_rx,
            pending_upload_tx: None,
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
        let (pending_upload_tx, mut pending_upload_rx) = mpsc::channel(1);
        let (mut schedule_upload_tx, mut schedule_upload_rx) = mpsc::channel(1);

        self.pending_upload_tx = Some(pending_upload_tx);

        let rt = self.runtime.clone();
        // Spawn the task that will remind us to retry any rate-limited uploads.
        let _ = self.runtime.spawn(async move {
            // The sender tells us how long to wait until to schedule the upload
            while let Some(duration) = pending_upload_rx.next().await {
                rt.sleep(duration).await;

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
    #[allow(unreachable_code)] // TODO HSS: remove
    #[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
    async fn run_once(
        &mut self,
        schedule_upload_rx: &mut Receiver<()>,
    ) -> Result<(), ReactorError> {
        let mut netdir_events = self.dir_provider.events();

        select_biased! {
            res = self.upload_task_complete_rx.next().fuse() => {
                let upload_res = res.ok_or(ReactorError::ShuttingDown)?;

                self.handle_upload_results(upload_res).await;
            }
            netidr_event = netdir_events.next().fuse() => {
                // The consensus changed. Grab a new NetDir.
                let netdir = self.dir_provider.netdir(Timeliness::Timely)?;

                self.handle_consensus_change(netdir).await?;
            }
            ipts = self.ipt_watcher.await_update().fuse() => {
                if let Ok(()) = ipts.ok_or(ReactorError::ShuttingDown)? {
                    // TODO HSS: add more context to the error
                    internal!("failed to receive IPT update");
                }
                // TODO HSS: try to read IPTs from shared state (see #1023)
                let ipts = todo!();
                self.handle_new_intro_points(ipts).await?;
            },
            config = self.config_rx.next().fuse() => {
                let config = config.ok_or(ReactorError::ShuttingDown)?;
                self.handle_svc_config_change(config).await?;
            },
            res = schedule_upload_rx.next().fuse() => {
                let _: () = res.ok_or(ReactorError::ShuttingDown)?;

                // Time to reattempt a previously rate-limited upload
                self.upload_all().await?;
            }
        }

        Ok(())
    }

    /// Handle a batch of upload outcomes,
    /// possibly updating the status of the descriptor for the corresponding HSDirs.
    async fn handle_upload_results(&self, results: TimePeriodUploadResult) {
        let mut inner = self.inner.lock().await;
        inner.last_uploaded = Some(self.runtime.now());

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
    async fn handle_consensus_change(&self, netdir: Arc<NetDir>) -> Result<(), ReactorError> {
        let _old: Arc<NetDir> = self.replace_netdir(netdir).await;

        self.recompute_hs_dirs().await?;

        // TODO HSS: upload the descriptors.

        Ok(())
    }

    /// Recompute the HsDirs for all relevant time periods.
    async fn recompute_hs_dirs(&self) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().await;
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
    async fn replace_netdir(&self, new_netdir: Arc<NetDir>) -> Arc<NetDir> {
        std::mem::replace(&mut self.inner.lock().await.netdir, new_netdir)
    }

    /// Update our list of introduction points.
    #[allow(clippy::unnecessary_wraps)]
    #[allow(unreachable_code, unused_mut, clippy::diverging_sub_expression)] // TODO HSS remove
    async fn handle_new_intro_points(&self, ipts: PublishIptSet) -> Result<(), ReactorError> {
        let Some(ipts) = ipts else {
            todo!() // TODO HSS stop publishing when we get None for ipts
        };

        let mut inner = self.inner.lock().await;
        #[allow(unused_variables)] // TODO HSS remove
        let IptSet { ipts, lifetime } = ipts;

        let ipts = todo!(); // TODO HSSS something something last_publish etc.
                            // (this current code is entirely wrong, see #1023)

        inner.descriptor.ipts(ipts);

        // TODO HSS: upload the descriptors.

        Ok(())
    }

    /// Use the new keys.
    async fn handle_new_keys(&self) -> Result<(), ReactorError> {
        todo!()
    }

    /// Update the descriptors based on the config change.
    async fn handle_svc_config_change(
        &self,
        _config: OnionServiceConfig,
    ) -> Result<(), ReactorError> {
        // TODO HSS: check if the config changes affect our descriptor. If they do, update its
        // state and mark it as dirty for all hsdirs
        todo!();
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
        let last_uploaded = self.inner.lock().await.last_uploaded;
        let now = self.runtime.now();
        // Check if we should rate-limit this upload.
        if let Some(last_uploaded) = last_uploaded {
            let duration_since_upload = last_uploaded.duration_since(now);

            if duration_since_upload < UPLOAD_RATE_LIM_THRESHOLD {
                return self.schedule_pending_upload().await;
            }
        }

        let inner = self.inner.lock().await;

        // Check we have enough information to generate the descriptor before proceeding.
        let hsdesc = match inner.descriptor.build() {
            Ok(desc) => desc,
            Err(e) => {
                // TODO HSS:
                // This can only happen if, for some reason, we decide to call the upload function
                // before receiving our first NewIpts event (the intro points are the only piece of
                // information we need from the "outside", AFAICT).
                //
                // I think this should never happen: we shouldn't start an upload unless we have
                // enough information to build the descriptor (if we do get here, it's a bug).
                //
                // Instead of skipping the upload, we should be returning an internal! error.
                trace!(hsid=%self.hsid, "not enough information to build descriptor, skipping upload: {e}");
                return Ok(());
            }
        };

        let netdir = Arc::clone(&inner.netdir);

        let runtime = self.runtime.clone();
        let mockable = self.mockable.clone();
        let hsid_key = self.hsid_key.clone();
        let upload_task_complete_tx = self.upload_task_complete_tx.clone();
        let hsid = self.hsid;

        let upload_tasks = inner.time_periods.iter().map(move |period| {
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
                let mut rng = mockable.thread_rng();
                hsdesc.build_sign(
                    hsid_key,
                    blind_id_kp,
                    period.period,
                    revision_counter,
                    &mut rng,
                )?
            };

            let handle = runtime.spawn(async {
                let hsdesc = VersionedDescriptor {
                    desc: hsdesc.clone(),
                    revision_counter,
                };
                if let Err(_e) = Self::upload_for_time_period(
                    hsdesc,
                    hs_dirs,
                    &netdir,
                    period.period,
                    hsid,
                    upload_task_complete_tx,
                )
                .await
                {
                    // TODO HSS
                }
            });

            Ok::<_, ReactorError>(handle)
        });

        Ok(())
    }

    /// Tell the "upload reminder" task to remind us about a pending upload.
    async fn schedule_pending_upload(&mut self) -> Result<(), ReactorError> {
        if let Err(e) = self
            .pending_upload_tx
            .as_mut()
            .ok_or(internal!(
                "channel not initialized (schedule_pending_upload called before run?!)"
            ))?
            .send(UPLOAD_RATE_LIM_THRESHOLD)
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
        hsid: HsId,
        mut upload_task_complete_tx: Sender<TimePeriodUploadResult>,
    ) -> Result<(), ReactorError> {
        let VersionedDescriptor {
            desc,
            revision_counter,
        } = &hsdesc;

        let upload_results = futures::stream::iter(hs_dirs)
            .map(|relay_ids| {
                let netdir = netdir.clone();

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

                        Self::upload_descriptor_with_retries(desc.clone(), &netdir, &hsdir).await
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

                            error!(
                                hsid=%hsid, hsdir_id=%ed_id, hsdir_rsa_id=%rsa_id,
                                "failed to upload descriptor: {e}"
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

        trace!(hsid=%hsid, "{}/{} descriptors were successfully uploaded", succeeded.len(), failed.len());

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
        &self,
        hsdesc: String,
        netdir: &Arc<NetDir>,
        hsdir: &Relay<'_>,
    ) -> Result<(), ReactorError> {
        let request = HsDescUploadRequest::new(hsdesc);

        trace!(hsid=%self.hsid, hsdir_id=%hsdir.id(), hsdir_rsa_id=%hsdir.rsa_id(), request=?request,
            "trying to upload descriptor. HTTP request:\n{:?}",
            request.make_request()
        );

        let circuit = self
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
            .map_err(ReactorError::Stream)?;

        let response = send_request(&self.runtime, &request, &mut stream, None)
            .await
            .map_err(|dir_error| -> ReactorError {
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
            hsid=%self.hsid, hsdir_id=%hsdir.id(), hsdir_rsa_id=%hsdir.rsa_id(),
            "successfully uploaded descriptor"
        );

        Ok(())
    }

    /// Upload a descriptor to the specified HSDir, retrying if appropriate.
    ///
    /// TODO HSS: document the retry logic when we implement it.
    async fn upload_descriptor_with_retries(
        _hsdesc: String,
        _netdir: &Arc<NetDir>,
        _hsdir: &Relay<'_>,
    ) -> Result<(), ReactorError> {
        todo!();
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
