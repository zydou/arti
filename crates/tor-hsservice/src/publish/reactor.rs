//! The onion service publisher reactor.
//!
//! TODO (#1216): write the docs
//!
//! With respect to [`OnionServiceStatus`] reporting,
//! the following state transitions are possible:
//!
//!
//! ```ignore
//!
//!                 update_publish_status(UploadScheduled|AwaitingIpts|RateLimited) +---------------+
//!                +--------------------------------------------------------------->| Bootstrapping |
//!                |                                                                +---------------+
//! +----------+   | update_publish_status(Idle)        +---------+                         |
//! | Shutdown |-- +----------------------------------->| Running |----+                    |
//! +----------+   |                                    +---------+    |                    |
//!                |                                                   |                    |
//!                |                                                   |                    |
//!                | run_once() returns an error  +--------+           |                    |
//!                +----------------------------->| Broken |<----------+--------------------+
//!                                               +--------+ run_once() returns an error
//! ```
//!
//! Ideally, the publisher should also set the
//! [`OnionServiceStatus`] to `Recovering` whenever a transient
//! upload error occurs, but this is currently not possible:
//!
//!   * making the upload tasks set the status to `Recovering` (on failure) and `Running` (on
//!     success) wouldn't work, because the upload tasks run in parallel (they would race with each
//!     other, and the final status (`Recovering`/`Running`) would be the status of the last upload
//!     task, rather than the real status of the publisher
//!   * making the upload task set the status to `Recovering` on upload failure, and letting
//!     `upload_publish_status` reset it back to `Running also would not work:
//!     `upload_publish_status` sets the status back to `Running` when the publisher enters its
//!     `Idle` state, regardless of the status of its upload tasks
//!
//! TODO: Indeed, setting the status to `Recovering` _anywhere_ would not work, because
//! `upload_publish_status` will just overwrite it. We would need to introduce some new
//! `PublishStatus` variant (currently, the publisher only has 3 states, `Idle`, `UploadScheduled`,
//! `AwaitingIpts`), for the `Recovering` (retrying a failed upload) and `Broken` (the upload
//! failed and we've given up) states. However, adding these 2 new states is non-trivial:
//!
//!   * how do we define "failure"? Is it the failure to upload to a single HsDir, or the failure
//!     to upload to **any** HsDirs?
//!   * what should make the publisher transition out of the `Broken`/`Recovering` states? While
//!     `handle_upload_results` can see the upload results for a batch of HsDirs (corresponding to
//!     a time period), the publisher doesn't do any sort of bookkeeping to know if a previously
//!     failed HsDir upload succeeded in a later upload "batch"
//!
//! For the time being, the publisher never sets the status to `Recovering`, and uses the `Broken`
//! status for reporting fatal errors (crashes).

use tor_config::file_watcher::{
    self, Event as FileEvent, FileEventReceiver, FileEventSender, FileWatcher, FileWatcherBuilder,
};
use tor_netdir::DirEvent;

use crate::config::restricted_discovery::{
    DirectoryKeyProviderList, RestrictedDiscoveryConfig, RestrictedDiscoveryKeys,
};
use crate::config::OnionServiceConfigPublisherView;

use super::*;

// TODO-CLIENT-AUTH: perhaps we should add a separate CONFIG_CHANGE_REPUBLISH_DEBOUNCE_INTERVAL
// for rate-limiting the publish jobs triggered by a change in the config?
//
// Currently the descriptor publish tasks triggered by changes in the config
// are rate-limited via the usual rate limiting mechanism
// (which rate-limits the uploads for 1m).
//
// I think this is OK for now, but we might need to rethink this if it becomes problematic
// (for example, we might want an even longer rate-limit, or to reset any existing rate-limits
// each time the config is modified).

/// The upload rate-limiting threshold.
///
/// Before initiating an upload, the reactor checks if the last upload was at least
/// `UPLOAD_RATE_LIM_THRESHOLD` seconds ago. If so, it uploads the descriptor to all HsDirs that
/// need it. If not, it schedules the upload to happen `UPLOAD_RATE_LIM_THRESHOLD` seconds from the
/// current time.
//
// TODO: We may someday need to tune this value; it was chosen more or less arbitrarily.
const UPLOAD_RATE_LIM_THRESHOLD: Duration = Duration::from_secs(60);

/// The maximum number of concurrent upload tasks per time period.
//
// TODO: this value was arbitrarily chosen and may not be optimal.  For now, it
// will have no effect, since the current number of replicas is far less than
// this value.
//
// The uploads for all TPs happen in parallel.  As a result, the actual limit for the maximum
// number of concurrent upload tasks is multiplied by a number which depends on the TP parameters
// (currently 2, which means the concurrency limit will, in fact, be 32).
//
// We should try to decouple this value from the TP parameters.
const MAX_CONCURRENT_UPLOADS: usize = 16;

/// The maximum time allowed for uploading a descriptor to a single HSDir,
/// across all attempts.
pub(crate) const OVERALL_UPLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// A reactor for the HsDir [`Publisher`]
///
/// The entrypoint is [`Reactor::run`].
#[must_use = "If you don't call run() on the reactor, it won't publish any descriptors."]
pub(super) struct Reactor<R: Runtime, M: Mockable> {
    /// The immutable, shared inner state.
    imm: Arc<Immutable<R, M>>,
    /// A source for new network directories that we use to determine
    /// our HsDirs.
    dir_provider: Arc<dyn NetDirProvider>,
    /// The mutable inner state,
    inner: Arc<Mutex<Inner>>,
    /// A channel for receiving IPT change notifications.
    ipt_watcher: IptsPublisherView,
    /// A channel for receiving onion service config change notifications.
    config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
    /// A channel for receiving restricted discovery key_dirs change notifications.
    key_dirs_rx: FileEventReceiver,
    /// A channel for sending restricted discovery key_dirs change notifications.
    ///
    /// A copy of this sender is handed out to every `FileWatcher` created.
    key_dirs_tx: FileEventSender,
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
    /// A channel for sending upload completion notifications.
    ///
    /// This channel is polled in the main loop of the reactor.
    upload_task_complete_rx: mpsc::Receiver<TimePeriodUploadResult>,
    /// A channel for receiving upload completion notifications.
    ///
    /// A copy of this sender is handed to each upload task.
    upload_task_complete_tx: mpsc::Sender<TimePeriodUploadResult>,
    /// A sender for notifying any pending upload tasks that the reactor is shutting down.
    ///
    /// Receivers can use this channel to find out when reactor is dropped.
    ///
    /// This is currently only used in [`upload_for_time_period`](Reactor::upload_for_time_period).
    /// Any future background tasks can also use this channel to detect if the reactor is dropped.
    ///
    /// Closing this channel will cause any pending upload tasks to be dropped.
    shutdown_tx: broadcast::Sender<Void>,
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
    nickname: HsNickname,
    /// The key manager,
    keymgr: Arc<KeyMgr>,
    /// The restricted discovery authorized clients.
    ///
    /// `None`, unless the service is running in restricted discovery mode.
    authorized_clients: Arc<Mutex<Option<RestrictedDiscoveryKeys>>>,
    /// A sender for updating the status of the onion service.
    status_tx: PublisherStatusSender,
}

impl<R: Runtime, M: Mockable> Immutable<R, M> {
    /// Create an [`AesOpeKey`] for generating revision counters for the descriptors associated
    /// with the specified [`TimePeriod`].
    ///
    /// If the onion service is not running in offline mode, the key of the returned `AesOpeKey` is
    /// the private part of the blinded identity key. Otherwise, the key is the private part of the
    /// descriptor signing key.
    ///
    /// Returns an error if the service is running in offline mode and the descriptor signing
    /// keypair of the specified `period` is not available.
    //
    // TODO (#1194): we don't support "offline" mode (yet), so this always returns an AesOpeKey
    // built from the blinded id key
    fn create_ope_key(&self, period: TimePeriod) -> Result<AesOpeKey, FatalError> {
        let ope_key = match read_blind_id_keypair(&self.keymgr, &self.nickname, period)? {
            Some(key) => {
                let key: ed25519::ExpandedKeypair = key.into();
                key.to_secret_key_bytes()[0..32]
                    .try_into()
                    .expect("Wrong length on slice")
            }
            None => {
                // TODO (#1194): we don't support externally provisioned keys (yet), so this branch
                // is unreachable (for now).
                let desc_sign_key_spec =
                    DescSigningKeypairSpecifier::new(self.nickname.clone(), period);
                let key: ed25519::Keypair = self
                    .keymgr
                    .get::<HsDescSigningKeypair>(&desc_sign_key_spec)?
                    // TODO (#1194): internal! is not the right type for this error (we need an
                    // error type for the case where a hidden service running in offline mode has
                    // run out of its pre-previsioned keys).
                    //
                    // This will be addressed when we add support for offline hs_id mode
                    .ok_or_else(|| internal!("identity keys are offline, but descriptor signing key is unavailable?!"))?
                    .into();
                key.to_bytes()
            }
        };

        Ok(AesOpeKey::from_secret(&ope_key))
    }

    /// Generate a revision counter for a descriptor associated with the specified
    /// [`TimePeriod`].
    ///
    /// Returns a revision counter generated according to the [encrypted time in period] scheme.
    ///
    /// [encrypted time in period]: https://spec.torproject.org/rend-spec/revision-counter-mgt.html#encrypted-time
    fn generate_revision_counter(
        &self,
        params: &HsDirParams,
        now: SystemTime,
    ) -> Result<RevisionCounter, FatalError> {
        // TODO: in the future, we might want to compute ope_key once per time period (as oppposed
        // to each time we generate a new descriptor), for performance reasons.
        let ope_key = self.create_ope_key(params.time_period())?;

        // TODO: perhaps this should be moved to a new HsDirParams::offset_within_sr() function
        let srv_start = params.start_of_shard_rand_period();
        let offset = params.offset_within_srv_period(now).ok_or_else(|| {
            internal!(
                "current wallclock time not within SRV range?! (now={:?}, SRV_start={:?})",
                now,
                srv_start
            )
        })?;
        let rev = ope_key.encrypt(offset);

        Ok(RevisionCounter::from(rev))
    }
}

/// Mockable state for the descriptor publisher reactor.
///
/// This enables us to mock parts of the [`Reactor`] for testing purposes.
#[async_trait]
pub(crate) trait Mockable: Clone + Send + Sync + Sized + 'static {
    /// The type of random number generator.
    type Rng: rand::Rng + rand::CryptoRng;

    /// The type of client circuit.
    type ClientCirc: MockableClientCirc;

    /// Return a random number generator.
    fn thread_rng(&self) -> Self::Rng;

    /// Create a circuit of the specified `kind` to `target`.
    async fn get_or_launch_specific<T>(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: T,
    ) -> Result<Arc<Self::ClientCirc>, tor_circmgr::Error>
    where
        T: CircTarget + Send + Sync;

    /// Return an estimate-based value for how long we should allow a single
    /// directory upload operation to complete.
    ///
    /// Includes circuit construction, stream opening, upload, and waiting for a
    /// response.
    fn estimate_upload_timeout(&self) -> Duration;
}

/// Mockable client circuit
#[async_trait]
pub(crate) trait MockableClientCirc: Send + Sync {
    /// The data stream type.
    type DataStream: AsyncRead + AsyncWrite + Send + Unpin;

    /// Start a new stream to the last relay in the circuit, using
    /// a BEGIN_DIR cell.
    async fn begin_dir_stream(self: Arc<Self>) -> Result<Self::DataStream, tor_proto::Error>;
}

#[async_trait]
impl MockableClientCirc for ClientCirc {
    type DataStream = tor_proto::stream::DataStream;

    async fn begin_dir_stream(self: Arc<Self>) -> Result<Self::DataStream, tor_proto::Error> {
        ClientCirc::begin_dir_stream(self).await
    }
}

/// The real version of the mockable state of the reactor.
#[derive(Clone, From, Into)]
pub(crate) struct Real<R: Runtime>(Arc<HsCircPool<R>>);

#[async_trait]
impl<R: Runtime> Mockable for Real<R> {
    type Rng = rand::rngs::ThreadRng;
    type ClientCirc = ClientCirc;

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

    fn estimate_upload_timeout(&self) -> Duration {
        use tor_circmgr::timeouts::Action;
        let est_build = self.0.estimate_timeout(&Action::BuildCircuit { length: 4 });
        let est_roundtrip = self.0.estimate_timeout(&Action::RoundTrip { length: 4 });
        // We assume that in the worst case we'll have to wait for an entire
        // circuit construction and two round-trips to the hsdir.
        let est_total = est_build + est_roundtrip * 2;
        // We always allow _at least_ this much time, in case our estimate is
        // ridiculously low.
        let min_timeout = Duration::from_secs(30);
        max(est_total, min_timeout)
    }
}

/// The mutable state of a [`Reactor`].
struct Inner {
    /// The onion service config.
    config: Arc<OnionServiceConfigPublisherView>,
    /// Watcher for key_dirs.
    ///
    /// Set to `None` if the reactor is not running, or if `watch_configuration` is false.
    ///
    /// The watcher is recreated whenever the `restricted_discovery.key_dirs` change.
    file_watcher: Option<FileWatcher>,
    /// The relevant time periods.
    ///
    /// This includes the current time period, as well as any other time periods we need to be
    /// publishing descriptors for.
    ///
    /// This is empty until we fetch our first netdir in [`Reactor::run`].
    time_periods: Vec<TimePeriodContext>,
    /// Our most up to date netdir.
    ///
    /// This is initialized in [`Reactor::run`].
    netdir: Option<Arc<NetDir>>,
    /// The timestamp of our last upload.
    ///
    /// This is the time when the last update was _initiated_ (rather than completed), to prevent
    /// the publisher from spawning multiple upload tasks at once in response to multiple external
    /// events happening in quick succession, such as the IPT manager sending multiple IPT change
    /// notifications in a short time frame (#1142), or an IPT change notification that's
    /// immediately followed by a consensus change. Starting two upload tasks at once is not only
    /// inefficient, but it also causes the publisher to generate two different descriptors with
    /// the same revision counter (the revision counter is derived from the current timestamp),
    /// which ultimately causes the slower upload task to fail (see #1142).
    ///
    /// Note: This is only used for deciding when to reschedule a rate-limited upload. It is _not_
    /// used for retrying failed uploads (these are handled internally by
    /// [`Reactor::upload_descriptor_with_retries`]).
    last_uploaded: Option<Instant>,
    /// A max-heap containing the time periods for which we need to reupload the descriptor.
    // TODO: we are currently reuploading more than nececessary.
    // Ideally, this shouldn't contain contain duplicate TimePeriods,
    // because we only need to retain the latest reupload time for each time period.
    //
    // Currently, if, for some reason, we upload the descriptor multiple times for the same TP,
    // we will end up with multiple ReuploadTimer entries for that TP,
    // each of which will (eventually) result in a reupload.
    //
    // TODO: maybe this should just be a HashMap<TimePeriod, Instant>
    //
    // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1971#note_2994950
    reupload_timers: BinaryHeap<ReuploadTimer>,
}

/// The part of the reactor state that changes with every time period.
struct TimePeriodContext {
    /// The HsDir params.
    params: HsDirParams,
    /// The HsDirs to use in this time period.
    ///
    // We keep a list of `RelayIds` because we can't store a `Relay<'_>` inside the reactor
    // (the lifetime of a relay is tied to the lifetime of its corresponding `NetDir`. To
    // store `Relay<'_>`s in the reactor, we'd need a way of atomically swapping out both the
    // `NetDir` and the cached relays, and to convince Rust what we're doing is sound)
    hs_dirs: Vec<(RelayIds, DescriptorStatus)>,
    /// The revision counter of the last successful upload, if any.
    last_successful: Option<RevisionCounter>,
}

impl TimePeriodContext {
    /// Create a new `TimePeriodContext`.
    ///
    /// Any of the specified `old_hsdirs` also present in the new list of HsDirs
    /// (returned by `NetDir::hs_dirs_upload`) will have their `DescriptorStatus` preserved.
    fn new<'r>(
        params: HsDirParams,
        blind_id: HsBlindId,
        netdir: &Arc<NetDir>,
        old_hsdirs: impl Iterator<Item = &'r (RelayIds, DescriptorStatus)>,
    ) -> Result<Self, FatalError> {
        let period = params.time_period();
        Ok(Self {
            params,
            hs_dirs: Self::compute_hsdirs(period, blind_id, netdir, old_hsdirs)?,
            last_successful: None,
        })
    }

    /// Recompute the HsDirs for this time period.
    fn compute_hsdirs<'r>(
        period: TimePeriod,
        blind_id: HsBlindId,
        netdir: &Arc<NetDir>,
        mut old_hsdirs: impl Iterator<Item = &'r (RelayIds, DescriptorStatus)>,
    ) -> Result<Vec<(RelayIds, DescriptorStatus)>, FatalError> {
        let hs_dirs = netdir.hs_dirs_upload(blind_id, period)?;

        Ok(hs_dirs
            .map(|hs_dir| {
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
}

/// An error that occurs while trying to upload a descriptor.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UploadError {
    /// An error that has occurred after we have contacted a directory cache and made a circuit to it.
    #[error("descriptor upload request failed: {}", _0.error)]
    Request(#[from] RequestFailedError),

    /// Failed to establish circuit to hidden service directory
    #[error("could not build circuit to HsDir")]
    Circuit(#[from] tor_circmgr::Error),

    /// Failed to establish stream to hidden service directory
    #[error("failed to establish directory stream to HsDir")]
    Stream(#[source] tor_proto::Error),

    /// A descriptor upload timed out before it could complete.
    #[error("descriptor publication timed out")]
    Timeout,

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}
define_asref_dyn_std_error!(UploadError);

impl<R: Runtime, M: Mockable> Reactor<R, M> {
    /// Create a new `Reactor`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        runtime: R,
        nickname: HsNickname,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: M,
        config: &OnionServiceConfig,
        ipt_watcher: IptsPublisherView,
        config_rx: watch::Receiver<Arc<OnionServiceConfig>>,
        status_tx: PublisherStatusSender,
        keymgr: Arc<KeyMgr>,
    ) -> Self {
        /// The maximum size of the upload completion notifier channel.
        ///
        /// The channel we use this for is a futures::mpsc channel, which has a capacity of
        /// `UPLOAD_CHAN_BUF_SIZE + num-senders`. We don't need the buffer size to be non-zero, as
        /// each sender will send exactly one message.
        const UPLOAD_CHAN_BUF_SIZE: usize = 0;

        let (upload_task_complete_tx, upload_task_complete_rx) =
            mpsc::channel(UPLOAD_CHAN_BUF_SIZE);

        let (publish_status_tx, publish_status_rx) = watch::channel();
        // Setting the buffer size to zero here is OK,
        // since we never actually send anything on this channel.
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(0);

        let authorized_clients = Self::read_authorized_clients(&config.restricted_discovery);

        // Create a channel for watching for changes in the configured
        // restricted_discovery.key_dirs.
        let (key_dirs_tx, key_dirs_rx) = file_watcher::channel();

        let imm = Immutable {
            runtime,
            mockable,
            nickname,
            keymgr,
            status_tx,
            authorized_clients: Arc::new(Mutex::new(authorized_clients)),
        };

        let inner = Inner {
            time_periods: vec![],
            config: Arc::new(config.into()),
            file_watcher: None,
            netdir: None,
            last_uploaded: None,
            reupload_timers: Default::default(),
        };

        Self {
            imm: Arc::new(imm),
            inner: Arc::new(Mutex::new(inner)),
            dir_provider,
            ipt_watcher,
            config_rx,
            key_dirs_rx,
            key_dirs_tx,
            publish_status_rx,
            publish_status_tx,
            upload_task_complete_rx,
            upload_task_complete_tx,
            shutdown_tx,
        }
    }

    /// Start the reactor.
    ///
    /// Under normal circumstances, this function runs indefinitely.
    ///
    /// Note: this also spawns the "reminder task" that we use to reschedule uploads whenever an
    /// upload fails or is rate-limited.
    pub(super) async fn run(mut self) -> Result<(), FatalError> {
        debug!(nickname=%self.imm.nickname, "starting descriptor publisher reactor");

        {
            let netdir = wait_for_netdir(self.dir_provider.as_ref(), Timeliness::Timely).await?;
            let time_periods = self.compute_time_periods(&netdir, &[])?;

            let mut inner = self.inner.lock().expect("poisoned lock");

            inner.netdir = Some(netdir);
            inner.time_periods = time_periods;
        }

        // Create the initial key_dirs watcher.
        self.update_file_watcher();

        loop {
            match self.run_once().await {
                Ok(ShutdownStatus::Continue) => continue,
                Ok(ShutdownStatus::Terminate) => {
                    debug!(nickname=%self.imm.nickname, "descriptor publisher is shutting down!");

                    self.imm.status_tx.send_shutdown();
                    return Ok(());
                }
                Err(e) => {
                    // TODO: update the publish status (see also the module-level TODO about this).
                    error_report!(
                        e,
                        "HS service {}: descriptor publisher crashed!",
                        self.imm.nickname
                    );

                    self.imm.status_tx.send_broken(e.clone());

                    return Err(e);
                }
            }
        }
    }

    /// Run one iteration of the reactor loop.
    async fn run_once(&mut self) -> Result<ShutdownStatus, FatalError> {
        let mut netdir_events = self.dir_provider.events();

        // Note: TrackingNow tracks the values it is compared with.
        // This is equivalent to sleeping for (until - now) units of time,
        let upload_rate_lim: TrackingNow = TrackingNow::now(&self.imm.runtime);
        if let PublishStatus::RateLimited(until) = self.status() {
            if upload_rate_lim > until {
                // We are no longer rate-limited
                self.expire_rate_limit().await?;
            }
        }

        let reupload_tracking = TrackingNow::now(&self.imm.runtime);
        let mut reupload_periods = vec![];
        {
            let mut inner = self.inner.lock().expect("poisoned lock");
            let inner = &mut *inner;
            while let Some(reupload) = inner.reupload_timers.peek().copied() {
                // First, extract all the timeouts that already elapsed.
                if reupload.when <= reupload_tracking {
                    inner.reupload_timers.pop();
                    reupload_periods.push(reupload.period);
                } else {
                    // We are not ready to schedule any more reuploads.
                    //
                    // How much we need to sleep is implicitly
                    // tracked in reupload_tracking (through
                    // the TrackingNow implementation)
                    break;
                }
            }
        }

        // Check if it's time to schedule any reuploads.
        for period in reupload_periods {
            if self.mark_dirty(&period) {
                debug!(
                    time_period=?period,
                    "descriptor reupload timer elapsed; scheduling reupload",
                );
                self.update_publish_status_unless_rate_lim(PublishStatus::UploadScheduled)
                    .await?;
            }
        }

        select_biased! {
            res = self.upload_task_complete_rx.next().fuse() => {
                let Some(upload_res) = res else {
                    return Ok(ShutdownStatus::Terminate);
                };

                self.handle_upload_results(upload_res);
            },
            () = upload_rate_lim.wait_for_earliest(&self.imm.runtime).fuse() => {
                self.expire_rate_limit().await?;
            },
            () = reupload_tracking.wait_for_earliest(&self.imm.runtime).fuse() => {
                // Run another iteration, executing run_once again. This time, we will remove the
                // expired reupload from self.reupload_timers, mark the descriptor dirty for all
                // relevant HsDirs, and schedule the upload by setting our status to
                // UploadScheduled.
                return Ok(ShutdownStatus::Continue);
            },
            netdir_event = netdir_events.next().fuse() => {
                let Some(netdir_event) = netdir_event else {
                    debug!("netdir event stream ended");
                    return Ok(ShutdownStatus::Terminate);
                };

                if !matches!(netdir_event, DirEvent::NewConsensus) {
                    return Ok(ShutdownStatus::Continue);
                };

                // The consensus changed. Grab a new NetDir.
                let netdir = match self.dir_provider.netdir(Timeliness::Timely) {
                    Ok(y) => y,
                    Err(e) => {
                        error_report!(e, "HS service {}: netdir unavailable. Retrying...", self.imm.nickname);
                        // Hopefully a netdir will appear in the future.
                        // in the meantime, suspend operations.
                        //
                        // TODO (#1218): there is a bug here: we stop reading on our inputs
                        // including eg publish_status_rx, but it is our job to log some of
                        // these things.  While we are waiting for a netdir, all those messages
                        // are "stuck"; they'll appear later, with misleading timestamps.
                        //
                        // Probably this should be fixed by moving the logging
                        // out of the reactor, where it won't be blocked.
                        wait_for_netdir(self.dir_provider.as_ref(), Timeliness::Timely)
                            .await?
                    }
                };
                let relevant_periods = netdir.hs_all_time_periods();
                self.handle_consensus_change(netdir).await?;
                expire_publisher_keys(
                    &self.imm.keymgr,
                    &self.imm.nickname,
                    &relevant_periods,
                ).unwrap_or_else(|e| {
                    error_report!(e, "failed to remove expired keys");
                });
            }
            update = self.ipt_watcher.await_update().fuse() => {
                if self.handle_ipt_change(update).await? == ShutdownStatus::Terminate {
                    return Ok(ShutdownStatus::Terminate);
                }
            },
            config = self.config_rx.next().fuse() => {
                let Some(config) = config else {
                    return Ok(ShutdownStatus::Terminate);
                };

                self.handle_svc_config_change(&config).await?;
            },
            res = self.key_dirs_rx.next().fuse() => {
                let Some(event) = res else {
                    return Ok(ShutdownStatus::Terminate);
                };

                while let Some(_ignore) = self.key_dirs_rx.try_recv() {
                    // Discard other events, so that we only reload once.
                }

                self.handle_key_dirs_change(event).await?;
            }
            should_upload = self.publish_status_rx.next().fuse() => {
                let Some(should_upload) = should_upload else {
                    return Ok(ShutdownStatus::Terminate);
                };

                // Our PublishStatus changed -- are we ready to publish?
                if should_upload == PublishStatus::UploadScheduled {
                    self.update_publish_status_unless_waiting(PublishStatus::Idle).await?;
                    self.upload_all().await?;
                }
            }
        }

        Ok(ShutdownStatus::Continue)
    }

    /// Returns the current status of the publisher
    fn status(&self) -> PublishStatus {
        *self.publish_status_rx.borrow()
    }

    /// Handle a batch of upload outcomes,
    /// possibly updating the status of the descriptor for the corresponding HSDirs.
    fn handle_upload_results(&self, results: TimePeriodUploadResult) {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let inner = &mut *inner;

        // Check which time period these uploads pertain to.
        let period = inner
            .time_periods
            .iter_mut()
            .find(|ctx| ctx.params.time_period() == results.time_period);

        let Some(period) = period else {
            // The uploads were for a time period that is no longer relevant, so we
            // can ignore the result.
            return;
        };

        // We will need to reupload this descriptor at at some point, so we pick
        // a random time between 60 minutes and 120 minutes in the future.
        //
        // See https://spec.torproject.org/rend-spec/deriving-keys.html#WHEN-HSDESC
        let mut rng = self.imm.mockable.thread_rng();
        // TODO SPEC: Control republish period using a consensus parameter?
        let minutes = rng.gen_range_checked(60..=120).expect("low > high?!");
        let duration = Duration::from_secs(minutes * 60);
        let reupload_when = self.imm.runtime.now() + duration;
        let time_period = period.params.time_period();

        info!(
            time_period=?time_period,
            "reuploading descriptor in {}",
            humantime::format_duration(duration),
        );

        inner.reupload_timers.push(ReuploadTimer {
            period: time_period,
            when: reupload_when,
        });

        for upload_res in results.hsdir_result {
            let relay = period
                .hs_dirs
                .iter_mut()
                .find(|(relay_ids, _status)| relay_ids == &upload_res.relay_ids);

            let Some((_relay, status)): Option<&mut (RelayIds, _)> = relay else {
                // This HSDir went away, so the result doesn't matter.
                // Continue processing the rest of the results
                continue;
            };

            if upload_res.upload_res == UploadStatus::Success {
                let update_last_successful = match period.last_successful {
                    None => true,
                    Some(counter) => counter <= upload_res.revision_counter,
                };

                if update_last_successful {
                    period.last_successful = Some(upload_res.revision_counter);
                    // TODO (#1098): Is it possible that this won't update the statuses promptly
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
        }
    }

    /// Maybe update our list of HsDirs.
    async fn handle_consensus_change(&mut self, netdir: Arc<NetDir>) -> Result<(), FatalError> {
        trace!("the consensus has changed; recomputing HSDirs");

        let _old: Option<Arc<NetDir>> = self.replace_netdir(netdir);

        self.recompute_hs_dirs()?;
        self.update_publish_status_unless_waiting(PublishStatus::UploadScheduled)
            .await?;

        Ok(())
    }

    /// Recompute the HsDirs for all relevant time periods.
    fn recompute_hs_dirs(&self) -> Result<(), FatalError> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let inner = &mut *inner;

        let netdir = Arc::clone(
            inner
                .netdir
                .as_ref()
                .ok_or_else(|| internal!("started upload task without a netdir"))?,
        );

        // Update our list of relevant time periods.
        let new_time_periods = self.compute_time_periods(&netdir, &inner.time_periods)?;
        inner.time_periods = new_time_periods;

        Ok(())
    }

    /// Compute the [`TimePeriodContext`]s for the time periods from the specified [`NetDir`].
    ///
    /// The specified `time_periods` are used to preserve the `DescriptorStatus` of the
    /// HsDirs where possible.
    fn compute_time_periods(
        &self,
        netdir: &Arc<NetDir>,
        time_periods: &[TimePeriodContext],
    ) -> Result<Vec<TimePeriodContext>, FatalError> {
        netdir
            .hs_all_time_periods()
            .iter()
            .map(|params| {
                let period = params.time_period();
                let blind_id_kp =
                    read_blind_id_keypair(&self.imm.keymgr, &self.imm.nickname, period)?
                        // Note: for now, read_blind_id_keypair cannot return Ok(None).
                        // It's supposed to return Ok(None) if we're in offline hsid mode,
                        // but that might change when we do #1194
                        .ok_or_else(|| internal!("offline hsid mode not supported"))?;

                let blind_id: HsBlindIdKey = (&blind_id_kp).into();

                // If our previous `TimePeriodContext`s also had an entry for `period`, we need to
                // preserve the `DescriptorStatus` of its HsDirs. This helps prevent unnecessarily
                // publishing the descriptor to the HsDirs that already have it (the ones that are
                // marked with DescriptorStatus::Clean).
                //
                // In other words, we only want to publish to those HsDirs that
                //   * are part of a new time period (which we have never published the descriptor
                //   for), or
                //   * have just been added to the ring of a time period we already knew about
                if let Some(ctx) = time_periods
                    .iter()
                    .find(|ctx| ctx.params.time_period() == period)
                {
                    TimePeriodContext::new(
                        params.clone(),
                        blind_id.into(),
                        netdir,
                        ctx.hs_dirs.iter(),
                    )
                } else {
                    // Passing an empty iterator here means all HsDirs in this TimePeriodContext
                    // will be marked as dirty, meaning we will need to upload our descriptor to them.
                    TimePeriodContext::new(params.clone(), blind_id.into(), netdir, iter::empty())
                }
            })
            .collect::<Result<Vec<TimePeriodContext>, FatalError>>()
    }

    /// Replace the old netdir with the new, returning the old.
    fn replace_netdir(&self, new_netdir: Arc<NetDir>) -> Option<Arc<NetDir>> {
        self.inner
            .lock()
            .expect("poisoned lock")
            .netdir
            .replace(new_netdir)
    }

    /// Replace our view of the service config with `new_config` if `new_config` contains changes
    /// that would cause us to generate a new descriptor.
    fn replace_config_if_changed(&self, new_config: Arc<OnionServiceConfigPublisherView>) -> bool {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let old_config = &mut inner.config;

        // The fields we're interested in haven't changed, so there's no need to update
        // `inner.config`.
        if *old_config == new_config {
            return false;
        }

        let log_change = match (
            old_config.restricted_discovery.enabled,
            new_config.restricted_discovery.enabled,
        ) {
            (true, false) => Some("Disabling restricted discovery mode"),
            (false, true) => Some("Enabling restricted discovery mode"),
            _ => None,
        };

        if let Some(msg) = log_change {
            info!(nickname=%self.imm.nickname, "{}", msg);
        }

        let _old: Arc<OnionServiceConfigPublisherView> = std::mem::replace(old_config, new_config);

        true
    }

    /// Recreate the FileWatcher for watching the restricted discovery key_dirs.
    fn update_file_watcher(&self) {
        let mut inner = self.inner.lock().expect("poisoned lock");
        if inner.config.restricted_discovery.watch_configuration() {
            debug!("The restricted_discovery.key_dirs have changed, updating file watcher");
            let mut watcher = FileWatcher::builder(self.imm.runtime.clone());

            let dirs = inner.config.restricted_discovery.key_dirs().clone();

            watch_dirs(&mut watcher, &dirs);

            let watcher = watcher
                .start_watching(self.key_dirs_tx.clone())
                .map_err(|e| {
                    error_report!(e, "Cannot set file watcher");
                })
                .ok();
            inner.file_watcher = watcher;
        } else {
            if inner.file_watcher.is_some() {
                debug!("removing key_dirs watcher");
            }
            inner.file_watcher = None;
        }
    }

    /// Read the intro points from `ipt_watcher`, and decide whether we're ready to start
    /// uploading.
    fn note_ipt_change(&self) -> PublishStatus {
        let mut ipts = self.ipt_watcher.borrow_for_publish();
        match ipts.ipts.as_mut() {
            Some(_ipts) => PublishStatus::UploadScheduled,
            None => PublishStatus::AwaitingIpts,
        }
    }

    /// Update our list of introduction points.
    async fn handle_ipt_change(
        &mut self,
        update: Option<Result<(), crate::FatalError>>,
    ) -> Result<ShutdownStatus, FatalError> {
        trace!(nickname=%self.imm.nickname, "received IPT change notification from IPT manager");
        match update {
            Some(Ok(())) => {
                let should_upload = self.note_ipt_change();
                debug!(nickname=%self.imm.nickname, "the introduction points have changed");

                self.mark_all_dirty();
                self.update_publish_status_unless_rate_lim(should_upload)
                    .await?;
                Ok(ShutdownStatus::Continue)
            }
            Some(Err(e)) => Err(e),
            None => {
                debug!(nickname=%self.imm.nickname, "received shut down signal from IPT manager");
                Ok(ShutdownStatus::Terminate)
            }
        }
    }

    /// Update the `PublishStatus` of the reactor with `new_state`,
    /// unless the current state is `AwaitingIpts`.
    async fn update_publish_status_unless_waiting(
        &mut self,
        new_state: PublishStatus,
    ) -> Result<(), FatalError> {
        // Only update the state if we're not waiting for intro points.
        if self.status() != PublishStatus::AwaitingIpts {
            self.update_publish_status(new_state).await?;
        }

        Ok(())
    }

    /// Update the `PublishStatus` of the reactor with `new_state`,
    /// unless the current state is `RateLimited`.
    async fn update_publish_status_unless_rate_lim(
        &mut self,
        new_state: PublishStatus,
    ) -> Result<(), FatalError> {
        // We can't exit this state until the rate-limit expires.
        if !matches!(self.status(), PublishStatus::RateLimited(_)) {
            self.update_publish_status(new_state).await?;
        }

        Ok(())
    }

    /// Unconditionally update the `PublishStatus` of the reactor with `new_state`.
    async fn update_publish_status(&mut self, new_state: PublishStatus) -> Result<(), FatalError> {
        let onion_status = match new_state {
            PublishStatus::Idle => State::Running,
            PublishStatus::UploadScheduled
            | PublishStatus::AwaitingIpts
            | PublishStatus::RateLimited(_) => State::Bootstrapping,
        };

        self.imm.status_tx.send(onion_status, None);

        trace!(
            "publisher reactor status change: {:?} -> {:?}",
            self.status(),
            new_state
        );

        self.publish_status_tx.send(new_state).await.map_err(
            |_: postage::sink::SendError<_>| internal!("failed to send upload notification?!"),
        )?;

        Ok(())
    }

    /// Update the descriptors based on the config change.
    async fn handle_svc_config_change(
        &mut self,
        config: &OnionServiceConfig,
    ) -> Result<(), FatalError> {
        let new_config = Arc::new(config.into());
        if self.replace_config_if_changed(Arc::clone(&new_config)) {
            self.update_file_watcher();
            self.update_authorized_clients_if_changed().await?;

            info!(nickname=%self.imm.nickname, "Config has changed, generating a new descriptor");
            self.mark_all_dirty();

            // Schedule an upload, unless we're still waiting for IPTs.
            self.update_publish_status_unless_waiting(PublishStatus::UploadScheduled)
                .await?;
        }

        Ok(())
    }

    /// Update the descriptors based on a restricted discovery key_dirs change.
    ///
    /// If the authorized clients from the [`RestrictedDiscoveryConfig`] have changed,
    /// this marks the descriptor as dirty for all time periods,
    /// and schedules a reupload.
    async fn handle_key_dirs_change(&mut self, event: FileEvent) -> Result<(), FatalError> {
        debug!("The configured key_dirs have changed");
        match event {
            FileEvent::Rescan | FileEvent::FileChanged => {
                // These events are handled in the same way, by re-reading the keys from disk
                // and republishing the descriptor if necessary
            }
            _ => return Err(internal!("file watcher event {event:?}").into()),
        };

        if self.update_authorized_clients_if_changed().await? {
            self.mark_all_dirty();

            // Schedule an upload, unless we're still waiting for IPTs.
            self.update_publish_status_unless_waiting(PublishStatus::UploadScheduled)
                .await?;
        }

        Ok(())
    }

    /// Recreate the authorized_clients based on the current config.
    ///
    /// Returns `true` if the authorized clients have changed.
    async fn update_authorized_clients_if_changed(&mut self) -> Result<bool, FatalError> {
        let authorized_clients = {
            let inner = self.inner.lock().expect("poisoned lock");
            Self::read_authorized_clients(&inner.config.restricted_discovery)
        };

        let mut clients_lock = self.imm.authorized_clients.lock().expect("poisoned lock");
        let changed = clients_lock.as_ref() != authorized_clients.as_ref();

        if changed {
            info!("The restricted discovery mode authorized clients have changed");
            *clients_lock = authorized_clients;
        }

        Ok(changed)
    }

    /// Read the authorized `RestrictedDiscoveryKeys` from `config`.
    fn read_authorized_clients(
        config: &RestrictedDiscoveryConfig,
    ) -> Option<RestrictedDiscoveryKeys> {
        let authorized_clients = config.read_keys();

        if matches!(authorized_clients.as_ref(), Some(c) if c.is_empty()) {
            warn!(
                "Running in restricted discovery mode, but we have no authorized clients. Service will be unreachable"
            );
        }

        authorized_clients
    }

    /// Mark the descriptor dirty for all time periods.
    fn mark_all_dirty(&self) {
        trace!("marking the descriptor dirty for all time periods");

        self.inner
            .lock()
            .expect("poisoned lock")
            .time_periods
            .iter_mut()
            .for_each(|tp| tp.mark_all_dirty());
    }

    /// Mark the descriptor dirty for the specified time period.
    ///
    /// Returns `true` if the specified period is still relevant, and `false` otherwise.
    fn mark_dirty(&self, period: &TimePeriod) -> bool {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let period_ctx = inner
            .time_periods
            .iter_mut()
            .find(|tp| tp.params.time_period() == *period);

        match period_ctx {
            Some(ctx) => {
                trace!(time_period=?period, "marking the descriptor dirty");
                ctx.mark_all_dirty();
                true
            }
            None => false,
        }
    }

    /// Try to upload our descriptor to the HsDirs that need it.
    ///
    /// If we've recently uploaded some descriptors, we return immediately and schedule the upload
    /// to happen after [`UPLOAD_RATE_LIM_THRESHOLD`].
    ///
    /// Any failed uploads are retried (TODO (#1216, #1098): document the retry logic when we
    /// implement it, as well as in what cases this will return an error).
    async fn upload_all(&mut self) -> Result<(), FatalError> {
        trace!("starting descriptor upload task...");

        let last_uploaded = self.inner.lock().expect("poisoned lock").last_uploaded;
        let now = self.imm.runtime.now();
        // Check if we should rate-limit this upload.
        if let Some(ts) = last_uploaded {
            let duration_since_upload = now.duration_since(ts);

            if duration_since_upload < UPLOAD_RATE_LIM_THRESHOLD {
                return self.start_rate_limit(UPLOAD_RATE_LIM_THRESHOLD).await;
            }
        }

        let mut inner = self.inner.lock().expect("poisoned lock");
        let inner = &mut *inner;

        let _ = inner.last_uploaded.insert(now);

        for period_ctx in inner.time_periods.iter_mut() {
            let upload_task_complete_tx = self.upload_task_complete_tx.clone();

            // Figure out which HsDirs we need to upload the descriptor to (some of them might already
            // have our latest descriptor, so we filter them out).
            let hs_dirs = period_ctx
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

            if hs_dirs.is_empty() {
                trace!("the descriptor is clean for all HSDirs. Nothing to do");
                return Ok(());
            }

            let time_period = period_ctx.params.time_period();
            // This scope exists because rng is not Send, so it needs to fall out of scope before we
            // await anything.
            let netdir = Arc::clone(
                inner
                    .netdir
                    .as_ref()
                    .ok_or_else(|| internal!("started upload task without a netdir"))?,
            );

            let imm = Arc::clone(&self.imm);
            let ipt_upload_view = self.ipt_watcher.upload_view();
            let config = Arc::clone(&inner.config);

            trace!(nickname=%self.imm.nickname, time_period=?time_period,
                "spawning upload task"
            );

            let params = period_ctx.params.clone();
            let shutdown_rx = self.shutdown_tx.subscribe();

            // Spawn a task to upload the descriptor to all HsDirs of this time period.
            //
            // This task will shut down when the reactor is dropped (i.e. when shutdown_rx is
            // dropped).
            let _handle: () = self
                .imm
                .runtime
                .spawn(async move {
                    if let Err(e) = Self::upload_for_time_period(
                        hs_dirs,
                        &netdir,
                        config,
                        params,
                        Arc::clone(&imm),
                        ipt_upload_view.clone(),
                        upload_task_complete_tx,
                        shutdown_rx,
                    )
                    .await
                    {
                        error_report!(
                            e,
                            "descriptor upload failed for HS service {} and time period {:?}",
                            imm.nickname,
                            time_period
                        );
                    }
                })
                .map_err(|e| FatalError::from_spawn("upload_for_time_period task", e))?;
        }

        Ok(())
    }

    /// Upload the descriptor for the specified time period.
    ///
    /// Any failed uploads are retried (TODO (#1216, #1098): document the retry logic when we
    /// implement it, as well as in what cases this will return an error).
    #[allow(clippy::too_many_arguments)] // TODO: refactor
    async fn upload_for_time_period(
        hs_dirs: Vec<RelayIds>,
        netdir: &Arc<NetDir>,
        config: Arc<OnionServiceConfigPublisherView>,
        params: HsDirParams,
        imm: Arc<Immutable<R, M>>,
        ipt_upload_view: IptsPublisherUploadView,
        mut upload_task_complete_tx: mpsc::Sender<TimePeriodUploadResult>,
        shutdown_rx: broadcast::Receiver<Void>,
    ) -> Result<(), FatalError> {
        let time_period = params.time_period();
        trace!(time_period=?time_period, "uploading descriptor to all HSDirs for this time period");

        let hsdir_count = hs_dirs.len();

        /// An error returned from an upload future.
        //
        // Exhaustive, because this is a private type.
        #[derive(Clone, Debug, thiserror::Error)]
        enum PublishError {
            /// The upload was aborted because there are no IPTs.
            ///
            /// This happens because of an inevitable TOCTOU race, where after being notified by
            /// the IPT manager that the IPTs have changed (via `self.ipt_watcher.await_update`),
            /// we find out there actually are no IPTs, so we can't build the descriptor.
            ///
            /// This is a special kind of error that interrupts the current upload task, and is
            /// logged at `debug!` level rather than `warn!` or `error!`.
            ///
            /// Ideally, this shouldn't happen very often (if at all).
            #[error("No IPTs")]
            NoIpts,

            /// The reactor has shut down
            #[error("The reactor has shut down")]
            Shutdown,

            /// An fatal error.
            #[error("{0}")]
            Fatal(#[from] FatalError),
        }

        let upload_results = futures::stream::iter(hs_dirs)
            .map(|relay_ids| {
                let netdir = netdir.clone();
                let config = Arc::clone(&config);
                let imm = Arc::clone(&imm);
                let ipt_upload_view = ipt_upload_view.clone();
                let params = params.clone();
                let mut shutdown_rx = shutdown_rx.clone();

                let ed_id = relay_ids
                    .rsa_identity()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let rsa_id = relay_ids
                    .rsa_identity()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".into());

                async move {
                    let run_upload = |desc| async {
                        let Some(hsdir) = netdir.by_ids(&relay_ids) else {
                            // This should never happen (all of our relay_ids are from the stored
                            // netdir).
                            warn!(
                                nickname=%imm.nickname, hsdir_id=%ed_id, hsdir_rsa_id=%rsa_id,
                                "tried to upload descriptor to relay not found in consensus?!"
                            );
                            return UploadStatus::Failure;
                        };

                        Self::upload_descriptor_with_retries(
                            desc,
                            &netdir,
                            &hsdir,
                            &ed_id,
                            &rsa_id,
                            Arc::clone(&imm),
                        )
                        .await
                    };

                    // How long until we're supposed to time out?
                    let worst_case_end = imm.runtime.now() + OVERALL_UPLOAD_TIMEOUT;
                    // We generate a new descriptor before _each_ HsDir upload. This means each
                    // HsDir could, in theory, receive a different descriptor (not just in terms of
                    // revision-counters, but also with a different set of IPTs). It may seem like
                    // this could lead to some HsDirs being left with an outdated descriptor, but
                    // that's not the case: after the upload completes, the publisher will be
                    // notified by the ipt_watcher of the IPT change event (if there was one to
                    // begin with), which will trigger another upload job.
                    let hsdesc = {
                        // This scope is needed because the ipt_set MutexGuard is not Send, so it
                        // needs to fall out of scope before the await point below
                        let mut ipt_set = ipt_upload_view.borrow_for_publish();

                        // If there are no IPTs, we abort the upload. At this point, we might have
                        // uploaded the descriptor to some, but not all, HSDirs from the specified
                        // time period.
                        //
                        // Returning an error here means the upload completion task is never
                        // notified of the outcome of any of these uploads (which means the
                        // descriptor is not marked clean). This is OK, because if we suddenly find
                        // out we have no IPTs, it means our built `hsdesc` has an outdated set of
                        // IPTs, so we need to go back to the main loop to wait for IPT changes,
                        // and generate a fresh descriptor anyway.
                        //
                        // Ideally, this shouldn't happen very often (if at all).
                        let Some(ipts) = ipt_set.ipts.as_mut() else {
                            return Err(PublishError::NoIpts);
                        };

                        let hsdesc = {
                            trace!(
                                nickname=%imm.nickname, time_period=?time_period,
                                "building descriptor"
                            );
                            let mut rng = imm.mockable.thread_rng();

                            // We're about to generate a new version of the descriptor,
                            // so let's generate a new revision counter.
                            let now = imm.runtime.wallclock();
                            let revision_counter = imm.generate_revision_counter(&params, now)?;

                            build_sign(
                                &imm.keymgr,
                                &config,
                                &imm.authorized_clients,
                                ipts,
                                time_period,
                                revision_counter,
                                &mut rng,
                                imm.runtime.wallclock(),
                            )?
                        };

                        if let Err(e) =
                            ipt_set.note_publication_attempt(&imm.runtime, worst_case_end)
                        {
                            let wait = e.log_retry_max(&imm.nickname)?;
                            // TODO (#1226): retry instead of this
                            return Err(FatalError::Bug(internal!(
                                "ought to retry after {wait:?}, crashing instead"
                            ))
                            .into());
                        }

                        hsdesc
                    };

                    let VersionedDescriptor {
                        desc,
                        revision_counter,
                    } = hsdesc;

                    trace!(
                        nickname=%imm.nickname, time_period=?time_period,
                        revision_counter=?revision_counter,
                        "generated new descriptor for time period",
                    );

                    // (Actually launch the upload attempt. No timeout is needed
                    // here, since the backoff::Runner code will handle that for us.)
                    let upload_res = select_biased! {
                        shutdown = shutdown_rx.next().fuse() => {
                            // This will always be None, since Void is uninhabited.
                            let _: Option<Void> = shutdown;

                            // It looks like the reactor has shut down,
                            // so there is no point in uploading the descriptor anymore.
                            //
                            // Let's shut down the upload task too.
                            trace!(
                                nickname=%imm.nickname, time_period=?time_period,
                                "upload task received shutdown signal"
                            );

                            return Err(PublishError::Shutdown);
                        },
                        res = run_upload(desc.clone()).fuse() => res,
                    };

                    // Note: UploadStatus::Failure is only returned when
                    // upload_descriptor_with_retries fails, i.e. if all our retry
                    // attempts have failed
                    Ok(HsDirUploadStatus {
                        relay_ids,
                        upload_res,
                        revision_counter,
                    })
                }
            })
            // This fails to compile unless the stream is boxed. See https://github.com/rust-lang/rust/issues/104382
            .boxed()
            .buffer_unordered(MAX_CONCURRENT_UPLOADS)
            .try_collect::<Vec<_>>()
            .await;

        let upload_results = match upload_results {
            Ok(v) => v,
            Err(PublishError::Fatal(e)) => return Err(e),
            Err(PublishError::NoIpts) => {
                debug!(
                    nickname=%imm.nickname, time_period=?time_period,
                     "no introduction points; skipping upload"
                );

                return Ok(());
            }
            Err(PublishError::Shutdown) => {
                debug!(
                    nickname=%imm.nickname, time_period=?time_period,
                     "the reactor has shut down; aborting upload"
                );

                return Ok(());
            }
        };

        let (succeeded, _failed): (Vec<_>, Vec<_>) = upload_results
            .iter()
            .partition(|res| res.upload_res == UploadStatus::Success);

        debug!(
            nickname=%imm.nickname, time_period=?time_period,
            "descriptor uploaded successfully to {}/{} HSDirs",
            succeeded.len(), hsdir_count
        );

        if upload_task_complete_tx
            .send(TimePeriodUploadResult {
                time_period,
                hsdir_result: upload_results,
            })
            .await
            .is_err()
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
    ///
    /// This function does not handle timeouts.
    async fn upload_descriptor(
        hsdesc: String,
        netdir: &Arc<NetDir>,
        hsdir: &Relay<'_>,
        imm: Arc<Immutable<R, M>>,
    ) -> Result<(), UploadError> {
        let request = HsDescUploadRequest::new(hsdesc);

        trace!(nickname=%imm.nickname, hsdir_id=%hsdir.id(), hsdir_rsa_id=%hsdir.rsa_id(),
            "starting descriptor upload",
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

        let _response: String = send_request(&imm.runtime, &request, &mut stream, None)
            .await
            .map_err(|dir_error| -> UploadError {
                match dir_error {
                    DirClientError::RequestFailed(e) => e.into(),
                    DirClientError::CircMgr(e) => into_internal!(
                        "tor-dirclient complains about circmgr going wrong but we gave it a stream"
                    )(e)
                    .into(),
                    e => into_internal!("unexpected error")(e).into(),
                }
            })?
            .into_output_string()?; // This returns an error if we received an error response

        Ok(())
    }

    /// Upload a descriptor to the specified HSDir, retrying if appropriate.
    ///
    /// TODO (#1216): document the retry logic when we implement it.
    async fn upload_descriptor_with_retries(
        hsdesc: String,
        netdir: &Arc<NetDir>,
        hsdir: &Relay<'_>,
        ed_id: &str,
        rsa_id: &str,
        imm: Arc<Immutable<R, M>>,
    ) -> UploadStatus {
        /// The base delay to use for the backoff schedule.
        const BASE_DELAY_MSEC: u32 = 1000;
        let schedule = PublisherBackoffSchedule {
            retry_delay: RetryDelay::from_msec(BASE_DELAY_MSEC),
            mockable: imm.mockable.clone(),
        };

        let runner = Runner::new(
            "upload a hidden service descriptor".into(),
            schedule.clone(),
            imm.runtime.clone(),
        );

        let fallible_op =
            || Self::upload_descriptor(hsdesc.clone(), netdir, hsdir, Arc::clone(&imm));

        let outcome: Result<(), BackoffError<UploadError>> = runner.run(fallible_op).await;
        match outcome {
            Ok(()) => {
                debug!(
                    nickname=%imm.nickname, hsdir_id=%ed_id, hsdir_rsa_id=%rsa_id,
                    "successfully uploaded descriptor to HSDir",
                );

                UploadStatus::Success
            }
            Err(e) => {
                warn_report!(
                    e,
                    "failed to upload descriptor for service {} (hsdir_id={}, hsdir_rsa_id={})",
                    imm.nickname,
                    ed_id,
                    rsa_id
                );

                UploadStatus::Failure
            }
        }
    }

    /// Stop publishing descriptors until the specified delay elapses.
    async fn start_rate_limit(&mut self, delay: Duration) -> Result<(), FatalError> {
        if !matches!(self.status(), PublishStatus::RateLimited(_)) {
            debug!(
                "We are rate-limited for {}; pausing descriptor publication",
                humantime::format_duration(delay)
            );
            let until = self.imm.runtime.now() + delay;
            self.update_publish_status(PublishStatus::RateLimited(until))
                .await?;
        }

        Ok(())
    }

    /// Handle the upload rate-limit being lifted.
    async fn expire_rate_limit(&mut self) -> Result<(), FatalError> {
        debug!("We are no longer rate-limited; resuming descriptor publication");
        self.update_publish_status(PublishStatus::UploadScheduled)
            .await?;
        Ok(())
    }
}

/// Try to expand a path, logging a warning on failure.
fn maybe_expand_path(p: &tor_config::CfgPath) -> Option<PathBuf> {
    // map_err returns unit for clarity
    #[allow(clippy::unused_unit, clippy::semicolon_if_nothing_returned)]
    p.path()
        .map_err(|e| {
            tor_error::warn_report!(e, "invalid path");
            ()
        })
        .ok()
}

/// Add `path` to the specified `watcher`.
macro_rules! watch_path {
    ($watcher:expr, $path:expr, $watch_fn:ident, $($watch_fn_args:expr,)*) => {{
        if let Err(e) = $watcher.$watch_fn(&$path, $($watch_fn_args)*) {
            warn_report!(e, "failed to watch path {:?}", $path);
        } else {
            debug!("watching path {:?}", $path);
        }
    }}
}

/// Add the specified directories to the watcher.
#[allow(clippy::cognitive_complexity)]
fn watch_dirs<R: Runtime>(watcher: &mut FileWatcherBuilder<R>, dirs: &DirectoryKeyProviderList) {
    for path in dirs {
        let path = path.path();
        let Some(path) = maybe_expand_path(path) else {
            warn!("failed to expand key_dir path {:?}", path);
            continue;
        };

        // If the path doesn't exist, the notify watcher will return an error if we attempt to watch it,
        // so we skip over paths that don't exist at this time
        // (this obviously suffers from a TOCTOU race, but most of the time,
        // it is good enough at preventing the watcher from failing to watch.
        // If the race *does* happen it is not disastrous, i.e. the reactor won't crash,
        // but it will fail to set the watcher).
        if matches!(path.try_exists(), Ok(true)) {
            watch_path!(watcher, &path, watch_dir, "auth",);
        }
        // FileWatcher::watch_file causes the parent dir of the path to be watched.
        if matches!(path.parent().map(|p| p.try_exists()), Some(Ok(true))) {
            watch_path!(watcher, &path, watch_file,);
        }
    }
}

/// Try to read the blinded identity key for a given `TimePeriod`.
///
/// Returns `None` if the service is running in "offline" mode.
///
// TODO (#1194): we don't currently have support for "offline" mode so this can never return
// `Ok(None)`.
pub(super) fn read_blind_id_keypair(
    keymgr: &Arc<KeyMgr>,
    nickname: &HsNickname,
    period: TimePeriod,
) -> Result<Option<HsBlindIdKeypair>, FatalError> {
    let svc_key_spec = HsIdKeypairSpecifier::new(nickname.clone());
    let hsid_kp = keymgr
        .get::<HsIdKeypair>(&svc_key_spec)?
        .ok_or_else(|| FatalError::MissingHsIdKeypair(nickname.clone()))?;

    let blind_id_key_spec = BlindIdKeypairSpecifier::new(nickname.clone(), period);

    // TODO: make the keystore selector configurable
    let keystore_selector = Default::default();
    match keymgr.get::<HsBlindIdKeypair>(&blind_id_key_spec)? {
        Some(kp) => Ok(Some(kp)),
        None => {
            let (_hs_blind_id_key, hs_blind_id_kp, _subcredential) = hsid_kp
                .compute_blinded_key(period)
                .map_err(|_| internal!("failed to compute blinded key"))?;

            // Note: we can't use KeyMgr::generate because this key is derived from the HsId
            // (KeyMgr::generate uses the tor_keymgr::Keygen trait under the hood,
            // which assumes keys are randomly generated, rather than derived from existing keys).

            keymgr.insert(hs_blind_id_kp, &blind_id_key_spec, keystore_selector)?;

            let arti_path = |spec: &dyn KeySpecifier| {
                spec.arti_path()
                    .map_err(into_internal!("invalid key specifier?!"))
            };

            Ok(Some(
                keymgr.get::<HsBlindIdKeypair>(&blind_id_key_spec)?.ok_or(
                    FatalError::KeystoreRace {
                        action: "read",
                        path: arti_path(&blind_id_key_spec)?,
                    },
                )?,
            ))
        }
    }
}

/// Whether the reactor should initiate an upload.
#[derive(Copy, Clone, Debug, Default, PartialEq)]
enum PublishStatus {
    /// We need to call upload_all.
    UploadScheduled,
    /// We are rate-limited until the specified [`Instant`].
    ///
    /// We have tried to schedule multiple uploads in a short time span,
    /// and we are rate-limited. We are waiting for a signal from the schedule_upload_tx
    /// channel to unblock us.
    RateLimited(Instant),
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

    fn overall_timeout(&self) -> Option<Duration> {
        Some(OVERALL_UPLOAD_TIMEOUT)
    }

    fn single_attempt_timeout(&self) -> Option<Duration> {
        Some(self.mockable.estimate_upload_timeout())
    }

    fn next_delay<E: RetriableError>(&mut self, _error: &E) -> Option<Duration> {
        Some(self.retry_delay.next_delay(&mut self.mockable.thread_rng()))
    }
}

impl RetriableError for UploadError {
    fn should_retry(&self) -> bool {
        match self {
            UploadError::Request(_)
            | UploadError::Circuit(_)
            | UploadError::Stream(_)
            | UploadError::Timeout => true,
            UploadError::Bug(_) => false,
        }
    }
}

/// The outcome of uploading a descriptor to the HSDirs from a particular time period.
#[derive(Debug, Clone)]
struct TimePeriodUploadResult {
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
    /// The revision counter of the descriptor we tried to upload.
    revision_counter: RevisionCounter,
}

/// The outcome of uploading a descriptor.
//
// TODO: consider making this a type alias for Result<(), ()>
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
