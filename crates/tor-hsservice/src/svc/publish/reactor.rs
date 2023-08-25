//! The onion service publisher reactor.
//!
//! TODO HSS: write the docs

use std::fmt::Debug;
use std::iter;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_broadcast::{broadcast, Receiver, RecvError, Sender};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::task::SpawnExt;
use futures::{select_biased, FutureExt, StreamExt};
use tracing::{debug, trace};

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
use crate::svc::netdir::{wait_for_netdir, NetdirProviderShutdown};
use crate::svc::publish::descriptor::{DescriptorBuilder, DescriptorStatus, Ipt};

/// The upload rate-limiting threshold.
///
/// Before initiating an upload, the reactor checks if the last upload was at least
/// `UPLOAD_RATE_LIM_THRESHOLD` seconds ago. If so, it uploads the descriptor to all HsDirs that
/// need it. If not, it schedules the upload to happen `UPLOAD_RATE_LIM_THRESHOLD` seconds from the
/// current time.
//
// TODO HSS: this value is probably not right.
const UPLOAD_RATE_LIM_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// A reactor for the HsDir [`Publisher`](super::Publisher).
///
/// The entrypoint is [`Reactor::run`].
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
    /// A channel for receiving events.
    rx: mpsc::UnboundedReceiver<Event>,
    /// A channel for the telling the upload reminder task when to remind us we need to upload
    /// some descriptors.
    pending_upload_tx: Sender<Duration>,
    /// A channel for receiving reminders from the upload reminder task.
    schedule_upload_rx: Receiver<()>,
}

/// Mockable state for the descriptor publisher reactor.
///
/// This enables us to mock parts of the [`Reactor`] for testing purposes.
#[async_trait]
pub(super) trait Mockable<R>: Send + Sync + Sized + 'static {
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
    /// Note: this may be partially built. Use [`DescriptorBuilder::validate`] to check if it is
    /// complete.
    ///
    /// This field is only expected to be incomplete on startup. Once the introduction points are
    /// established, we should have enough information to generate and upload the descriptor.
    descriptor: DescriptorBuilder,
    /// The onion service config.
    config: OnionServiceConfig,
    /// State specific to the current time period.
    current_period: TimePeriodContext,
    /// State specific to the previous time period.
    previous_period: Option<TimePeriodContext>,
    /// Our most up to date netdir.
    netdir: Arc<NetDir>,
    /// The timestamp of our last upload.
    //
    // TODO HSS: maybe we should implement rate-limiting on a per-hsdir basis? It's probably not
    // necessary though.
    last_uploaded: Option<SystemTime>,
}

impl Inner {
    /// Handle the transition to a new time period.
    fn register_new_period(
        &mut self,
        new_period: TimePeriod,
        blind_id: HsBlindId,
    ) -> Result<(), ReactorError> {
        let new_period = TimePeriodContext::new(new_period, blind_id, &self.netdir)?;
        let current_period = std::mem::replace(&mut self.current_period, new_period);

        self.previous_period = Some(current_period);

        Ok(())
    }
}

/// The part of the reactor state that changes with every time period.
#[derive(Clone)]
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
}

/// An event that needs to be handled by the publisher [`Reactor`].
///
/// These are triggered by calling the various methods of [`Publisher`](super::Publisher).
pub(super) enum Event {
    /// The introduction points of this service have changed.
    NewIntroPoints(Vec<Ipt>),
    /// The keys of this service have changed.
    ///
    /// TODO HSS: decide whether we need this, and if so, who is going to emit this event and what
    /// information it will include.
    NewKeys(()),
    /// The config of this service has changed.
    ///
    /// Note: not all config changes will cause the descriptor to be updated (if the changes are
    /// unrelated it is left unmodified).
    SvcConfigChange(OnionServiceConfig),
    /// A new time period started.
    TimePeriodChange((HsBlindId, TimePeriod)),
    // TODO HSS: do we need a shutdown event for explicitly shutting down the reactor?

    // Note: the reactor responds to other types of external events too, which do not have
    // a corresponding `Event` variant. These are:
    //
    //   * consensus changes, handled in [`Reactor::handle_consensus_change`]
    //   * handling deferred uploads: sometimes the reactor will defer an upload (for example, due
    //   to rate-limiting). Whenever this happens, the reactor notifies its "reminder task" to
    //   remind it to execute the upload at a later point
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
    #[allow(unreachable_code)] // TODO HSS: remove
    #[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
    pub(super) async fn new(
        runtime: R,
        hsid: HsId,
        dir_provider: Arc<dyn NetDirProvider>,
        mockable: M,
        config: OnionServiceConfig,
        rx: mpsc::UnboundedReceiver<Event>,
    ) -> Result<Self, ReactorError> {
        let hsid_key: HsIdKey = hsid
            .try_into()
            .expect("failed to recover ed25519 public key from hsid?!");
        let netdir = wait_for_netdir(dir_provider.as_ref(), Timeliness::Timely).await?;

        // TODO HSS: figure out how to compute the initial time period!
        let period = todo!();

        let (blind_id, _subcredential) = hsid_key
            .compute_blinded_key(period)
            .expect("failed to compute blinded key?!"); // TODO HSS: perhaps this should be an Err
        let current_period = TimePeriodContext::new(period, blind_id.into(), &netdir)?;

        // There will be at most one pending upload.
        let (pending_upload_tx, _) = broadcast(1);
        let (_, schedule_upload_rx) = broadcast(1);

        let inner = Inner {
            descriptor: DescriptorBuilder::default(),
            current_period,
            previous_period: None,
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
            rx,
            pending_upload_tx,
            schedule_upload_rx,
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

        let mut pending_upload_rx = self.pending_upload_tx.new_receiver();
        let schedule_upload_tx = self.schedule_upload_rx.new_sender();

        let rt = self.runtime.clone();
        // Spawn the task that will remind us to retry any rate-limited uploads.
        let _ = self.runtime.spawn(async move {
            // The sender tells us how long to wait until to schedule the upload
            while let Ok(duration) = pending_upload_rx.recv().await {
                rt.sleep(duration).await;

                // Enough time has elapsed. Remind the reactor to retry the upload.
                if let Err(e) = schedule_upload_tx.broadcast(()).await {
                    // TODO HSS: update publisher state
                    debug!("failed to notify reactor to reattempt upload");
                }
            }

            debug!("reupload task channel closed!");
        });

        let err = loop {
            if let Err(e) = self.run_once().await {
                break e;
            }
        };

        debug!("reactor stoped: {err}");

        Err(err)
    }

    /// Run one iteration of the reactor loop.
    async fn run_once(&mut self) -> Result<(), ReactorError> {
        let mut netdir_events = self.dir_provider.events();

        select_biased! {
            netidr_event = netdir_events.next().fuse() => {
                // The consensus changed. Grab a new NetDir.
                let netdir = self.dir_provider.netdir(Timeliness::Timely)?;

                self.handle_consensus_change(netdir).await?;
            }
            event = self.rx.next() => {
                // TODO HSS: document who is supposed to be keeping the sending end of this channel
                // alive.
                let event = event.ok_or(ReactorError::ShuttingDown)?;
                self.handle_event(event).await?;
            },
            res = self.schedule_upload_rx.recv().fuse() => {
                let _: () = res.map_err(|_: RecvError| ReactorError::ShuttingDown)?;

                // Time to reattempt a previously rate-limited upload
                self.upload_all().await?;
            }
            // TODO HSS: maybe create some task that notifies us when the time period changes?
            // Alternatively, we can check if the time period changed every time we handle an
            // event/consensus change.
        }

        Ok(())
    }

    /// Maybe update our list of HsDirs.
    async fn handle_consensus_change(&self, netdir: Arc<NetDir>) -> Result<(), ReactorError> {
        let _old: Arc<NetDir> = self.replace_netdir(netdir).await;

        self.recompute_hs_dirs().await?;

        Ok(())
    }

    /// Maybe note a change in our list of HsDirs.
    async fn handle_hs_dir_change(&mut self, netdir: Arc<NetDir>) -> Result<(), ReactorError> {
        todo!()
    }

    /// Recompute the HsDirs for both the current and the previous time period.
    async fn recompute_hs_dirs(&self) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        inner.current_period.recompute_hs_dirs(&inner.netdir)?;

        if let Some(previous_period) = inner.previous_period.as_mut() {
            previous_period.recompute_hs_dirs(&inner.netdir)?;
        }

        Ok(())
    }

    /// Replace the old netdir with the new, returning the old.
    async fn replace_netdir(&self, new_netdir: Arc<NetDir>) -> Arc<NetDir> {
        std::mem::replace(&mut self.inner.lock().await.netdir, new_netdir)
    }

    /// Handle an incoming [`Event`].
    async fn handle_event(&self, ev: Event) -> Result<(), ReactorError> {
        match ev {
            Event::NewIntroPoints(ipts) => self.handle_new_intro_points(ipts).await,
            Event::NewKeys(_keys) => self.handle_new_keys().await,
            Event::SvcConfigChange(config) => self.handle_svc_config_change(config).await,
            Event::TimePeriodChange((hs_blind_id, time_period)) => {
                self.handle_new_tp(hs_blind_id, time_period).await
            }
        }
    }

    /// Update our list of introduction points.
    #[allow(clippy::unnecessary_wraps)]
    async fn handle_new_intro_points(&self, ipts: Vec<Ipt>) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().await;

        inner.descriptor.ipts(ipts);

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

    /// Handle the start of a new time period.
    async fn handle_new_tp(
        &self,
        hsid: HsBlindId,
        time_period: TimePeriod,
    ) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().await;

        inner.register_new_period(time_period, hsid)?;

        Ok(())
    }

    /// Try to upload our descriptor to the HsDirs that need it.
    ///
    /// If we've recently uploaded some descriptors, we return immediately and schedule the upload
    /// to happen N minutes from now.
    //
    // TODO HSS: what is N?
    //
    // TODO HSS: should this spawn upload tasks instead of blocking the reactor until the
    // uploads complete? How would that work - if, during an upload, we receive an event telling us
    // to update the descriptor, do we cancel the existing upload tasks, or do we let them carry
    // on?
    async fn upload_all(&self) -> Result<(), ReactorError> {
        let last_uploaded = self.inner.lock().await.last_uploaded;
        let now = SystemTime::now();

        // Check if we should rate-limit this upload.
        if let Some(last_uploaded) = last_uploaded {
            let duration_since_upload = last_uploaded
                .duration_since(now)
                .unwrap_or(Duration::from_secs(0));

            if duration_since_upload < UPLOAD_RATE_LIM_THRESHOLD {
                return self.schedule_pending_upload().await;
            }
        }

        self.upload_for_time_period(true).await?;
        self.upload_for_time_period(false).await?;

        self.inner.lock().await.last_uploaded = Some(SystemTime::now());

        Ok(())
    }

    /// Tell the "upload reminder" task to remind us about a pending upload.
    async fn schedule_pending_upload(&self) -> Result<(), ReactorError> {
        if let Err(e) = self
            .pending_upload_tx
            .broadcast(UPLOAD_RATE_LIM_THRESHOLD)
            .await
        {
            // TODO HSS: return an error
            debug!("failed to schedule upload reattempt");
        }

        Ok(())
    }

    /// Upload the descriptor for the current or previous time period.
    //
    // TODO HSS: perhaps `current` should be an enum rather than a bool
    #[allow(unreachable_code)] // TODO HSS: remove
    #[allow(clippy::diverging_sub_expression)] // TODO HSS: remove
    async fn upload_for_time_period(&self, current: bool) -> Result<(), ReactorError> {
        let mut inner = self.inner.lock().await;

        // First, grab the time period-specific context.
        let context = if current {
            &mut inner.current_period
        } else if let Some(previous_period) = inner.previous_period.as_mut() {
            previous_period
        } else {
            // Nothing to do
            return Ok(());
        };

        // Figure out which HsDirs we need to upload the descriptor to (some of them might already
        // have our latest descriptor, so we filter them out).
        let hs_dirs = context
            .hs_dirs
            .iter_mut()
            .filter(|(_relay_id, status)| *status == DescriptorStatus::Dirty);

        // Check we have enough information to generate the descriptor before proceeding.
        let hsdesc = match inner.descriptor.build() {
            Ok(desc) => {
                let blind_id_kp = todo!();
                let mut rng = self.mockable.thread_rng();

                desc.build_sign(self.hsid_key, blind_id_kp, context.period, &mut rng)?;
            }
            Err(e) => {
                trace!(hsid=%self.hsid, "not enough information to build descriptor, skipping upload: {e}");
                return Ok(());
            }
        };

        for (relay_ids, status) in hs_dirs {
            let Some(hsdir) = inner.netdir.by_ids(&*relay_ids) else {
                // This should never happen (all of our relay_ids are from the stored netdir).
                return Err(internal!(
                    "tried to upload descriptor to relay not found in consensus?"
                )
                .into());
            };

            // `inner` is an async-aware mutex so we can hold it across this await point
            self.upload_descriptor_with_retries(hsdesc, inner.netdir, &hsdir)
                .await?;

            // We successfully uploaded the descriptor to this HsDir, so we now mark it as clean
            // for that specific HsDir.
            *status = DescriptorStatus::Clean;
        }

        Ok(())
    }

    /// Upload a descriptor to the specified HSDir.
    async fn upload_descriptor(
        &self,
        hsdesc: String,
        netdir: Arc<NetDir>,
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
                &netdir,
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
    async fn upload_descriptor_with_retries(
        &self,
        _hsdesc: String,
        _netdir: Arc<NetDir>,
        _hsdir: &Relay<'_>,
    ) -> Result<(), ReactorError> {
        todo!();
    }
}
