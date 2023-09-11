//! IPT Manager
//!
//! Maintains introduction points and publishes descriptors.
//! Provides a stream of rendezvous requests.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use futures::channel::{mpsc, oneshot};
use futures::task::SpawnExt as _;
use futures::{future, select_biased};
use futures::{FutureExt as _, SinkExt as _, StreamExt as _};

use educe::Educe;
use postage::watch;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, trace, warn};
use void::{ResultVoidErrExt as _, Void};

use tor_basic_utils::RngExt as _;
use tor_circmgr::hspool::HsCircPool;
use tor_error::error_report;
use tor_error::{internal, into_internal, Bug};
use tor_hscrypto::pk::{HsIntroPtSessionIdKeypair, HsSvcNtorKey};
use tor_linkspec::{HasRelayIds as _, RelayIds};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::util::rand_compat::RngCompatExt as _;
use tor_netdir::NetDirProvider;
use tor_rtcompat::Runtime;

use crate::ipt_set::{self, IptsManagerView, PublishIptSet};
use crate::svc::ipt_establish;
use crate::timeout_track::{TrackingInstantOffsetNow, TrackingNow};
use crate::{FatalError, HsNickname, IptLocalId, OnionServiceConfig, RendRequest, StartupError};
use ipt_establish::{IptEstablisher, IptParameters, IptStatus, IptStatusStatus, IptWantsToRetire};

use IptStatusStatus as ISS;
use TrackedStatus as TS;

/// Time for which we'll use an IPT relay before selecting a new relay to be our IPT
// TODO HSS IPT_RELAY_ROTATION_TIME should be tuneable.  And, is default correct?
const IPT_RELAY_ROTATION_TIME: RangeInclusive<Duration> = {
    /// gosh this is clumsy
    const DAY: u64 = 86400;
    Duration::from_secs(DAY * 4)..=Duration::from_secs(DAY * 7)
};

/// Expiry time to put on an interim descriptor (IPT publication set Uncertain)
// TODO HSS IPT_PUBLISH_UNCERTAIN configure? get from netdir?
const IPT_PUBLISH_UNCERTAIN: Duration = Duration::from_secs(30 * 60); // 30 mins
/// Expiry time to put on a final descriptor (IPT publication set Certain
// TODO HSS IPT_PUBLISH_CERTAIN configure? get from netdir?
const IPT_PUBLISH_CERTAIN: Duration = Duration::from_secs(12 * 3600); // 12 hours

/// IPT Manager (for one hidden service)
#[derive(Educe)]
#[educe(Debug(bound))]
pub(crate) struct IptManager<R, M> {
    /// Immutable contents
    imm: Immutable<R>,

    /// Mutable state
    state: State<R, M>,
}

/// Immutable contents of an IPT Manager
///
/// Contains things inherent to our identity, and
/// handles to services that we'll be using.
#[derive(Educe)]
#[educe(Debug(bound))]
pub(crate) struct Immutable<R> {
    /// Runtime
    #[educe(Debug(ignore))]
    runtime: R,

    /// Netdir provider
    #[educe(Debug(ignore))]
    dirprovider: Arc<dyn NetDirProvider>,

    /// Nickname
    nick: HsNickname,

    /// Output MPSC for rendezvous requests
    ///
    /// Passed to IPT Establishers we create
    output_rend_reqs: mpsc::Sender<RendRequest>,

    /// Internal channel for updates from IPT Establishers (sender)
    ///
    /// When we make a new `IptEstablisher` we use this arrange for
    /// its status updates to arrive, appropriately tagged, via `status_recv`
    status_send: mpsc::Sender<(IptLocalId, IptStatus)>,
}

/// State of an IPT Manager
#[derive(Debug)]
pub(crate) struct State<R, M> {
    /// Configuration
    config: Arc<OnionServiceConfig>,

    /// Channel for updates from IPT Establishers (receiver)
    ///
    /// We arrange for all the updates to be multiplexed,
    /// as that makes handling them easy in our event loop.
    status_recv: mpsc::Receiver<(IptLocalId, IptStatus)>,

    /// State: selected relays
    ///
    /// We append to this, and call `retain` on it,
    /// so these are in chronological order of selection.
    irelays: Vec<IptRelay>,

    /// Did we fail to select a relay last time?
    ///
    /// This can only be caused (or triggered) by a busted netdir or config.
    last_irelay_selection_outcome: Result<(), ()>,

    /// Signal for us to shut down
    shutdown: oneshot::Receiver<Void>,

    /// Mockable state, normally [`Real`]
    ///
    /// This is in `State` so it can be passed mutably to tests,
    /// even though the main code doesn't need `mut`
    /// since `HsCircPool` is a service with interior mutability.
    mockable: M,

    /// Runtime (to placate compiler)
    runtime: PhantomData<R>,
}

/// Mockable state in an IPT Manager - real version
#[derive(Educe)]
#[educe(Debug)]
pub(crate) struct Real<R: Runtime> {
    /// Circuit pool for circuits we need to make
    ///
    /// Passed to the each new Establisher
    #[educe(Debug(ignore))]
    pub(crate) circ_pool: Arc<HsCircPool<R>>,
}

/// One selected relay, at which we are establishing (or relavantly advertised) IPTs
#[derive(Debug)]
struct IptRelay {
    /// The actual relay
    relay: RelayIds,

    /// The retirement time we selected for this relay
    ///
    /// We use `SystemTime`, not `Instant`, because we will want to save it to disk.
    planned_retirement: SystemTime,

    /// IPTs at this relay
    ///
    /// At most one will have [`IsCurrent`].
    ///
    /// We append to this, and call `retain` on it,
    /// so these are in chronological order of selection.
    ipts: Vec<Ipt>,
}

/// TODO HSS surely this should be `tor_proto::crypto::handshake::ntor::NtorSecretKey` ?
///
/// But that is private?
/// Also it has a strange name, for something which contains both private and public keys.
#[derive(Clone, Debug)]
struct NtorKeyPair {}

impl NtorKeyPair {
    /// TODO HSS document or replace
    fn public(&self) -> HsSvcNtorKey {
        todo!() // TODO HSS implement, or get rid of NtorKeyPair, or something
    }

    /// TODO HSS document or replace
    fn generate(rng: &mut impl Rng) -> Self {
        todo!() // TODO HSS implement, or get rid of NtorKeyPair, or something
    }
}

/// One introduction point, representation in memory
#[derive(Debug)]
struct Ipt {
    /// Local persistent identifier
    lid: IptLocalId,

    /// Handle for the establisher; we keep this here just for its `Drop` action
    ///
    /// The real type is `M::IptEstablisher`.
    /// We use `Box<dyn Any>` to avoid propagating the `M` type parameter to `Ipt` etc.
    #[allow(dead_code)]
    establisher: Box<dyn Any + Send + Sync + 'static>,

    /// `KS_hs_ipt_sid`, `KP_hs_ipt_sid`
    k_sid: HsIntroPtSessionIdKeypair,

    /// `KS_hss_ntor`, `KP_hss_ntor`
    // TODO HSS how do we provide the private half to the recipients of our rend reqs?
    // It needs to be attached to each request, since the intro points have different
    // keys and the consumer of the rend req stream needs to use the right ones.
    k_hss_ntor: NtorKeyPair,

    /// Last information about how it's doing including timing info
    status_last: TrackedStatus,

    /// Until when ought we to try to maintain it
    ///
    /// For introduction points we are publishing,
    /// this is a copy of the value set by the publisher
    /// in the `IptSet` we share with the publisher,
    ///
    /// (`None` means the IPT has not been advertised at all yet.)
    ///
    /// We must duplicate the information because:
    ///
    ///  * We can't have it just live in the shared `IptSet`
    ///    because we need to retain it for no-longer-being published IPTs.
    ///
    ///  * We can't have it just live here because the publisher needs to update it.
    ///
    /// (An alternative would be to more seriously entangle the manager and publisher.)
    last_descriptor_expiry_including_slop: Option<Instant>,

    /// Is this IPT current - should we include it in descriptors ?
    ///
    /// `None` might mean:
    ///  * WantsToRetire
    ///  * We have >N IPTs and we have been using this IPT so long we want to rotate it out
    is_current: Option<IsCurrent>,
}

/// Last information from establisher about an IPT, with timing info added by us
#[derive(Debug)]
enum TrackedStatus {
    /// Corresponds to [`IptStatusStatus::Faulty`]
    Faulty,

    /// Corresponds to [`IptStatusStatus::Establishing`]
    Establishing {
        /// When we were told we started to establish, for calculating `time_to_establish`
        started: Instant,
    },

    /// Corresponds to [`IptStatusStatus::Good`]
    Good {
        /// How long it took to establish (if we could determine that information)
        ///
        /// Can only be `Err` in strange situations.
        time_to_establish: Result<Duration, ()>,

        /// Details, from the Establisher
        details: ipt_establish::GoodIptDetails,
    },
}

/// Token indicating that this introduction point is current (not Retiring)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
struct IsCurrent;

/// Record of intro point establisher state, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS remove
struct StateRecord {
    /// Relays
    ipt_relays: Vec<RelayRecord>,
}

/// Record of a selected intro point relay, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS remove
struct RelayRecord {
    /// Which relay?
    relay: RelayIds,
    /// The IPTs, including the current one and any still-wanted old ones
    ipts: Vec<IptRecord>,
}

/// Record of a single intro point, as stored on disk
#[derive(Serialize, Deserialize)]
#[allow(dead_code)] // TODO HSS remove
struct IptRecord {
    /// Used to find the cryptographic keys, amongst other things
    lid: IptLocalId,
    // TODO HSS other fields need to be here!
}

/// Return value from one call to the main loop iteration
enum ShutdownStatus {
    /// We should continue to operate this IPT manager
    Continue,
    /// We should shut down: the service, or maybe the whole process, is shutting down
    Terminate,
}

impl From<oneshot::Canceled> for ShutdownStatus {
    fn from(cancelled: oneshot::Canceled) -> ShutdownStatus {
        ShutdownStatus::Terminate
    }
}

impl rand::distributions::Distribution<IptLocalId> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> IptLocalId {
        IptLocalId(rng.gen())
    }
}

impl IptRelay {
    /// Get a reference to this IPT relay's current intro point state (if any)
    ///
    /// `None` means this IPT has no current introduction points.
    /// That might be, briefly, because a new intro point needs to be created;
    /// or it might be because we are retiring the relay.
    fn current_ipt(&self) -> Option<&Ipt> {
        self.ipts
            .iter()
            .find(|ipt| ipt.is_current == Some(IsCurrent))
    }

    /// Get a mutable reference to this IPT relay's current intro point state (if any)
    fn current_ipt_mut(&mut self) -> Option<&mut Ipt> {
        self.ipts
            .iter_mut()
            .find(|ipt| ipt.is_current == Some(IsCurrent))
    }

    /// Should this IPT Relay be retired ?
    ///
    /// This is determined by our IPT relay rotation time.
    fn should_retire(&self, now: &TrackingNow) -> bool {
        now > &self.planned_retirement
    }

    /// Make a new introduction point at this relay
    ///
    /// It becomes the current IPT.
    #[allow(unreachable_code, clippy::diverging_sub_expression)] // TODO HSS remove
    fn make_new_ipt<R: Runtime, M: Mockable<R>>(
        &mut self,
        imm: &Immutable<R>,
        mockable: &mut M,
    ) -> Result<(), FatalError> {
        let params = IptParameters {
            netdir_provider: imm.dirprovider.clone(),
            introduce_tx: imm.output_rend_reqs.clone(),
            // TODO HSS IntroPointId lacks a constructor and maybe should change anyway
            intro_pt_id: todo!(),
            target: self.relay.clone(),
            ipt_sid_keypair: todo!(),    // TODO HSS
            accepting_requests: todo!(), // TODO HSS
        };
        let (establisher, mut watch_rx) = mockable.make_new_ipt(imm, params)?;

        // we'll treat it as Establishing until we find otherwise
        let status_last = TS::Establishing {
            started: imm.runtime.now(),
        };

        let rng = mockable.thread_rng();
        let lid: IptLocalId = rng.gen();
        let k_hss_ntor = NtorKeyPair::generate(&mut rng);
        let k_sid = ed25519::Keypair::generate(&mut rng.rng_compat()).into();

        imm.runtime
            .spawn({
                let mut status_send = imm.status_send.clone();
                async move {
                    loop {
                        let Some(status) = watch_rx.next().await else {
                            trace!("HS service IPT status task: establisher went away");
                            break;
                        };
                        match status_send.send((lid, status)).await {
                            Ok(()) => {}
                            Err::<_, mpsc::SendError>(e) => {
                                // Not using trace_report because SendError isn't HasKind
                                trace!("HS service IPT status task: manager went away: {e}");
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|cause| FatalError::Spawn {
                spawning: "IPT establisher watch status task",
                cause: cause.into(),
            })?;

        let ipt = Ipt {
            lid,
            establisher: Box::new(establisher),
            k_hss_ntor,
            k_sid,
            status_last,
            last_descriptor_expiry_including_slop: None,
            is_current: Some(IsCurrent),
        };

        self.ipts.push(ipt);

        Ok(())
    }
}

impl Ipt {
    /// Returns `true` if this IPT has status Good (and should perhaps be published)
    fn is_good(&self) -> bool {
        match self.status_last {
            TS::Good { .. } => true,
            TS::Establishing { .. } | TS::Faulty => false,
        }
    }

    /// Construct the information needed by the publisher for this intro point
    fn for_publish(&self, details: &ipt_establish::GoodIptDetails) -> Result<ipt_set::Ipt, Bug> {
        let k_sid: &ed25519::Keypair = self.k_sid.as_ref();
        tor_netdoc::doc::hsdesc::IntroPointDesc::builder()
            .link_specifiers(details.link_specifiers.clone())
            .ipt_kp_ntor(details.ipt_kp_ntor)
            .kp_hs_ipt_sid(k_sid.public.into())
            .kp_hss_ntor(self.k_hss_ntor.public())
            .build()
            .map_err(into_internal!("failed to construct IntroPointDesc"))
    }
}

impl<R: Runtime, M: Mockable<R>> IptManager<R, M> {
    /// Create a new IptManager
    #[allow(clippy::unnecessary_wraps)] // TODO HSS remove
    pub(crate) fn new(
        runtime: R,
        dirprovider: Arc<dyn NetDirProvider>,
        nick: HsNickname,
        config: Arc<OnionServiceConfig>,
        output_rend_reqs: mpsc::Sender<RendRequest>,
        shutdown: oneshot::Receiver<Void>,
        mockable: M,
    ) -> Result<Self, StartupError> {
        // TODO HSS load persistent state

        // We don't need buffering; since this is written to by dedicated tasks which
        // are reading watches.
        let (status_send, status_recv) = mpsc::channel(0);

        let imm = Immutable {
            runtime,
            dirprovider,
            nick,
            status_send,
            output_rend_reqs,
        };
        let state = State {
            config,
            status_recv,
            mockable,
            shutdown,
            irelays: vec![],
            last_irelay_selection_outcome: Ok(()),
            runtime: PhantomData,
        };
        let mgr = IptManager { imm, state };

        Ok(mgr)
    }

    /// Send the IPT manager off to run and establish intro points
    pub(crate) fn launch_background_tasks(
        self,
        publisher: IptsManagerView,
    ) -> Result<(), StartupError> {
        let runtime = self.imm.runtime.clone();
        runtime
            .spawn(self.main_loop_task(publisher))
            .map_err(|cause| StartupError::Spawn {
                spawning: "ipt manager",
                cause: cause.into(),
            })?;
        Ok(())
    }

    /// Iterate over the current IPTs
    ///
    /// Yields each `IptRelay` at most once.
    fn current_ipts(&self) -> impl Iterator<Item = (&IptRelay, &Ipt)> {
        self.state
            .irelays
            .iter()
            .filter_map(|ir| Some((ir, ir.current_ipt()?)))
    }

    /// Iterate over the current IPTs in `Good` state
    fn good_ipts(&self) -> impl Iterator<Item = (&IptRelay, &Ipt)> {
        self.current_ipts().filter(|(_ir, ipt)| ipt.is_good())
    }
}

/// An error that happened while trying to select a relay
///
/// Used only within the IPT manager.
/// Can only be caused by bad netdir or maybe bad config.
#[derive(Debug, Error)]
enum ChooseIptError {
    /// Bad or insufficient netdir
    #[error("bad or insufficient netdir")]
    NetDir(#[from] tor_netdir::Error),
    /// Too few suitable relays
    #[error("too few suitable relays")]
    TooFewUsableRelays,
    /// Time overflow
    #[error("time overflow (system clock set wrong?)")]
    TimeOverflow,
    /// Internal error
    #[error("internal error")]
    Bug(#[from] Bug),
}

impl<R: Runtime, M: Mockable<R>> State<R, M> {
    /// Find the `Ipt` with persistent local id `lid`
    fn ipt_by_lid_mut(&mut self, needle: IptLocalId) -> Option<&mut Ipt> {
        self.irelays
            .iter_mut()
            .find_map(|ir| ir.ipts.iter_mut().find(|ipt| ipt.lid == needle))
    }

    /// Choose a new relay to use for IPTs
    fn choose_new_ipt_relay(
        &mut self,
        imm: &Immutable<R>,
        now: SystemTime,
    ) -> Result<(), ChooseIptError> {
        let netdir = imm.dirprovider.timely_netdir()?;

        let mut rng = self.mockable.thread_rng();

        let relay = netdir
            .pick_relay(
                &mut rng,
                tor_netdir::WeightRole::HsIntro,
                // TODO HSS should we apply any other conditions to the selected IPT?
                |new| {
                    new.is_hs_intro_point()
                        && !self
                            .irelays
                            .iter()
                            .any(|existing| new.has_any_relay_id_from(&existing.relay))
                },
            )
            .ok_or(ChooseIptError::TooFewUsableRelays)?;

        let retirement = rng
            .gen_range_checked(IPT_RELAY_ROTATION_TIME)
            .ok_or_else(|| internal!("IPT_RELAY_ROTATION_TIME range was empty!"))?;
        let retirement = now
            .checked_add(retirement)
            .ok_or(ChooseIptError::TimeOverflow)?;

        let new_irelay = IptRelay {
            relay: RelayIds::from_relay_ids(&relay),
            planned_retirement: retirement,
            ipts: vec![],
        };
        self.irelays.push(new_irelay);
        Ok(())
    }

    /// Update `self`'s status tracking for one introduction point
    fn handle_ipt_status_update(&mut self, imm: &Immutable<R>, lid: IptLocalId, update: IptStatus) {
        let Some(ipt) = self.ipt_by_lid_mut(lid) else {
            // update from now-withdrawn IPT, ignore it (can happen due to the IPT being a task)
            return;
        };

        let IptStatus {
            status: update,
            wants_to_retire,
            n_faults: _,
        } = update;

        #[allow(clippy::single_match)] // want to be explicit about the Ok type
        match wants_to_retire {
            Err(IptWantsToRetire) => ipt.is_current = None,
            Ok(()) => {}
        }

        let now = || imm.runtime.now();

        ipt.status_last = match update {
            ISS::Establishing => TS::Establishing { started: now() },
            ISS::Good(details) => {
                let time_to_establish = match &ipt.status_last {
                    TS::Establishing { started, .. } => {
                        // return () at end of ok_or_else closure, for clarity
                        #[allow(clippy::unused_unit, clippy::semicolon_if_nothing_returned)]
                        now().checked_duration_since(*started).ok_or_else(|| {
                            warn!("monotonic clock went backwards! (HS IPT)");
                            ()
                        })
                    }
                    other => {
                        error!("internal error: HS IPT went from {:?} to Good", &other);
                        Err(())
                    }
                };
                TS::Good {
                    time_to_establish,
                    details,
                }
            }
            ISS::Faulty => TS::Faulty,
        };
    }
}

// TODO HSS: Combine this block with the other impl IptManager<R, M>
// We probably want to make sure this whole file is in a sensible order.
impl<R: Runtime, M: Mockable<R>> IptManager<R, M> {
    /// Make some progress, if possible, and say when to wake up again
    ///
    /// Examines the current state and attempts to improve it.
    ///
    /// If `idempotently_progress_things_now` makes any changes,
    /// it will return `None`.
    /// It should then be called again immediately.
    ///
    /// Otherwise, it returns the time in the future when further work ought to be done:
    /// i.e., the time of the earliest timeout or planned future state change -
    /// as a [`TrackingNow`].
    ///
    /// In that case, the caller must call `compute_iptsetstatus_publish`,
    /// since the IPT set etc. may have changed.
    fn idempotently_progress_things_now(&mut self) -> Result<Option<TrackingNow>, FatalError> {
        /// Return value which means "we changed something, please run me again"
        ///
        /// In each case, if we make any changes which indicate we might
        /// want to restart, , we `return CONTINUE`, and
        /// our caller will just call us again.
        ///
        /// This approach simplifies the logic: everything here is idempotent.
        /// (It does mean the algorithm can be quadratic in the number of intro points,
        /// but that number is reasonably small for a modern computer and the constant
        /// factor is small too.)
        const CONTINUE: Result<Option<TrackingNow>, FatalError> = Ok(None);

        // This tracks everything we compare it to, using interior mutability,
        // so that if there is no work to do and no timeouts have expired,
        // we know when we will want to wake up.
        let now = TrackingNow::now(&self.imm.runtime);

        // ---------- collect garbage ----------

        // Rotate out an old IPT if we have >N good IPTs
        if self.good_ipts().count() >= self.target_n_intro_points() {
            for ir in &mut self.state.irelays {
                if ir.should_retire(&now) {
                    if let Some(ipt) = ir.current_ipt_mut() {
                        ipt.is_current = None;
                        return CONTINUE;
                    }
                }
            }
        }

        // Forget old IPTs (after the last descriptor mentioning them has expired)
        for ir in &mut self.state.irelays {
            // When we drop the Ipt we drop the IptEstablisher, withdrawing the intro point
            ir.ipts.retain(|ipt| {
                ipt.is_current.is_some()
                    || match ipt.last_descriptor_expiry_including_slop {
                        None => false,
                        Some(last) => now < last,
                    }
            });
            // No need to return CONTINUE, since there is no other future work implied
            // by discarding a non-current IPT.
        }

        // Forget retired IPT relays (all their IPTs are gone)
        self.state
            .irelays
            .retain(|ir| !(ir.should_retire(&now) && ir.ipts.is_empty()));
        // If we deleted relays, we might want to select new ones.  That happens below.

        // ---------- make progress ----------
        //
        // Consider selecting new relays and setting up new IPTs.

        // Create new IPTs at already-chosen relays
        for ir in &mut self.state.irelays {
            if !ir.should_retire(&now) && ir.current_ipt_mut().is_none() {
                // We don't have a current IPT at this relay, but we should.
                ir.make_new_ipt(&self.imm, &mut self.state.mockable)?;
                return CONTINUE;
            }
        }

        // Consider choosing a new IPT relay
        {
            // block {} prevents use of `n_good_ish_relays` for other (wrong) purposes

            // We optimistically count an Establishing IPT as good-ish;
            // specifically, for the purposes of deciding whether to select a new
            // relay because we don't have enough good-looking ones.
            let n_good_ish_relays = self
                .current_ipts()
                .filter(|(_ir, ipt)| match ipt.status_last {
                    TS::Good { .. } | TS::Establishing { .. } => true,
                    TS::Faulty => false,
                })
                .count();

            #[allow(clippy::unused_unit, clippy::semicolon_if_nothing_returned)] // in map_err
            if n_good_ish_relays < self.target_n_intro_points()
                && self.state.irelays.len() < self.max_n_intro_relays()
                && self.state.last_irelay_selection_outcome.is_ok()
            {
                self.state.last_irelay_selection_outcome = self
                    .state
                    .choose_new_ipt_relay(&self.imm, now.system_time().get_now_untracked())
                    .map_err(|error| {
                        error_report!(
                            error,
                            "HS service {} failed to select IPT relay",
                            &self.imm.nick,
                        );
                        ()
                    });
                return CONTINUE;
            }
        }

        //---------- caller (run_once) will update publisher, and wait ----------

        Ok(Some(now))
    }

    /// Import publisher's updates to latest descriptor expiry times
    ///
    /// Copies the `last_descriptor_expiry_including_slop` field
    /// from each ipt in `publish_set` to the corresponding ipt in `self`.
    fn import_new_expiry_times(&mut self, publish_set: &PublishIptSet) {
        let Some(publish_set) = publish_set else {
            // Nothing to update
            return;
        };

        // Every entry in the PublishIptSet corresponds to an ipt in self.
        // And the ordering is the same.  So we can do an O(N) merge-join.
        let all_ours = self
            .state
            .irelays
            .iter_mut()
            .flat_map(|ir| ir.ipts.iter_mut());

        for (_lid, ours, theirs) in merge_join_subset_by(
            all_ours,
            |ours| ours.lid,
            &publish_set.ipts,
            |theirs| theirs.lid,
        ) {
                ours.last_descriptor_expiry_including_slop =
                    theirs.last_descriptor_expiry_including_slop;
        }
    }

    /// Compute the IPT set to publish, and update the data shared with the publisher
    ///
    /// `now` is current time and also the earliest wakeup,
    /// which we are in the process of planning.
    /// The noted earliest wakeup can be updated by this function,
    /// for example, with a future time at which the IPT set ought to be published
    /// (eg, the status goes from Unknown to Uncertain).
    #[allow(clippy::unnecessary_wraps)] // for regularity
    fn compute_iptsetstatus_publish(
        &mut self,
        now: &TrackingNow,
        publish_set: &mut PublishIptSet,
    ) -> Result<(), FatalError> {
        //---------- tell the publisher what to announce ----------

        let very_recently: Option<TrackingInstantOffsetNow> = (|| {
            // on time overflow, don't treat any as started establishing very recently

            let fastest_good_establish_time = self
                .current_ipts()
                .filter_map(|(_ir, ipt)| match ipt.status_last {
                    TS::Good {
                        time_to_establish, ..
                    } => Some(time_to_establish.ok()?),
                    TS::Establishing { .. } | TS::Faulty => None,
                })
                .min()?;

            // TODO HSS is this the right guess for IPT establishment?
            // we could use circuit timings etc., but arguably the actual time to establish
            // our fastest IPT is a better estimator here (and we want an optimistic,
            // rather than pessimistic estimate).
            //
            // TODO HSS fastest_good_establish_time factor 2 should be tuneable
            let very_recently = fastest_good_establish_time.checked_mul(2)?;

            now.checked_sub(very_recently)
        })();

        let started_establishing_very_recently = || {
            self.current_ipts()
                .filter_map(|(_ir, ipt)| {
                    let started = match ipt.status_last {
                        TS::Establishing { started } => Some(started),
                        TS::Good { .. } | TS::Faulty => None,
                    }?;

                    (&started > very_recently.as_ref()?).then_some(())
                })
                .next()
        };

        *publish_set = if self.good_ipts().count() >= self.target_n_intro_points() {
            // "Certain" - we are sure of which IPTs we want to publish
            Some(self.publish_set(now, IPT_PUBLISH_CERTAIN)?)
        } else if self.good_ipts().next().is_none()
        /* !... .is_empty() */
        {
            // "Unknown" - we have no idea which IPTs to publish.
            None
        } else {
            // "Uncertain" - we have some IPTs we could publish, but we're not confident
            Some(self.publish_set(now, IPT_PUBLISH_UNCERTAIN)?)
        };

        // TODO HSS tell all the being-published IPTs to start accepting introductions

        //---------- store persistent state ----------

        // TODO HSS store persistent state

        Ok(())
    }

    /// Calculate `publish::IptSet`, given that we have decided to publish *something*
    ///
    /// Calculates set of ipts to publish, selecting up to the target `N`
    /// from the available good current IPTs.
    /// (Old, non-current IPTs, that we are trying to retire, are never published.)
    ///
    /// Updates each chosen `Ipt`'s `last_descriptor_expiry_including_slop`
    ///
    /// The returned `IptSet` set is in the same order as our data structure:
    /// firstly, by the ordering in `State.irelays`, and then within each relay,
    /// by the ordering in `IptRelay.ipts`.  Both of these are stable.
    #[allow(unreachable_code, clippy::diverging_sub_expression)] // TODO HSS remove
    fn publish_set(
        &self,
        now: &TrackingNow,
        lifetime: Duration,
    ) -> Result<ipt_set::IptSet, FatalError> {
        let expires = now
            .instant()
            // Our response to old descriptors expiring is handled by us checking
            // last_descriptor_expiry_including_slop in idempotently_progress_things_now
            .get_now_untracked()
            .checked_add(lifetime)
            .ok_or_else(|| internal!("time overflow calculating descriptor expiry"))?;

        /// Good candidate introduction point for publication
        type Candidate<'i> = &'i Ipt;

        let target_n = self.target_n_intro_points();

        let mut candidates: VecDeque<_> = self
            .state
            .irelays
            .iter()
            .filter_map(|ir: &_| -> Option<Candidate<'_>> {
                let current_ipt = ir.current_ipt()?;
                if !current_ipt.is_good() {
                    return None;
                }
                Some(current_ipt)
            })
            .collect();

        // Take the last N good IPT relays
        //
        // The way we manage irelays means that this is always
        // the ones we selected most recently.
        //
        // TODO SPEC  Publication strategy when we have more than >N IPTs
        //
        // We could have a number of strategies here.  We could take some timing
        // measurements, or use the establishment time, or something; but we don't
        // want to add distinguishability.
        //
        // Another concern is manipulability, but
        // We can't be forced to churn because we don't remove relays
        // from our list of relays to try to use, other than on our own schedule.
        // But we probably won't want to be too reactive to the network environment.
        //
        // Since we only choose new relays when old ones are to retire, or are faulty,
        // choosing the most recently selected, rather than the least recently,
        // has the effect of preferring relays we don't know to be faulty,
        // to ones we have considered faulty least once.
        //
        // That's better than the opposite.  Also, choosing more recently selected relays
        // for publication may slightly bring forward the time at which all descriptors
        // mentioning that relay have expired, and then we can forget about it.
        while candidates.len() > target_n {
            // WTB: VecDeque::truncate_front
            let _: Candidate = candidates.pop_front().expect("empty?!");
        }

        let new_last_expiry = expires
            .checked_add(ipt_set::IPT_PUBLISH_EXPIRY_SLOP)
            .ok_or_else(|| internal!("time overflow adding expiry slop"))?;

        let ipts = candidates
            .into_iter()
            .map(|current_ipt| {
                let TS::Good { details, .. } = &current_ipt.status_last else {
                    return Err(internal!("was good but now isn't?!").into());
                };

                let publish = current_ipt.for_publish(details)?;

                // last_descriptor_expiry_including_slop was earlier merged in from
                // the previous IptSet, and here we copy it back
                let publish = ipt_set::IptInSet {
                    ipt: publish,
                    lid: current_ipt.lid,
                    last_descriptor_expiry_including_slop: current_ipt
                        .last_descriptor_expiry_including_slop,
                };

                Ok::<_, FatalError>(publish)
            })
            .collect::<Result<_, _>>()?;

        Ok(ipt_set::IptSet { ipts, lifetime })
    }

    /// Run one iteration of the loop
    ///
    /// Either do some work, making changes to our state,
    /// or, if there's nothing to be done, wait until there *is* something to do.
    async fn run_once(
        &mut self,
        // This is a separate argument for borrowck reasons
        publisher: &mut IptsManagerView,
    ) -> Result<ShutdownStatus, FatalError> {
        let mut publish_set = publisher.borrow_for_update();

        self.import_new_expiry_times(&publish_set);

        let now = loop {
            if let Some(now) = self.idempotently_progress_things_now()? {
                break now;
            }
        };

        self.compute_iptsetstatus_publish(&now, &mut publish_set)?;

        drop(publish_set); // release lock, and notify publisher of any changes

        select_biased! {
            () = now.wait_for_earliest(&self.imm.runtime).fuse() => {},
            shutdown = &mut self.state.shutdown => return Ok(shutdown.void_unwrap_err().into()),

            update = self.state.status_recv.next() => {
                let (lid, update) = update.ok_or_else(|| internal!("update mpsc ended!"))?;
                self.state.handle_ipt_status_update(&self.imm, lid, update);
            }

            _dir_event = async {
                match self.state.last_irelay_selection_outcome {
                    Ok(()) => future::pending().await,
                    // This boxes needlessly but it shouldn't really happen
                    Err(()) => self.imm.dirprovider.events().next().await,
                }
            }.fuse() => {
                self.state.last_irelay_selection_outcome = Ok(());
            }

            // TODO HSS clear last_irelay_selection_outcome on new configuration
        }

        Ok(ShutdownStatus::Continue)
    }

    /// IPT Manager main loop, runs as a task
    ///
    /// Contains the error handling, including catching panics.
    async fn main_loop_task(mut self, mut publisher: IptsManagerView) {
        loop {
            match async {
                AssertUnwindSafe(self.run_once(&mut publisher))
                    .catch_unwind()
                    .await
                    .map_err(|_: Box<dyn Any + Send>| internal!("IPT manager crashed"))?
            }
            .await
            {
                Err(crash) => {
                    error!("HS service {} crashed! {}", &self.imm.nick, crash);
                    break;
                }
                Ok(ShutdownStatus::Continue) => continue,
                Ok(ShutdownStatus::Terminate) => break,
            }
        }
    }

    /// Target number of intro points
    pub(crate) fn target_n_intro_points(&self) -> usize {
        self.state.config.num_intro_points.into()
    }

    /// Maximum number of concurrent intro point relays
    pub(crate) fn max_n_intro_relays(&self) -> usize {
        // TODO HSS max_n_intro_relays should be configurable
        // TODO HSS consider default, in context of intro point forcing attacks
        self.target_n_intro_points() * 2
    }
}

/// Mockable state for the IPT Manager
///
/// This allows us to use a fake IPT Establisher and IPT Publisher,
/// so that we can unit test the Manager.
pub(crate) trait Mockable<R>: Debug + Send + Sync + Sized + 'static {
    /// IPT establisher type
    type IptEstablisher: Send + Sync + 'static;

    /// A random number generator
    type Rng: rand::Rng + rand::CryptoRng;

    /// Return a random number generator
    fn thread_rng(&self) -> Self::Rng;

    /// Call `IptEstablisher::new`
    fn make_new_ipt(
        &mut self,
        imm: &Immutable<R>,
        params: IptParameters,
    ) -> Result<(Self::IptEstablisher, watch::Receiver<IptStatus>), FatalError>;

    /// Call `Publisher::new_intro_points`
    fn new_intro_points(&mut self, ipts: ()) {
        todo!() // TODO HSS there should be no default impl; code should be in Real's impl
    }
}

impl<R: Runtime> Mockable<R> for Real<R> {
    type IptEstablisher = IptEstablisher;

    /// A random number generator
    type Rng = rand::rngs::ThreadRng;

    /// Return a random number generator
    fn thread_rng(&self) -> Self::Rng {
        rand::thread_rng()
    }

    fn make_new_ipt(
        &mut self,
        imm: &Immutable<R>,
        params: IptParameters,
    ) -> Result<(Self::IptEstablisher, watch::Receiver<IptStatus>), FatalError> {
        IptEstablisher::new(imm.runtime.clone(), params, self.circ_pool.clone())
    }
}

/// Joins two iterators, by keys, one of which is a subset of the other
///
/// `bigger` and `smaller` are iterators yielding `BI` and `SI`.
///
/// The key `K`, which can be extracted from each element of either iterator,
/// is `PartialEq` and says whether a `BI` is "the same as" an `SI`.
///
/// `call` is called for each `K` which appears in both lists, in that same order.
/// Nothing is done about elements which are only in `bigger`.
///
/// (The behaviour with duplicate entries is unspecified.)
///
/// The algorithm has complexity `O(N_bigger)`,
/// and also a working set of `O(N_bigger)`.
fn merge_join_subset_by<'out, K, BI, SI>(
    bigger: impl IntoIterator<Item = BI> + 'out,
    bigger_keyf: impl Fn(&BI) -> K + 'out,
    smaller: impl IntoIterator<Item = SI> + 'out,
    smaller_keyf: impl Fn(&SI) -> K + 'out,
) -> impl Iterator<Item = (K, BI, SI)> + 'out
where
    K: Eq + Hash + Clone + 'out,
    BI: 'out,
    SI: 'out,
{
    let mut smaller: HashMap<K, SI> = smaller
        .into_iter()
        .map(|si| (smaller_keyf(&si), si))
        .collect();

    bigger.into_iter().filter_map(move |bi| {
        let k = bigger_keyf(&bi);
        let si = smaller.remove(&k)?;
        Some((k, bi, si))
    })
}

// TODO HSS add unit tests for IptManager
// Especially, we want to exercise all code paths in idempotently_progress_things_now
