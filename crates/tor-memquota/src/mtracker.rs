//! Memory quota tracker, core and low-level API
//!
//! # Example
//!
//! ```cfg(feature = "memquota")
//! use std::{collections::VecDeque, sync::{Arc, Mutex}};
//! use tor_rtcompat::{CoarseInstant, CoarseTimeProvider, PreferredRuntime};
//! use tor_memquota::{mtracker, MemoryQuotaTracker, MemoryReclaimedError, EnabledToken};
//! use void::{ResultVoidExt, Void};
//!
//! #[derive(Debug)]
//! struct TrackingQueue(Mutex<Result<Inner, MemoryReclaimedError>>);
//! #[derive(Debug)]
//! struct Inner {
//!     partn: mtracker::Participation,
//!     data: VecDeque<(Box<[u8]>, CoarseInstant)>,
//! }
//!
//! impl TrackingQueue {
//!     fn push(&self, now: CoarseInstant, bytes: Box<[u8]>) -> Result<(), MemoryReclaimedError> {
//!         let mut inner = self.0.lock().unwrap();
//!         let inner = inner.as_mut().map_err(|e| e.clone())?;
//!         inner.partn.claim(bytes.len())?;
//!         inner.data.push_back((bytes, now));
//!         Ok(())
//!     }
//! }
//!
//! impl mtracker::IsParticipant for TrackingQueue {
//!     fn get_oldest(&self, _: EnabledToken) -> Option<CoarseInstant> {
//!         let inner = self.0.lock().unwrap();
//!         Some(inner.as_ref().ok()?.data.front()?.1)
//!     }
//!     fn reclaim(self: Arc<Self>, _: EnabledToken) -> mtracker::ReclaimFuture {
//!         let mut inner = self.0.lock().unwrap();
//!         *inner = Err(MemoryReclaimedError::new());
//!         Box::pin(async { mtracker::Reclaimed::Collapsing })
//!     }
//! }
//!
//! let runtime = PreferredRuntime::create().unwrap();
//! let config  = tor_memquota::Config::builder().max(1024*1024*1024).build().unwrap();
#![cfg_attr(
    feature = "memquota",
    doc = "let trk = MemoryQuotaTracker::new(&runtime, config).unwrap();"
)]
#![cfg_attr(
    not(feature = "memquota"),
    doc = "let trk = MemoryQuotaTracker::new_noop();"
)]
//!
//! let account = trk.new_account(None).unwrap();
//!
//! let queue: Arc<TrackingQueue> = account.register_participant_with(
//!     runtime.now_coarse(),
//!     |partn| {
//!         Ok::<_, Void>((Arc::new(TrackingQueue(Mutex::new(Ok(Inner {
//!             partn,
//!             data: VecDeque::new(),
//!         })))), ()))
//!     },
//! ).unwrap().void_unwrap().0;
//!
//! queue.push(runtime.now_coarse(), Box::new([0; 24])).unwrap();
//! ```
//
// For key internal documentation about the data structure, see the doc comment for
// `struct State` (down in the middle of the file).

#![forbid(unsafe_code)] // if you remove this, enable (or write) miri tests (git grep miri)

use crate::internal_prelude::*;

use IfEnabled::*;

mod bookkeeping;
mod reclaim;
mod total_qty_notifier;

#[cfg(all(test, feature = "memquota", not(miri) /* coarsetime */))]
pub(crate) mod test;

use bookkeeping::{BookkeepableQty, ClaimedQty, ParticipQty, TotalQty};
use total_qty_notifier::TotalQtyNotifier;

/// Maximum amount we'll "cache" locally in a [`Participation`]
///
/// ie maximum value of `Participation.cache`.
//
// TODO is this a good amount? should it be configurable?
pub(crate) const MAX_CACHE: Qty = Qty(16384);

/// Target cache size when we seem to be claiming
const TARGET_CACHE_CLAIMING: Qty = Qty(MAX_CACHE.as_usize() * 3 / 4);
/// Target cache size when we seem to be releasing
#[allow(clippy::identity_op)] // consistency
const TARGET_CACHE_RELEASING: Qty = Qty(MAX_CACHE.as_usize() * 1 / 4);

//---------- public data types ----------

/// Memory data tracker
///
/// Instance of the memory quota system.
///
/// Usually found as `Arc<MemoryQuotaTracker>`.
#[derive(Debug)]
pub struct MemoryQuotaTracker {
    /// The actual tracker state etc.
    state: IfEnabled<Mutex<State>>,
}

/// Handle onto an Account
///
/// An `Account` is a handle.  All clones refer to the same underlying conceptual Account.
///
/// `Account`s are created using [`MemoryQuotaTracker::new_account`].
///
/// # Use in Arti
///
/// In Arti, we usually use a newtype around `Account`, rather than a bare `Account`.
/// See `tor_proto::memquota`.
#[derive(Educe)]
#[educe(Debug)]
pub struct Account(IfEnabled<AccountInner>);

/// Contents of an enabled [`Account`]
#[derive(Educe)]
#[educe(Debug)]
pub struct AccountInner {
    /// The account ID
    aid: refcount::Ref<AId>,

    /// The underlying tracker
    #[educe(Debug(ignore))]
    tracker: Arc<MemoryQuotaTracker>,
}

/// Weak handle onto an Account
///
/// Like [`Account`], but doesn't keep the account alive.
/// Must be upgraded before use.
//
// Doesn't count for ARecord.account_clones
//
// We can't lift out Arc, so that the caller sees `Arc<Account>`,
// because an Account is Arc<MemoryQuotaTracker> plus AId,
// not Arc of something account-specific.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct WeakAccount(IfEnabled<WeakAccountInner>);

/// Contents of an enabled [`WeakAccount`]
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct WeakAccountInner {
    /// The account ID
    aid: AId,

    /// The underlying tracker
    #[educe(Debug(ignore))]
    tracker: Weak<MemoryQuotaTracker>,
}

/// Handle onto a participant's participation in a tracker
///
/// `Participation` is a handle.  All clones are for use by the same conceptual Participant.
/// It doesn't keep the underlying Account alive.
///
/// `Participation`s are created by registering new participants,
/// for example using [`Account::register_participant`].
///
/// Variables of this type are often named `partn`.
#[derive(Debug)]
pub struct Participation(IfEnabled<ParticipationInner>);

/// Contents of an enabled [`Participation`]
#[derive(Debug)]
pub struct ParticipationInner {
    /// Participant id
    pid: refcount::Ref<PId>,

    /// Account id
    aid: AId,

    /// The underlying tracker
    tracker: Weak<MemoryQuotaTracker>,

    /// Quota we have preemptively claimed for use by this Account
    ///
    /// Has been added to `PRecord.used`,
    /// but not yet returned by `Participation::claim`.
    ///
    /// This cache field arranges that most of the time we don't have to hammer a
    /// single cache line.
    ///
    /// The value here is bounded by a configured limit.
    ///
    /// Invariants on memory accounting:
    ///
    ///  * `Participation.cache < configured limit`
    ///  * `PRecord.used = Participation.cache + Σ Participation::claim - Σ P'n::release`
    ///    except if `PRecord` has been deleted
    ///    (ie when we aren't tracking any more and think the Participant is `Collapsing`).
    ///  * `Σ PRecord.used = State.total_used`
    ///
    /// Enforcement of these invariants is partially assured by
    /// types in [`bookkeeping`].
    cache: ClaimedQty,
}

/// Participants provide an impl of the hooks in this trait
///
/// Trait implemented by client of the memtrack API.
///
/// # Panic handling, "unwind safety"
///
/// If these methods panic, the memory tracker will tear down its records of the
/// participant, preventing future allocations.
///
/// But, it's not guaranteed that these methods on `IsParticipant` won't be called again,
/// even if they have already panicked on a previous occasion.
/// Thus the implementations might see "broken invariants"
/// as discussed in the docs for `std::panic::UnwindSafe`.
///
/// Nevertheless we don't make `RefUnwindSafe` a supertrait of `IsParticipant`.
/// That would force the caller to mark *all* their methods unwind-safe,
/// which is unreasonable (and probably undesirable).
///
/// Variables which are `IsParticipant` are often named `particip`.
pub trait IsParticipant: Debug + Send + Sync + 'static {
    /// Return the age of the oldest data held by this Participant
    ///
    /// `None` means this Participant holds no data.
    ///
    /// # Performance and reentrancy
    ///
    /// This function runs with the `MemoryQuotaTracker`'s internal global lock held.
    /// Therefore:
    ///
    ///  * It must be fast.
    ///  * it *must not* call back into methods from [`tracker`](crate::mtracker).
    ///  * It *must not* even `Clone` or `Drop` a [`MemoryQuotaTracker`],
    ///    [`Account`], or [`Participation`].
    fn get_oldest(&self, _: EnabledToken) -> Option<CoarseInstant>;

    /// Start memory reclamation
    ///
    /// The Participant should start to free all of its memory,
    /// and then return `Reclaimed::Collapsing`.
    //
    // In the future:
    //
    // Should free *at least* all memory at least as old as discard_...
    //
    // v1 of the actual implementation might not have `discard_everything_as_old_as`
    // and `but_can_stop_discarding_...`,
    // and might therefore only support Reclaimed::Collapsing
    fn reclaim(
        self: Arc<Self>,
        _: EnabledToken,
        // Future:
        // discard_everything_as_old_as_this: RoughTime,
        // but_can_stop_discarding_after_freeing_this_much: Qty,
    ) -> ReclaimFuture;
}

/// Future returned by the [`IsParticipant::reclaim`] reclamation request
pub type ReclaimFuture = Pin<Box<dyn Future<Output = Reclaimed> + Send + Sync>>;

/// Outcome of [`IsParticipant::reclaim`]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum Reclaimed {
    /// Participant is responding to reclamation by collapsing completely.
    ///
    /// All memory will be freed and `release`'d soon (if it hasn't been already).
    /// `MemoryQuotaTracker` should forget the Participant and all memory it used, right away.
    ///
    /// Currently this is the only supported behaviour.
    Collapsing,
    // Future:
    // /// Participant has now reclaimed some memory as instructed
    // ///
    // /// If this is not sufficient, tracker must call reclaim() again.
    // /// (We may not want to implement Partial right away but the API
    // /// ought to support it so let's think about it now, even if we don't implement it.)
    // Partial,
}

//---------- principal data structure ----------

slotmap::new_key_type! {
    /// Identifies an Account
    ///
    /// After an account is torn down, the `AId` becomes invalid
    /// and attempts to use it will give an error.
    ///
    /// The same `AId` won't be reused for a later Account.
    struct AId;

    /// Identifies a Participant within an Account
    ///
    /// Ie, PId is scoped within in the context of an account.
    ///
    /// As with `AId`, a `PId` is invalid after the
    /// participation is torn down, and is not reused.
    struct PId;
}

/// Memory tracker inner, including mutable state
///
/// # Module internal documentation
///
/// ## Data structure
///
///  * [`MemoryQuotaTracker`] contains mutex-protected `State`.
///  * The `State` contains a [`SlotMap`] of account records [`ARecord`].
///  * Each `ARecord` contains a `SlotMap` of participant records [`PRecord`].
///
/// The handles [`Account`], [`WeakAccount`], and [`Participation`],
/// each contain a reference (`Arc`/`Weak`) to the `MemoryQuotaTracker`,
/// and the necessary slotmap keys.
///
/// The `ARecord` and `PRecord` each contain a reference count,
/// which is used to clean up when all the handles are gone.
///
/// The slotmap keys which count for the reference count (ie, strong references)
/// are stored as [`refcount::Ref`],
/// which helps assure correct reference counting.
/// (Bare ids [`AId`] and [`PId`] are weak references.)
///
/// ## Data structure lookup
///
/// Given a reference to the tracker, and some ids, the macro `find_in_tracker!`
/// is used to obtain mutable references to the `ARecord` and (if applicable) `PRecord`.
///
/// ## Bookkeeping
///
/// We use separate types for quantities of memory in various "states",
/// rather than working with raw quantities.
///
/// The types, and the legitimate transactions, are in `bookkeeping`.
///
/// ## Reentrancy (esp. `Drop` and `Clone`)
///
/// When the handle structs are dropped or cloned, they must manipulate the refcount(s).
/// So they must take the lock.
/// Therefore, an `Account` and `Participation` may not be dropped with the lock held!
///
/// Internally, this is actually fairly straightforward:
/// we take handles by reference, and constructors only make them at the last moment on return,
/// so our internal code here, in this module, doesn't have owned handles.
///
/// We also need to worry about reentrantly reentering the tracker code, from user code.
/// The user supplies a `dyn IsParticipant`.
/// The principal methods are from [`IsParticipant`],
/// for which we handle reentrancy in the docs.
/// But we also implicitly invoke its `Drop` impl, which might in turn drop stuff of ours,
/// such as [`Account`]s and [`Participation`]s, whose `Drop` impls need to take our lock.
/// To make sure this isn't done reentrantly, we have a special newtype around it,
/// and defer some of our drops during reclaim.
/// That's in `drop_reentrancy` and `tracker::reclaim::deferred_drop`.
///
/// The `Debug` impl isn't of concern, since we don't call it ourselves.
/// And we don't rely on it being `Clone`, since it's in an `Arc`.
///
/// ## Drop bombs
///
/// With `#[cfg(test)]`, several of our types have "drop bombs":
/// they cause a panic if dropped inappropriately.
/// This is intended to detect bad code paths during testing.
#[derive(Debug, Deref, DerefMut)]
struct State {
    /// Global parts of state
    ///
    /// Broken out to allow passing both
    /// `&mut Global` and `&mut ARecord`/`&mut PRecord`
    /// to some function(s).
    #[deref]
    #[deref_mut]
    global: Global,

    /// Accounts
    accounts: SlotMap<AId, ARecord>,
}

/// Global parts of `State`
#[derive(Debug)]
struct Global {
    /// Total memory used
    ///
    /// Wrapper type for ensuring we wake up the reclamation task
    total_used: TotalQtyNotifier,

    /// Configuration
    config: ConfigInner,

    /// Make this type uninhabited if memory tracking is compiled out
    #[allow(dead_code)]
    enabled: EnabledToken,
}

/// Account record, within `State.accounts`
#[derive(Debug)]
#[must_use = "don't just drop, call auto_release"]
struct ARecord {
    /// Number of clones of `Account`; to know when to tear down the account
    refcount: refcount::Count<AId>,

    /// Child accounts
    children: Vec<AId>,

    /// Participants linked to this Account
    ps: SlotMap<PId, PRecord>,

    /// Make this type uninhbaited if memory tracking is compiled out
    #[allow(dead_code)]
    enabled: EnabledToken,
}

/// Participant record, within `ARecord.ps`
#[derive(Debug)]
#[must_use = "don't just drop, call auto_release"]
struct PRecord {
    /// Number of clones of `Participation`; to know when to tear down the participant
    refcount: refcount::Count<PId>,

    /// Memory usage of this participant
    ///
    /// Not 100% accurate, can lag, and be (boundedly) an overestimate
    used: ParticipQty,

    /// The hooks provided by the Participant
    particip: drop_reentrancy::ProtectedWeak<dyn IsParticipant>,

    /// Make this type uninhabited if memory tracking is compiled out
    #[allow(dead_code)]
    enabled: EnabledToken,
}

//#################### IMPLEMENTATION ####################

/// Given a `&Weak<MemoryQuotaTracker>`, find an account and maybe participant
///
/// ### Usage templates
///
/// ```rust,ignore
/// find_in_tracker! {
///     enabled;
///     weak_tracker => + tracker, state;
///     aid => arecord;
///   [ pid => precord; ]
///   [ ?Error | ?None ]
/// };
///
/// find_in_tracker! {
///     enabled;
///     strong_tracker => state;
///     .. // as above
/// };
/// ```
///
/// ### Input expressions (value arguments to the macro0
///
///  * `weak_tracker: &Weak<MemoryQuotaTracker>` (or equivalent)
///  * `strong_tracker: &MemoryQuotaTracker` (or equivalent)
///  * `enabled: EnabledToken` (or equivalent)
///  * `aid: AId`
///  * `pid: PId`
///
/// ### Generated bindings (identifier arguments to the macro)
///
///  * `tracker: Arc<MemoryQuotaTracker>`
///  * `state: &mut State` (borrowed from a `MutexGuard<State>` borrowed from `tracker`)
///  * `arecord: &mut ARecord` (mut borrowed from `state.accounts`)
///  * `precord: &mut PRecord` (mut borrowed from `arecord.ps`)
///
/// There is no access to the `MutexGuard` itself.
/// For control of the mutex release point, place `find_in_tracker!` in an enclosing block.
///
/// ### Error handling
///
/// If the tracker, account, or participant, can't be found,
/// the macro returns early from the enclosing scope (using `?`).
///
/// If `Error` is specified, applies `?` to `Err(Error::...)`.
/// If `None` is specified, just returns `None` (by applying `?` to None`).
//
// This has to be a macro because it makes a self-referential set of bindings.
// Input syntax is a bit janky because macro_rules is so bad.
// For an internal macro with ~9 call sites it's not worth making a big parsing contraption.
macro_rules! find_in_tracker { {
    // This `+` is needed because otherwise it's LL1-ambiguous and macro_rules can't cope
    $enabled:expr;
    $tracker_input:expr => $( + $tracker:ident, )? $state:ident;
    $aid:expr => $arecord:ident;
 $( $pid:expr => $precord:ident; )?
    // Either `Error` or None, to be passed to `find_in_tracker_eh!($eh ...: ...)`
    // (We need this to be an un-repeated un-optional binding, because
    // it is used within some other $( ... )?, and macro_rules gets confused.)
    ? $eh:tt
} => {
    let tracker = &$tracker_input;
  $(
    let $tracker: Arc<MemoryQuotaTracker> = find_in_tracker_eh!(
        $eh Error::TrackerShutdown;
        tracker.upgrade()
    );
    let tracker = &$tracker;
  )?
    let _: &EnabledToken = &$enabled;
    let state = find_in_tracker_eh!(
        $eh Error::Bug(internal!("noop MemoryQuotaTracker found via enabled datastructure"));
        tracker.state.as_enabled()
    );
    let mut state: MutexGuard<State> = find_in_tracker_eh!(
        $eh Error::TrackerCorrupted;
        state.lock().ok()
    );
    let $state: &mut State = &mut *state;
    let aid: AId = $aid;
    let $arecord: &mut ARecord = find_in_tracker_eh!(
        $eh Error::AccountClosed;
        $state.accounts.get_mut(aid)
    );
  $(
    let pid: PId = $pid;
    let $precord: &mut PRecord = find_in_tracker_eh!(
        $eh Error::ParticipantShutdown;
        $arecord.ps.get_mut(pid)
    );
  )?
} }
/// Error handling helper for `find_in_tracker`
macro_rules! find_in_tracker_eh {
    { None $variant:expr; $result:expr } => { $result? };
    { Error $variant:expr; $result:expr } => { $result.ok_or_else(|| $variant)? };
}

//========== impls on public types, including public methods and trait impls ==========

//---------- MemoryQuotaTracker ----------

impl MemoryQuotaTracker {
    /// Set up a new `MemoryDataTracker`
    pub fn new<R: Spawn>(runtime: &R, config: Config) -> Result<Arc<Self>, StartupError> {
        let Enabled(config, enabled) = config.0 else {
            return Ok(MemoryQuotaTracker::new_noop());
        };

        let (reclaim_tx, reclaim_rx) =
            mpsc_channel_no_memquota(0 /* plus num_senders, ie 1 */);
        let total_used = TotalQtyNotifier::new_zero(reclaim_tx);

        let global = Global {
            total_used,
            config,
            enabled,
        };
        let accounts = SlotMap::default();
        let state = Enabled(Mutex::new(State { global, accounts }), enabled);
        let tracker = Arc::new(MemoryQuotaTracker { state });

        // We don't provide a separate `launch_background_tasks`, because this task doesn't
        // wake up periodically, or, indeed, do anything until the tracker is used.

        let for_task = Arc::downgrade(&tracker);
        runtime.spawn(reclaim::task(for_task, reclaim_rx, enabled))?;

        Ok(tracker)
    }

    /// Reconfigure
    pub fn reconfigure(
        &self,
        new_config: Config,
        how: tor_config::Reconfigure,
    ) -> Result<(), ReconfigureError> {
        use tor_config::Reconfigure;

        let state = self.lock().map_err(into_internal!(
            "cannot reconfigure corrupted memquota tracker"
        ))?;

        let (state, new_config) = match (state, new_config.0) {
            (Noop, Noop) => return Ok(()),
            (Noop, Enabled(..)) => return how.cannot_change(
                // TODO #1577 (3) this isn't the `field` wanted by `cannot_change`
 "tor-memquota max (`system.memory.max`) cannot be set: cannot enable memory quota tracking, when disabled at program start"
            ),
            (Enabled(state, _enabled), new_config) => {
                let new_config = new_config.into_enabled().unwrap_or(
                    // If the new configuration is "Noop", set the limit values to MAX
                    // so we will never think we want to reclaim.
                    // We don't replace ourselves with a Noop or something,
                    // in case the user wants to re-enable tracking.
                    ConfigInner {
                        max: Qty::MAX,
                        low_water: Qty::MAX,
                    },
                );

                (state, new_config)
            },
        };

        // Bind state mutably only if we're supposed to actually be modifying anything
        let mut state = match how {
            Reconfigure::CheckAllOrNothing => return Ok(()),
            Reconfigure::AllOrNothing | Reconfigure::WarnOnFailures => state,
            _ => Err(internal!("Reconfigure variant unknown! {how:?}"))?, // TODO #1577 (1)
        };

        let global = &mut state.global;
        global.config = new_config;

        // If the new limit is lower, we might need to start reclaiming:
        global.total_used.maybe_wakeup(&global.config);

        // If the new low_water is higher, we might need to *stop* reclaiming.
        // We don't have a way to abort an ongoing reclaim request,
        // but the usage vs low_water will be rechecked before we reclaim
        // from another Participant, which will be sufficient.

        Ok(())
    }

    /// Returns an estimate of the total memory use
    ///
    /// The returned value is:
    ///
    ///  * [Approximate.](../index.html#is-approximate)
    ///  * A snapshot as of the current moment (and there is no way to await changes)
    ///  * Always `usize::MAX` for a no-op tracker
    pub fn used_current_approx(&self) -> Result<usize, TrackerCorrupted> {
        let Enabled(state, _enabled) = self.lock()? else {
            return Ok(usize::MAX);
        };
        Ok(*state.total_used.as_raw())
    }

    /// Make a new `Account`
    ///
    /// To actually record memory usage, a Participant must be added.
    ///
    /// At most call sites, take an `Account` rather than a `MemoryQuotaTracker`,
    /// and use [`Account::new_child()`].
    /// That improves the ability to manage the hierarchy of Participants.
    //
    // Right now, parent can't be changed after construction of an Account,
    // so circular accounts are impossible.
    // But, we might choose to support that in the future.
    // Circular parent relationships might need just a little care
    // in the reclamation loop (to avoid infinitely looping),
    // but aren't inherently unsupportable.
    #[allow(clippy::redundant_closure_call)] // We have IEFEs for good reasons
    pub fn new_account(self: &Arc<Self>, parent: Option<&Account>) -> crate::Result<Account> {
        let Enabled(mut state, enabled) = self.lock()? else {
            return Ok(Account(Noop));
        };

        let parent_aid_good = parent
            .map(|parent| {
                // Find and check the requested parent's Accountid

                let Enabled(parent, _enabled) = &parent.0 else {
                    return Err(
                        internal!("used no-op Account as parent for enabled new_account").into(),
                    );
                };

                let parent_aid = *parent.aid;
                let parent_arecord = state
                    .accounts
                    .get_mut(parent_aid)
                    .ok_or(Error::AccountClosed)?;

                // Can we insert the new child without reallocating?
                if !parent_arecord.children.spare_capacity_mut().is_empty() {
                    return Ok(parent_aid);
                }

                // No.  Well, let's do some garbage collection.
                // (Otherwise .children might grow without bound as accounts come and go)
                //
                // We would like to scan the accounts array while mutating this account.
                // Instead, steal the children array temporarily and put the filtered one back.
                // Must be infallible!
                //
                // The next line can't be in the closure (confuses borrowck)
                let mut parent_children = mem::take(&mut parent_arecord.children);
                (|| {
                    parent_children.retain(|child_aid| state.accounts.contains_key(*child_aid));

                    // Put the filtered list back, so sanity is restored.
                    state
                        .accounts
                        .get_mut(parent_aid)
                        .expect("parent vanished!")
                        .children = parent_children;
                })();

                Ok::<_, Error>(parent_aid)
            })
            .transpose()?;

        // We have resolved the parent AId and prepared to add the new account to its list of
        // children.  We still hold the lock, so nothing can have changed.

        // commitment - infallible IEFE assures that so we don't do half of it
        Ok((|| {
            let aid = refcount::slotmap_insert(&mut state.accounts, |refcount| ARecord {
                refcount,
                children: vec![],
                ps: SlotMap::default(),
                enabled,
            });

            if let Some(parent_aid_good) = parent_aid_good {
                state
                    .accounts
                    .get_mut(parent_aid_good)
                    .expect("parent vanished!")
                    .children
                    .push(*aid);
            }

            let tracker = self.clone();
            let inner = AccountInner { aid, tracker };
            Account(Enabled(inner, enabled)) // don't make this fallible, see above.
        })())
    }

    /// Obtain a new `MemoryQuotaTracker` that doesn't track anything and never reclaims
    pub fn new_noop() -> Arc<MemoryQuotaTracker> {
        Arc::new(MemoryQuotaTracker { state: Noop })
    }

    /// Obtain the lock on the state
    fn lock(&self) -> Result<IfEnabled<MutexGuard<State>>, TrackerCorrupted> {
        let Enabled(state, enabled) = &self.state else {
            return Ok(Noop);
        };
        Ok(Enabled(state.lock()?, *enabled))
    }
}

//---------- Account ----------

impl Account {
    /// Register a new Participant
    ///
    /// Returns the [`Participation`], which can be used to record memory allocations.
    ///
    /// Often, your implementation of [`IsParticipant`] wants to contain the [`Participation`].
    /// If so, use [`register_participant_with`](Account::register_participant_with) instead.
    pub fn register_participant(
        &self,
        particip: Weak<dyn IsParticipant>,
    ) -> Result<Participation, Error> {
        let Enabled(self_, enabled) = &self.0 else {
            return Ok(Participation(Noop));
        };

        let aid = *self_.aid;
        find_in_tracker! {
            enabled;
            self_.tracker => state;
            aid => arecord;
            ?Error
        }

        let (pid, cache) = refcount::slotmap_try_insert(&mut arecord.ps, |refcount| {
            let mut precord = PRecord {
                refcount,
                used: ParticipQty::ZERO,
                particip: drop_reentrancy::ProtectedWeak::new(particip),
                enabled: *enabled,
            };
            let cache =
                state
                    .global
                    .total_used
                    .claim(&mut precord, MAX_CACHE, &state.global.config)?;
            Ok::<_, Error>((precord, cache))
        })?;

        let tracker = Arc::downgrade(&self_.tracker);
        let inner = ParticipationInner {
            tracker,
            pid,
            aid,
            cache,
        };
        Ok(Participation(Enabled(inner, *enabled)))
    }

    /// Set the callbacks for a Participant (identified by its weak ids)
    fn set_participant_callbacks(
        &self,
        aid: AId,
        pid: PId,
        particip: drop_reentrancy::ProtectedWeak<dyn IsParticipant>,
    ) -> Result<(), Error> {
        let Enabled(self_, enabled) = &self.0 else {
            return Ok(());
        };
        find_in_tracker! {
            enabled;
            self_.tracker => state;
            aid => arecord;
            pid => precord;
            ?Error
        }
        precord.particip = particip;
        Ok(())
    }

    /// Register a new Participant using a constructor
    ///
    /// Passes `constructor` a [`Participation`] for the nascent Participant.
    /// Returns the `P: IsParticipant` provided by the constructor.
    ///
    /// For use when your `impl `[`IsParticipant`] wants to own the `Participation`.
    ///
    /// # Re-entrancy guarantees
    ///
    /// The `Participation` *may* be used by `constructor` for claiming memory use,
    /// even during construction.
    /// `constructor` may also clone the `Participation`, etc.
    ///
    /// Reclamation callbacks (via the `P as IsParticipant` impl) cannot occur
    /// until `constructor` returns.
    ///
    /// # Error handling
    ///
    /// Failures can occur before `constructor` is called,
    /// or be detected afterwards.
    /// If a failure is detected after `constructor` returns,
    /// the `Arc<P>` from `constructor` will be dropped
    /// (resulting in `P` being dropped, unless `constructor` kept another clone of it).
    ///
    /// `constructor` may also fail (throwing a different error type, `E`),
    /// in which case `register_participant_with` returns `Ok(Err(E))`.
    ///
    /// On successful setup of the Participant, returns `Ok(Ok(Arc<P>))`.
    pub fn register_participant_with<P: IsParticipant, X, E>(
        &self,
        now: CoarseInstant,
        constructor: impl FnOnce(Participation) -> Result<(Arc<P>, X), E>,
    ) -> Result<Result<(Arc<P>, X), E>, Error> {
        let Enabled(_self, _enabled) = &self.0 else {
            return Ok(constructor(Participation(Noop)));
        };

        use std::sync::atomic::{AtomicBool, Ordering};

        /// Temporary participant, which stands in during construction
        #[derive(Debug)]
        struct TemporaryParticipant {
            /// The age, which is right now.  We hope this is all fast!
            now: CoarseInstant,
            /// Did someone call reclaim() ?
            collapsing: AtomicBool,
        }

        impl IsParticipant for TemporaryParticipant {
            fn get_oldest(&self, _: EnabledToken) -> Option<CoarseInstant> {
                Some(self.now)
            }
            fn reclaim(self: Arc<Self>, _: EnabledToken) -> ReclaimFuture {
                self.collapsing.store(true, Ordering::Release);
                Box::pin(async { Reclaimed::Collapsing })
            }
        }

        let temp_particip = Arc::new(TemporaryParticipant {
            now,
            collapsing: false.into(),
        });

        let partn = self.register_participant(Arc::downgrade(&temp_particip) as _)?;
        let partn_ = partn
            .0
            .as_enabled()
            .ok_or_else(|| internal!("Enabled Account gave Noop Participant"))?;
        let aid = partn_.aid;
        let pid_weak = *partn_.pid;

        // We don't hold the state lock here.  register_participant took it and released it.
        // This is important, because the constructor might call claim!
        // (And, also, we don't want the constructor panicking to poison the whole tracker.)
        // But it means there can be quite a lot of concurrent excitement,
        // including, theoretically, a possible reclaim.
        let (particip, xdata) = match constructor(partn) {
            Ok(y) => y,
            Err(e) => return Ok(Err(e)),
        };
        let particip = drop_reentrancy::ProtectedArc::new(particip);

        // IEFE prevents use from accidentally dropping `particip` until we mean to
        let r = (|| {
            let weak = {
                let weak = particip.downgrade();

                // Trait cast, from Weak<P> to Weak<dyn IsParticipant>.
                // We can only do this for a primitive, so we must unprotect
                // the Weak, converr it, and protect it again.
                drop_reentrancy::ProtectedWeak::new(weak.unprotect() as _)
            };
            self.set_participant_callbacks(aid, pid_weak, weak)?;

            if temp_particip.collapsing.load(Ordering::Acquire) {
                return Err(Error::ParticipantShutdown);
            }
            Ok(())
        })();

        let particip = particip.promise_dropping_is_ok();
        r?;
        Ok(Ok((particip, xdata)))
    }

    /// Obtain a new `Account` which is a child of this one
    ///
    /// Equivalent to
    /// [`MemoryQuotaTracker.new_account`](MemoryQuotaTracker::new_account)`(Some(..))`
    pub fn new_child(&self) -> crate::Result<Self> {
        let Enabled(self_, _enabled) = &self.0 else {
            return Ok(Account::new_noop());
        };
        self_.tracker.new_account(Some(self))
    }

    /// Obtains a handle for the `MemoryQuotaTracker`
    pub fn tracker(&self) -> Arc<MemoryQuotaTracker> {
        let Enabled(self_, _enabled) = &self.0 else {
            return MemoryQuotaTracker::new_noop();
        };
        self_.tracker.clone()
    }

    /// Downgrade to a weak handle for the same Account
    pub fn downgrade(&self) -> WeakAccount {
        let Enabled(self_, enabled) = &self.0 else {
            return WeakAccount(Noop);
        };
        let inner = WeakAccountInner {
            aid: *self_.aid,
            tracker: Arc::downgrade(&self_.tracker),
        };
        WeakAccount(Enabled(inner, *enabled))
    }

    /// Obtain a new `Account` that does nothing and has no associated tracker
    ///
    /// All methods on this succeed, but they don't do anything.
    pub fn new_noop() -> Self {
        Account(IfEnabled::Noop)
    }
}

impl Clone for Account {
    fn clone(&self) -> Account {
        let Enabled(self_, enabled) = &self.0 else {
            return Account(Noop);
        };
        let tracker = self_.tracker.clone();
        let aid = (|| {
            let aid = *self_.aid;
            find_in_tracker! {
                enabled;
                tracker => state;
                aid => arecord;
                ?None
            }
            let aid = refcount::Ref::new(aid, &mut arecord.refcount).ok()?;
            // commitment point
            Some(aid)
        })()
        .unwrap_or_else(|| {
            // Either the account has been closed, or our refcount overflowed.
            // Return a busted `Account`, which always fails when we try to use it.
            //
            // If the problem was a refcount overflow, we're technically violating the
            // documented behaviour, since the returned `Account` isn't equivalent
            // to the original.  We could instead choose to tear down the Account;
            // that would be legal; but it's a lot of code to marginally change the
            // behaviour for a very unlikely situation.
            refcount::Ref::null()
        });
        let inner = AccountInner { aid, tracker };
        Account(Enabled(inner, *enabled))
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        let Enabled(self_, enabled) = &mut self.0 else {
            return;
        };
        (|| {
            find_in_tracker! {
                enabled;
                self_.tracker => state;
                *self_.aid => arecord;
                ?None
            }
            if let Some(refcount::Garbage(mut removed)) =
                slotmap_dec_ref!(&mut state.accounts, self_.aid.take(), &mut arecord.refcount)
            {
                // This account is gone.  Automatically release everything.
                removed.auto_release(state);
            }
            Some(())
        })()
        .unwrap_or_else(|| {
            // Account has been torn down.  Dispose of the strong ref.
            // (This has no effect except in cfg(test), when it defuses the drop bombs)
            self_.aid.take().dispose_container_destroyed();
        });
    }
}

//---------- WeakAccount ----------

impl WeakAccount {
    /// Upgrade to an `Account`, if the account still exists
    ///
    /// No-op `WeakAccounts` can always be upgraded.
    pub fn upgrade(&self) -> crate::Result<Account> {
        let Enabled(self_, enabled) = &self.0 else {
            return Ok(Account(Noop));
        };
        let aid = self_.aid;
        // (we must use a block, and can't use find_in_tracker's upgrade, because borrowck)
        let tracker = self_.tracker.upgrade().ok_or(Error::TrackerShutdown)?;
        let aid = {
            find_in_tracker! {
                enabled;
                tracker => state;
                aid => arecord;
                ?Error
            }
            refcount::Ref::new(aid, &mut arecord.refcount)?
            // commitment point
        };
        let inner = AccountInner { aid, tracker };
        Ok(Account(Enabled(inner, *enabled)))
    }

    /// Obtains a handle onto the `MemoryQuotaTracker`
    ///
    /// The returned handle is itself weak, and needs to be upgraded before use.
    ///
    /// If the `Account` was made a no-op `MemoryQuotaTracker`
    /// (ie, one from [`MemoryQuotaTracker::new_noop`])
    /// the returned value is always `Weak`.
    pub fn tracker(&self) -> Weak<MemoryQuotaTracker> {
        let Enabled(self_, _enabled) = &self.0 else {
            return Weak::default();
        };
        self_.tracker.clone()
    }

    /// Creates a new dangling, dummy, `WeakAccount`
    ///
    /// This can be used as a standin where a value of type `WeakAccount` is needed.
    /// The returned value cannot be upgraded to an `Account`,
    /// so cannot be used to claim memory or find a `MemoryQuotaTracker`.
    ///
    /// (If memory quota tracking is disabled at compile time,
    /// the returned value *can* be upgraded, to a no-op `Account`.)
    pub fn new_dangling() -> Self {
        let Some(enabled) = EnabledToken::new_if_compiled_in() else {
            return WeakAccount(Noop);
        };

        let inner = WeakAccountInner {
            aid: AId::default(),
            tracker: Weak::default(),
        };
        WeakAccount(Enabled(inner, enabled))
    }
}

//---------- Participation ----------

impl Participation {
    /// Record that some memory has been (or will be) allocated
    pub fn claim(&mut self, want: usize) -> crate::Result<()> {
        self.claim_qty(Qty(want))
    }

    /// Record that some memory has been (or will be) allocated (using `Qty`)
    pub(crate) fn claim_qty(&mut self, want: Qty) -> crate::Result<()> {
        let Enabled(self_, enabled) = &mut self.0 else {
            return Ok(());
        };

        if let Some(got) = self_.cache.split_off(want) {
            return got.claim_return_to_participant();
        }

        find_in_tracker! {
            enabled;
            self_.tracker => + tracker, state;
            self_.aid => arecord;
            *self_.pid => precord;
            ?Error
        };

        let mut claim = |want| -> Result<ClaimedQty, _> {
            state
                .global
                .total_used
                .claim(precord, want, &state.global.config)
        };
        let got = claim(want)?;

        if want <= TARGET_CACHE_CLAIMING {
            // While we're here, fill the cache to TARGET_CACHE_CLAIMING.
            // Cannot underflow: cache < want (since we failed at `got` earlier
            // and we've just checked want <= TARGET_CACHE_CLAIMING.
            let want_more_cache = TARGET_CACHE_CLAIMING
                .checked_sub(*self_.cache.as_raw())
                .expect("but cache < want");
            let want_more_cache = Qty(want_more_cache);
            if let Ok(add_cache) = claim(want_more_cache) {
                // On error, just don't do this; presumably the error will show up later
                // (we mustn't early exit here, because we've got the claim in our hand).
                self_.cache.merge_into(add_cache);
            }
        }
        got.claim_return_to_participant()
    }

    /// Record that some memory has been (or will be) freed by a participant
    pub fn release(&mut self, have: usize) // infallible
    {
        self.release_qty(Qty(have));
    }

    /// Record that some memory has been (or will be) freed by a participant (using `Qty`)
    pub(crate) fn release_qty(&mut self, have: Qty) // infallible
    {
        let Enabled(self_, enabled) = &mut self.0 else {
            return;
        };

        let have = ClaimedQty::release_got_from_participant(have);
        self_.cache.merge_into(have);
        if self_.cache > MAX_CACHE {
            match (|| {
                find_in_tracker! {
                    enabled;
                    self_.tracker => + tracker, state;
                    self_.aid => arecord;
                    *self_.pid => precord;
                    ?None
                }
                let return_from_cache = self_
                    .cache
                    .as_raw()
                    .checked_sub(*TARGET_CACHE_RELEASING)
                    .expect("TARGET_CACHE_RELEASING > MAX_CACHE ?!");
                let return_from_cache = Qty(return_from_cache);
                let from_cache = self_
                    .cache
                    .split_off(return_from_cache)
                    .expect("impossible");
                state.global.total_used.release(precord, from_cache);
                Some(())
            })() {
                Some(()) => {} // we've given our cache back to the tracker
                None => {
                    // account (or whole tracker!) is gone
                    // throw away the cache so that we don't take this path again for a bit
                    self_.cache.take().dispose_participant_destroyed();
                }
            }
        }
    }

    /// Obtain a handle onto the account
    ///
    /// The returned handle is weak, and needs to be upgraded before use,
    /// since a [`Participation`] doesn't keep its Account alive.
    ///
    /// The returned `WeakAccount` is equivalent to
    /// all the other account handles for the same account.
    pub fn account(&self) -> WeakAccount {
        let Enabled(self_, enabled) = &self.0 else {
            return WeakAccount(Noop);
        };

        let inner = WeakAccountInner {
            aid: self_.aid,
            tracker: self_.tracker.clone(),
        };
        WeakAccount(Enabled(inner, *enabled))
    }

    /// Destroy this participant
    ///
    /// Treat as freed all the memory allocated via this `Participation` and its clones.
    /// After this, other clones of this `Participation` are no longer usable:
    /// attempts to do so will give errors.
    /// (although they can still be used to get at the `Account`, if it still exists).
    ///
    /// The actual memory should be freed promptly.
    ///
    /// (It is not necessary to call this function in order to get the memory tracker
    /// to free its handle onto the `IsParticipant`,
    /// because the memory quota system holds only a [`Weak`] reference.)
    pub fn destroy_participant(mut self) {
        let Enabled(self_, enabled) = &mut self.0 else {
            return;
        };
        (|| {
            find_in_tracker! {
                enabled;
                self_.tracker => + tracker, state;
                self_.aid => arecord;
                ?None
            };
            if let Some(mut removed) =
                refcount::slotmap_remove_early(&mut arecord.ps, self_.pid.take())
            {
                removed.auto_release(&mut state.global);
            }
            Some(())
        })();
        // self will be dropped now, but we have already cleared it out.
    }

    /// Creates a new dangling, dummy, `Participation`
    ///
    /// This can be used as a standin where a value of type `Participation` is needed.
    /// The returned value cannot be used to claim memory,
    /// or find an `Account` or `MemoryQuotaTracker`.
    pub fn new_dangling() -> Self {
        let Some(enabled) = EnabledToken::new_if_compiled_in() else {
            return Participation(Noop);
        };

        let inner = ParticipationInner {
            pid: refcount::Ref::default(),
            aid: AId::default(),
            tracker: Weak::default(),
            cache: ClaimedQty::ZERO,
        };
        Participation(Enabled(inner, enabled))
    }
}

impl Clone for Participation {
    fn clone(&self) -> Participation {
        let Enabled(self_, enabled) = &self.0 else {
            return Participation(Noop);
        };
        let aid = self_.aid;
        let cache = ClaimedQty::ZERO;
        let tracker: Weak<_> = self_.tracker.clone();
        let pid = (|| {
            let pid = *self_.pid;
            find_in_tracker! {
                enabled;
                self_.tracker => + tracker_strong, state;
                aid => _arecord;
                pid => precord;
                ?None
            }
            let pid = refcount::Ref::new(pid, &mut precord.refcount).ok()?;
            // commitment point
            Some(pid)
        })()
        .unwrap_or_else(|| {
            // The account has been closed, the participant torn down, or the refcount
            // overflowed.  We can a busted `Participation`.
            //
            // We *haven't* incremented the refcount, so we mustn't return pid as a strong
            // reference.  We aren't supposed to count towards PRecord.refcount, we we *can*
            // return the weak reference aid.  (`refcount` type-fu assures this is correct.)
            //
            // If the problem was refcount overflow, we're technically violating the
            // documented behaviour.  This is OK; see comment in `<Account as Clone>::clone`.
            refcount::Ref::null()
        });
        let inner = ParticipationInner {
            aid,
            pid,
            cache,
            tracker,
        };
        Participation(Enabled(inner, *enabled))
    }
}

impl Drop for Participation {
    fn drop(&mut self) {
        let Enabled(self_, enabled) = &mut self.0 else {
            return;
        };
        (|| {
            find_in_tracker! {
                enabled;
                self_.tracker => + tracker_strong, state;
                self_.aid => arecord;
                *self_.pid => precord;
                ?None
            }
            // release the cached claim
            let from_cache = self_.cache.take();
            state.global.total_used.release(precord, from_cache);

            if let Some(refcount::Garbage(mut removed)) =
                slotmap_dec_ref!(&mut arecord.ps, self_.pid.take(), &mut precord.refcount)
            {
                // We might not have called `release` on everything, so we do that here.
                removed.auto_release(&mut state.global);
            }
            Some(())
        })()
        .unwrap_or_else(|| {
            // Account or Participation or tracker destroyed.
            // (This has no effect except in cfg(test), when it defuses the drop bombs)
            self_.pid.take().dispose_container_destroyed();
            self_.cache.take().dispose_participant_destroyed();
        });
    }
}

//========== impls on internal types ==========

impl State {
    /// Obtain all of the descendants of `parent_aid` according to the Child relation
    ///
    /// The returned `HashSet` includes `parent_aid`, its children,
    /// their children, and so on.
    ///
    /// Used in the reclamation algorithm in [`reclaim`].
    fn get_aid_and_children_recursively(&self, parent_aid: AId) -> HashSet<AId> {
        let mut out = HashSet::<AId>::new();
        let mut queue: Vec<AId> = vec![parent_aid];
        while let Some(aid) = queue.pop() {
            let Some(arecord) = self.accounts.get(aid) else {
                // shouldn't happen but no need to panic
                continue;
            };
            if out.insert(aid) {
                queue.extend(arecord.children.iter().cloned());
            }
        }
        out
    }
}

impl ARecord {
    /// Release all memory that this account's participants claimed
    fn auto_release(&mut self, global: &mut Global) {
        for (_pid, mut precord) in self.ps.drain() {
            precord.auto_release(global);
        }
    }
}

impl PRecord {
    /// Release all memory that this participant claimed
    fn auto_release(&mut self, global: &mut Global) {
        let for_teardown = self.used.for_participant_teardown();
        global.total_used.release(self, for_teardown);
    }
}
