# Memory limiting and reclamation

This is a design document.

It omits some important considerations.  Notably:

 * All arithmetic needs to be panic-free with appropriate out-of-course handling.
 * In general, error handing isn't shown.
 * What is called `RoughTime` here doesn't exist yet.
 * Pseudocode (and impls generally) are handwavy sketches.

## Intended behavour

In normal operation we track very little cheaply
We do track total memory use in nominal bytes
(but a little approximately).

When we exceed the quota, we engage a more expensive algorithm:
we build a heap to select oldest victims.
We use the heap to keep reducing memory
until we go below a low-water mark (hysteresis).

## Key concepts

 * **Tracker**: Instance of the memory quota system.  Each tracker has a notion of how much memory its participants are allowed to use, in aggregate.  Tracks memory usage by all the Accounts and Participants.  Different Trackers are completely independent.

 * **Account**: all memory used withing the same Account is treated equally, and reclamation also happens on an account-by-account basis.  (Each Account is with one Tracker.)

 * **Participant**: one data structure that uses memory.  Each Participant is linked to *one* Account.  An account has *one or more* Participants.  (An Account can exist with zero Participants, but can't then claim memory.)  A Participant provides a `dyn Participant` to the memory system; in turn, the memory system provides the Participant with a `Participation` - a handle for tracking memory alloc/free.

 * **Child Account**/**Parent Account**: An Account may have a Parent.  When a tracker requests memory reclamation from a Parent, it will also request it of all that Parent's Children (but not vice versa).

 * **Data age**: Each Participant is must be able to say what the oldest data is, that it is storing.  The reclamation policy is to try to free the oldest data.

 * **Reclamation**: When a Tracker decides that too much memory is being used, it will select a victim Account based on the data age.  It will then ask *every Participant* in that Account, and every Participant in every Child of that Account, to reclaim memory.  A Participant responds by freeing at least some memory, according to the reclamation request, and tells the Tracker when it has done so.

 * **Reclamation strategy**: To avoid too-frequent Reclamation, once Reclamation ha started, it will continue until a low-water mark is reached, significantly lower than the quota.  I.e. the system has a hysteresis.  The only currently implemented higher-level Participant is a queue which responds to a reclamation request by completely destroying itself and freeing all its data.

 * **Approximate** (both in time and space): The memory quota system is not completely precise.  Participants need not report their use precisely, but the errors should be reasonably small, and bounded.  Likewise, the enforcement is not precise: reclamation may start slightly too early, or too late; but the memory use will be bounded below by O(number of participants) and above by O(1) (plus errors from the participants).  Reclamation is not immediate, and is dependent on task scheduling; during memory pressure the quota may be exceeded; new allocations are not prevented while attempts at reclamation are ongoing.

 * **Queues**: We provide a higher-level API that wraps an mpsc queue and turns it into a Participant.

## Onwership and Arc keeping-alive

 * Somewhere, someone must keep an `Account` to keep the account open.  Ie, the principal
   object corresponding to the accountholder should contain an `Account`.

 * `Arc<MemoryTracker>` holds `Weak<dyn Participant>`.  If the tracker finds a `Participant`
   has vanished, it assumes this means that the Participant is being destroyed and it can treat
   all of the memory it claimed as freed.

 * Each participant holds a `Participation`.  A `Participation` may be invalidated by collapse
   of the underlying Account, which may be triggered in any number of ways.

 * A `Participation` does *not* keep its `Account` alive.  Ie, it has only a weak reference to
   the Account.

 * A Participant's implementor of `Participant` may hold a `Participation`.  If the
   `Participant` is also the principal accountholder object, it must hold an `Account` too.

 * Child/parent accounts do not imply any keeping-alive relationship.
   It's just that a reclamation request to a parent (if it still exists)
   will also be made to its children.


```
    accountholder   =======================================>*  Participant

          ||                                                     ^     ||
          ||                                                     |     ||
          ||                                                     |     ||
          ||                 global                     Weak<dyn>|     ||
          ||                     ||                              |     ||
          \/*                    \/                              |     ||
                                                                 |     ||
        Account  *===========>  MemoryTracker  ------------------'     ||
                                                                       ||
           ^                                                           ||
           |                                                           \/
           |
            `-------------------------------------------------*   Participation



    accountholder which is also directly the Participant ==============\
                                                                      ||
          ||                              ^                           ||
          ||                              |                           ||
          ||                              |                           ||
          ||                 global       |Weak<dyn>                  ||
          ||                     ||       |                           ||
          \/                     \/       |                           ||
                                                                      ||
        Account  *===========>  MemoryTracker                         ||
                                                                      ||
           ^                                                          ||
           |                                                          \/
           |
            `-------------------------------------------------*   Participation

```

## Higher level memory-tracking/limiting queue API

Replaces mpsc queues.

Key APIs.

 * `pub struct Sender<T>` and `pub struct Receiver<T>` with the obvious behaviours.
 * `pub fn channel` constructor that gives you a `Sender`/`Receiver` pair,
   (given an `Account`).
 * Elements in the queue must implement
   `SizeForMemoryQuota`.
 * Each channel is a Participant.

Reclamation APIs:
Hardly any.
When under memory pressure, the queue "collapses".
All its contents are immediately dropped,
and the sender and receiver both start to return errors.
There is a method to allow the sender to proactively notice collapse.

```
mod memquota::mpsc_queue {

  trait HasMemoryCost /* name? MemoryCosted? */ { fn memory_cost(&self) -> usize }

  pub fn channel<T:HasMemoryCost>(account: memquota::Account, buffer: usize) -> (Sender, Receiver)
    makes queue, calls new_participant

  #[derive(Clone)]
  pub struct Sender<T>(
    tx: mpsc::Sender<Entry<T>>,
    memquota: memquota::Account, // collapsed-checking is in here

  pub struct UnboundedSender<T>(
    tx: mpsc::UnboundedSender<Entry<T>>,
    memquota: memquota::Account, // collapsed-checking is in here
  // etc.

  pub struct Receiver<T> {
    // usually, lock acquired only by recv ie only by owner of Receiver
    // on memory pressure, lock acquired by memory system
    inner: Arc<Mutex<ReceiverState<T>

  struct ReceiverState<T> {
    // We'd like to use futures::stream::Peekable but it doesn't have sync try_peek
    // Probably, actually, roll our own private Peekable for clarity/testing
    peeked: Option<Entry<T>>,
    rx: mpsc::Receiver<Entry<T>>,
    // We have separate `Account`s for rx anc tx.
    // The tx is constantly claiming and the rx releasing;
    // each `local_quota`-limit's worth, they must balance out
    // via the (fairly globally shared) MemoryDataTracker.
    memquota: memquota::Participation,
    // when receiver dropped, or memory reclaimed, call all of these
    // for circuits, callback will send a ctrl msg
    // (callback is nicer than us handing out an mpsc rx
    // which user must read and convert items from)
    collpase_notify: Vec<CollapseCallback>,

  /// Entry in in the inner queue
  struct Entry {
    /// TODO: We're using `RoughTime` as a placeholder in this design doc.
    /// This will actually be whatever coarsetime-like thing we decide to add to Runtime.
    /// (No ticket for that that I can find, but see also #496.)
    when: RoughTime,
    t: T,
  }

  pub type CollapseCallback = Box<dyn FnOnce(CollapseReason) + Send + Sync + 'static>;
  pub enum CollapseReason {
    MemoryReclaimed,
    ReceiverDropped,
  }
  impl Drop for ReceiverState<T> {
    self.memquota.delete_participant(self.memquota_pid);
    self.collapse_notify.drain(). call(CollapseReason::ReceiverDropped)

  // weak ref to queue, for implementing Participant to hook into memory system
  struct ReceiverParticipant {
    inner: Weak<Mutex<RecieverState

  // sketch; really we'd impl Sink
  impl Sender<T> {
    // passing now means we don't have to have a runtime handle in the queue object
    pub async fn send(&mut self, now: RoughTime, t: T) -> Result {
      self.memquota.claim(t.size_for_memory_quota())? // will throw if collapsing
      self.tx.send(Entry::Real { ... })

  // sketch; really we'd impl Stream
  impl Receiver<T> {
    pub async fn recv(&mut self) -> {
      let state = self.inner.state.lock();
      state.collapse_status?; // check if we're out of memory
      let t = { obvious impl involving peeked and rx };
      state.memquota.release(t.size_for_memory_quota());
      t

    // this method is on Receiver because that has the State,
    // but could be called during setup to hook both sender's and
    // receiver's shutdown mechanisms.
    pub fn hook_collapse(&self, CollapseCallback)

  impl Participant for ReceiverParticipant {
    fn get_oldest(&self) -> Option<RoughTime> {
      let state = self.inner.upgrade()?.state.lock();
      let peeked = { obvious impl involving peeked and rx };
      return peeked.when
    }
    async fn reclaim(self: Arc<Self>, _, _) -> Reclaimed {
      let state = self.inner.upgrade()?.state.lock();
      for n in state.collapse_notify.drain() { n(CollapseReason::MemoryReclaimed); }
      // allow memory manager to continue
      // proactively empty the queue in case the sender doesn't
      while let Some(_) = state.rx.try_pop() {
        // no need to update memquota since we've told it we're collapsing
      }
      Reclaimed::Collapsing

```

## Low level

Key types:

 * `pub struct MemoryQuotaTracker`.
   One of these per quota.
   Contains the quota configuration and a list of participants,
   (and how much each participant is using).

 * `pub trait Participant`.
   Implemented by things that relevantly allocate memory.
   Provides the callback methods used during reclamation.
   Each `Account` has, somewhere, one or more Participants.

 * `pub struct Account`.
   Obtained by a participant from a `MemoryQuotaTracker`,
   during enrolment of the participant.
   The participant supplies a `Participant` implementation
   (to `MemoryQuotaTracker::new_account`)
   and gets a (cloneable) `Account`.
   A `Account` has methods
   for accounting the allocation and freeing of memory.

Actual memory allocation is handled by the participant itself,
using the global heap.

The `usize`'s handled by methods are in bytes, but they are nominal
and need not be completely precise.

```
mod memquota::raw {

  pub struct AccountId; // Clone, Copy, etc.

  /// ParticipantId is scoped within in the context of an account.
  /// Private.
  struct ParticipantId; // Clone, Copy, etc.

  type AId = AccountId;
  type PId = ParticipantId;

  pub struct MemoryQuotaTracker(
    Mutex<TrackerInner>

  pub struct TrackerInner {
    Config {
      max,
      low_water,
    }
    total_used,
    ps: SlotMap<AId, ARecord>
    reclaimation_task_wakeup: Condvar,

  struct ARecord {
    account_clones: u32,
    children: Vec<AId>,
    p: SlotMap<PId, PRecord>,
  }
  struct PRecord {
    participation_clones: u32,
    used: usize, // not 100% accurate, can lag, and be (boundedly) an overestimate
    reclaiming: bool,
    Weak<dyn Participant>,
  }

  pub trait Participant {
    fn get_oldest(&self) -> Option<RoughTime>;
    // Should free *at least* all memory at least as old as discard_...
    //
    // v1 of the actual implemnetation might not have `discard_everything_as_old_as`
    // and `but_can_stop_discarding_...`,
    // and might therefore only support Reclaimed::Collapsing
    //
    // ie then `reclaim` is really ~please collapse"
    async fn reclaim(self: Arc<Self>, discard_everything_as_old_as_this: RoughTime,
               but_can_stop_discarding_after_freeing_this_much: usize)
               -> Reclaimed

  enum Reclaimed {
    // Participant is responding to reclamation by collapsing completely.
    // All memory will be freed and `release`'d soon (if it hasn't been already).
    // Tracker should forget the Participant and all memory it used, right away.
    Collapsing,
    // Participant has already reclaimed some memory as instructed;
    // if this is not sufficient, tracker must call reclaim() again.
    // (We may not want to implement Partial right away but the API
    // ought to support it so let's think about it now, even if we don't implement it.)
    Partial,
  }

  pub struct Account {
    // existence of this field prevents us exposing the Arc, hence separate WeakAccount
    #[getter]
    aid: AId,
    #[getter]
    tracker: Arc<MemoryQuotaTracker>
  }
  pub struct WeakAccount {
    // like Account but has Weak<> and doesn't count for account_clones

  pub struct Participation {
    pid: ParticipationId,
    // quota we have preemptively claimed for use by this Account
    // has been added to PRecord.used
    // but not yet returned by Participation.claim
    //
    // this arranges that most of the time we don't have to hammer a
    // single cache line
    //
    // The value here is bounded by a configured limit
    //
    // Invariants on memory accounting:
    //
    //  * `Participation.local_quota < configured limit`
    //  * `Participation.local_quota + sum(Participation::claim) - sum(Participation::release) == `PRecord.used`
    //    except if `PRecord` has been deleted
    //    (ie when we aren't tracking any more and think the Participant is Collapsing).
    //  * `sum(PRecord.used) == TrackerInner.total_used`
    local_quota: usize,
    #[getter]
    account: WeakAccount,
  }

  impl Participation {
    pub fn claim(&mut self, usize) -> Result<()> {
       try to take usize from local_quota,
       failing that, get from tracker,
       possibly taking extra to put into local quota

    pub fn release(&mut self usize) /* infallible */ {
       self.local_quota += usize;
       if local quota too big, call tracker.release

  impl Account {
    pub fn new_participant(self, participant: Weak<dyn Participant>) -> Participation

  /// An Account is a handle.  All clones refer to the same underlying conceptual Account.
  impl Clone for Account
  /// Participation is a handle.  All clones are for use by the same Participant.
  /// It doesn't keep the underlying Account alive.
  impl Clone for Participation

  impl Drop for Account
    decrement account_clones
    the ARecord should no longer have anything in p
  impl Drop for Participation
    decrement participation_clones
    if zero, forget the participant (subtracting its PRecord.used from TrackerInner_used)

  // gives you another view of the same particant
  impl Clone for Account {
    // clone's local_quota is set to 0.

  impl MemoryQuotaTracker {
    // claim will fail until a Partciipant is added
    //
    // Right now, parent can't be changed after construction of an Account,
    // so circular accounts are impossible.
    // But, we might choose to support that in the future.  Circular accounts parent relationships
    // would need just a little care in the reclamation loop to avoid inifitely looping,
    // but aren't inherently unsupportable.
    pub fn new_account(&Arc<self>, parent: Option<AccountId>) -> Account {

    fn claim(&self, aid: AId, pid: PId,, req: usize) -> Result {
       let inner = self.0.lock().unwrap();
       let acc = inner.ps.get_mut(aid)
         .ok_or_else(ParticipantForgottenError)?;
       check that pid is in acc;
       self.used += req;
       p.used += req;
       if self.used > self.max { self.reclamation_task_wakeup.signal(); }
       Ok(())

    async fn reclamation_task() {
      let mut target = self.max;

      loop {
        condvar wait for signal;
        if self.used <= max { continue }

        // reclamation
        let mut heap: Heap<RoughTime, AId> = ps.iter().collect();
        while self.used > self.low_water {
          let oldest = heap.pop_lowest();
          let next_oldest = heap.peek_lowest();
          // fudge next_oldest by something to do with number of loop iterations,
          // to avoid one-allocation-each-time ping pong between multiple caches

          // Actually, each entry is a Vec<Partipant> so we must iterate or collect

          note that we are reclaiming oldest;
          oldest_particip = ps[oldest].clone();
          unlock the lock;
          let r = oldest_particip.reclaim(next_oldest, self.used - self.low_water)
              .await;

          reacquire lock;
          if matches!(r, Collapsing) { delete the participant }

          while (oldest is still reclaiming) { condvar wait }
          // do some timeouts and checks on participant behaviour
          // if we have unresponsive participant, we can't kill it but we can
          // start reclaiming other stuff?  maybe in 1st cut we just log such a situation

          // ^ do all this for self.ps[oldest].children too (maybe in parallel)
        }

```

## Plan for caches

We may or may not use this "shared quota, delete oldest thing" notion.
We may or may not want caches to share quota with queues, or to be independent.

## If we want to purge oldest cache data, with same age scale as queues

A cache knows its oldest data and will need to know how old each thing it has, is.

On reclaim, it discards the oldest things until it reaches roughly (at least) next_oldest,
or has freed the amount requested.
If that's not enough, tracker will call reclaim again.

## If we want a single quota, but a different reclamation strategy for caches

I.e. we want to balance caches with queues "somehow" (TBD).

We'll introduce a new kind of `Participant`, probably a new trait,
and a `new_cache_particpant` enrolment method.
(We may want to rename `Participant`?)

When memory pressure occurs the `MemoryQuotaTracker`
will ask queues about their oldest data.

It will ask caches about whatever it is that is relevant (via
`CacheParticipant`?).

The manager will decide who needs to free memory,
and give instructions via the `Particpant`/`CacheParticpant` trait method(s).

Policy and algorithms TBD.

## If we want caches to reclaim oldest data, but with a separate quota

We could make a separate `MemoryQuotaTracker` for each cache.
That cache will then end up using an LRU policy.

## If we want caches to be totally independent with a different policy

We may or may not reuse some of the code here, but the API will be different.
