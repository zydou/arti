# Memory limiting and reclamation

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

 * **Participant**: one data structure that uses memory.  Each Participant is linked to *one* Account.  An account has *one or more* Participants.

 * **Child Account**/**Parent Account**: An Account may have a Parent.  When a tracker requests memory reclamation from a Parent, it will also request it of all that Parent's Children (but not vice versa).

 * **Data age**: Each Participant is must be able to say what the oldest data is, that it is storing.  The reclamation policy is to try to free the oldest data.

 * **Reclamation**: When a Tracker decides that too much memory is being used, it will select a victim Account based on the data age.  It will then ask *every Participant* in that Account, and every Participant in every Child of that Account, to reclaim memory.  A Participant responds by freeing at least some memory, according to the reclamation request, and tells the Tracker when it has done so.

 * **Approximate** (both in time and space): The memory quota system is not completely precise.  Participants need not report their use precisely, but the errors should be reasonably small, and bounded.  Likewise, the enforcement is not precise: reclamation may start slightly too early, or too late; but the memory use will be bounded below by O(number of participants) and above by O(1) (plus errors from the participants).  Reclamation is not immediate, and is dependent on task scheduling; during memory pressure the quota may be exceeded; new allocations are not prevented while attempts at reclamation are ongoing.

 * **Queues**: We provide a higher-level API that wraps an mpsc queue and turns it into a Participant.

## Higher level memory-tracking/limiting queue API

Replaces mpsc queues.

Do we need *m*p ?  If so, need to make Sender.oldest Atomic.

Key APIs.

 * `pub struct Sender<T>` and `pub struct Receiver<T>` with the obvious behaviours.
 * `pub fn channel` constructor that gives you a `Sender`/`Receiver` pair,
   (given a `MemoryQuotaTracker`)
 * Elements in the queue must implement
   `SizeForMemoryQuota`.

Reclamation APIs:
Hardly any.
When under memory pressure, the queue "collapses".
All its contents are immediately dropped,
and the sender and receiver both start to return errors.
There is a method to allow the sender to proactively notice collapse.

```
mod memquota::spsc_queue {

  trait HasMemoryCost /* name? MemoryCosted? */ { fn memory_cost(&self) -> usize }

  pub fn channel<T:HasMemoryCost>(
     mgr: &MemoryQuotaTracker,
     parent: Option<AccountId>,
  )
      -> (Sender, Receiver)

  pub struct Sender<T>(
    tx: mpsc::Sender<Entry<T>>,
    memquota: memquots::raw::Account, // collapsed-checking is in here

  pub struct Receiver<T> {
    // usually, lock acquired only by recv ie only by owner of Receiver
    // on memory pressure, lock acquired by memory system
    inner: Arc<Mutex<ReceiverState<T>

  struct ReceiverState<T> {
    // We'd like to use futures::stream::Peekable but it doesn't have sync try_peek
    peeked: Option<Entry<T>>,
    rx: mpsc::Receiver<Entry<T>>,
    // We have separate `Account`s for rx anc tx.
    // The tx is constantly claiming and the rx releasing;
    // each `local_quota`-limit's worth, they must balance out
    // via the (fairly globally shared) MemoryDataTracker.
    memquota: memquots::raw::Account,
    // when receiver dropped, or memory reclaimed, call all of these
    // for circuits, callback will send a ctrl msg
    // (callback is nicer than us handing out an mpsc rx
    // which user must read and convert items from)
    collpase_notify: Vec<CollapseCallback>,

  /// Entry in in the inner queue
  struct Entry {
    when: RoughTime,
    t: T,
  }

  pub type CollapseCallback = Box<dyn FnOnce(CollapseReason) + Send + Sync + 'static>;
  pub enum CollapseReason {
    MemoryReclaimed,
    ReceiverDropped,
  }
  impl Drop for ReceiverState<T> {
    // no need to tell quota tracker, dropping the Account clones will do that
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
    fn reclaim(&mut self, _, _, token) {
      let state = self.inner.upgrade()?.state.lock();
      for n in state.collapse_notify.drain() { n(CollapseReason::MemoryReclaimed); }
      // allow memory manager to continue
      token.forget_account();
      // proactively empty the queue in case the sender doesn't
      while let Some(_) = state.rx.try_pop() { 
        // no need to update memquota since we've told it we're collapsing
      }

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
   Each participant has, somewhere, one or more `Account`s.
   
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

  struct AccountId; // Clone, Copy, etc.

  type AId = AccountId;

  pub struct MemoryQuotaTracker(
    Mutex<TrackerInner>

  pub struct TrackerInner {
    Config {
      max,
      low_water,
    }
    total_used,
    ps: SlotMap<AId, PRecord>
    reclaimation_task_wakeup: Condvar,

  struct PRecord {
    used: usize, // not 100% accurate, can lag, and be (boundedly) an overestimate
    reclaiming: bool, // does a ReclaimingToken exist, see below
    acount_clones: u32,
    children: Vec<AId>,
    p: Vec<Box<dyn Participant>>,
  }

  pub trait Participant {
    fn get_oldest(&self) -> Option<RoughTime>;
    /// MAY BE CALLED REENTRANTLY as a result of claim() !
    // not async because &self borrows from TrackerInner
    //
    // Should free *at least* all memory at least as old as next_oldest
    // (can be done asynchronously) and then drop the ReclaimingToken.
    fn reclaim(&mut self, discard_everything_as_old_as_this: RoughTime, 
               but_can_stop_discarding_after_freeing_this_much: usize,
               ReclaimingToken);

  pub struct Account {
    #[getter]
    aid: AId,
    // quota we have preemptively claimed for use by this Account
    // has been added to PRecord.used
    // but not yet returned by Account.claim
    //
    // this arranges that most of the time we don't have to hammer a
    // single cache line
    local_quota: u16,
    #[deref] // Actually, have an accessor
    tracker: MemoryQuotaTracker

  impl Account {
    fn claim(&mut self, usize) -> Result<()> {
       try to take usize from local_quota,
       failing that, get from tracker,
       possibly taking extra to put into local quota

    fn release(&mut self usize) /* infallible */ {
       self.local_quota += usize;
       if local quota too big, call tracker.release

    fn new_participant(&self, participant: Box<dyn Participant>) {
       self.tracker.new_participant(self.aid, participant);
    }

  /// An Account is a handle.  All clones refer to the same underlying conceptual Account.
  impl Clone for Account

  impl Drop for Account
    decrement participation_clones
    if zero, forget the account (subtracting its PRecord.used from TrackerInner_used)

  // gives you another view of the same particant
  impl Clone for Account {
    // clone's local_quota is set to 0.

  impl MemoryQuotaTracker {
    pub fn new_account(&Arc<self>, participant: Box<dyn Participant>, parent: Option<AccountId>)
        -> Account;

    pub fn new_participant(&Arc<self>, account_id: AccountId, Box<dyn Participant>>) {

    fn claim(&self, pid: AId, req: usize) -> Result {
       let inner = self.0.lock().unwrap();
       let p = inner.ps.get_mut(pid)
         .ok_or_else(ParticipantForgottenError)?;
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
          self.ps[oldest].reclaiming = true;
          // Actually, each entry is a Vec<Partipant> so we must iterate
          // fudge next_oldest by something to do with number of loop iterations,
          // to avoid one-allocation-each-time ping pong between multiple caches
          self.ps[oldest].reclaim(next_oldest, self.used - self.low_water, ReclaimingToken { });
          // ^ do this for self.ps[oldest].children too
          while self.ps[oldest].reclaiming { condvar wait }
          // ^ do this for self.ps[oldest].children too
          // do some timeouts and checks on participant behaviour
          // if we have unresponsive participant, we can't kill it but we can
          // start reclaiming other stuff?  maybe in 1st cut we just log such a situation
        }

  /// Type that is passed to a participant's `reclaim()`,
  /// and is dropped by the participant to notify the quota tracker
  /// that participant has finished the requested reclamation.
  ///
  /// Ie dropping this means "I've done some stuff, please call reclaim()
  /// again if necessary".
  // Drop impl clears PRecord.reclaiming and signals
  struct ReclaimingToken {

  impl ReclaimingToken {
    /// "this account is reclaiming by collapsing completely.
    /// all memory it uses will be eventually `release`d,
    /// but this may not have happened yet".
    ///
    /// The `reclaim()` method won't be called again.
    fn forget_account(self) {
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
