# Memory limiting and reclamation

This is a design document.

It omits some important considerations.  Notably:

 * All arithmetic needs to be panic-free with appropriate out-of-course handling.
 * In general, error handing isn't shown.
 * What is called `RoughTime` here doesn't exist yet.
 * Pseudocode (and impls generally) are handwavy sketches.

Re arithmetic overflow, see the clippy lint `arithmetic_side_effects`
but also its bugs
<https://github.com/rust-lang/rust-clippy/issues/11220>
<https://github.com/rust-lang/rust-clippy/issues/11145>
<https://github.com/rust-lang/rust-clippy/issues/10209>.

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
    makes queue, calls register_participant

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
    collapse_notify: Vec<CollapseCallback>,

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
    inner: Weak<Mutex<ReceiverState

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
      // proactively empty the queue in case the sender doesn't
      while let Some(_) = state.rx.try_pop() {
        // no need to update memquota since we've told it we're collapsing
      }
      let collapse_notify = mem::take(&mut collapse_notify);
      drop(state); // release lock
      for n in state.collapse_notify.drain() { n(CollapseReason::MemoryReclaimed); }
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
and a `new_cache_participant` enrolment method.
(We may want to rename `Participant`?)

When memory pressure occurs the `MemoryQuotaTracker`
will ask queues about their oldest data.

It will ask caches about whatever it is that is relevant (via
`CacheParticipant`?).

The manager will decide who needs to free memory,
and give instructions via the `Participant`/`CacheParticipant` trait method(s).

Policy and algorithms TBD.

## If we want caches to reclaim oldest data, but with a separate quota

We could make a separate `MemoryQuotaTracker` for each cache.
That cache will then end up using an LRU policy.

## If we want caches to be totally independent with a different policy

We may or may not reuse some of the code here, but the API will be different.
