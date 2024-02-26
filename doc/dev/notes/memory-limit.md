# Memory limiting and reclamation

## Intended behavour

In normal operation we track very little cheaply
We do track total memory use in nominal bytes
(but a little approximately).

When we exceed the quota, we engage a more expensive algorithm:
we build a heap to select oldest victims.
We use the heap to keep reducing memory
until we go below a low-water mark (hysteresis).

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

  trait SizeForMemoryQuota { fn size_for_memory_quota(&self) -> usize }

  pub fn channel<T: SizeForMemoryQuota + HasDummyValue>(mgr: &MemoryQuotaTracker)
      -> (Sender, Receiver)

  pub struct Sender<T>(
    rx: mpsc::Sender<Entry<T>>,
    shared: Arc<Shared>

  pub struct Receiver<T> {
  struct ReceiverInner<T> { // Just so we don't expose Participant impl
    // We'd like to use futures::stream::Peekable but it doesn't have sync try_peek
    peeked: Option<Entry<T>>,
    rx: mpsc::Receiver<Entry<T>>,
    shared: Arc<Shared>,

  struct Shared {
    collapsing: AtomicBool,
    memquota: memquots::raw::Participation,

  /// Entry in in the inner queue
  // we might want to bit-shave to optimise the layout of this
  enum Entry {
    Real {
      when: RoughTime,
	  t: T,
    }
    /// When collapsing, one of these is put in the queue,
    /// which will wake up the receiver.
	DummyJustForWakeup,
  }

  // sketch; really we'd impl Sink
  impl Sender<T> {
    // passing now means we don't have to have a runtime handle in the queue object
    async fn send(&mut self, now: RoughTime, t: T) -> Result {
      if self.shared.collapsing.load() { return Err }
      self.shared.memquota.claim(t.size_for_memory_quota())
      self.shared.send(Entry::Real { ... })

    // when the queue decides to collapse due to memory exhaustion, yields None
    fn watch_for_collapse(&self) -> impl Stream<Void> + Send + Sync + 'static {
      makes and returns a async_broadcast::Receiver<Void>

  // sketch; really we'd impl Stream
  impl Receiver<T> {
    async fn recv(&mut self) -> {
      if self.shared.collapsing.load() { return Err }
	  let t = { obvious impl involving peeked and rx };
	  self.shared.memquota.release(t.size_for_memory_quota());
	  t

  impl Participant for ReceiverInner {
    fn get_oldest(&self) -> Option<RoughTime> {
	  let peeked = { obvious impl involving peeked and rx };
      return peeked.when
    }
    fn reclaim(&mut self, _, _, token) {
      self.shared.collapse.store(true);
	  token.forget_participant();
      // proactively empty the queue in case the sender doesn't wake
      // up for some reason
      while let Some(_) = self.shared.queue.try_pop() { 
	    // no need to update memquota since we've told it we're collapsing
	  }
      // put a dummy element in the queue to wake the sender up
	  // we do this rather than having a separate signal,
	  // so that each loop iteration in the receiver doesn't need to
	  // register two wakers
	  self.shared.queue.send(Entry::DummyJustForWakeup)

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
   Each participant has, somewhere, one or more `Participation`s.
   
 * `pub struct Participation`.
   Obtained by a participant from a `MemoryQuotaTracker`,
   during enrolment of the participant.
   The participant supplies a `Participant` implementation
   (to `MemoryQuotaTracker::new_participant`)
   and gets a (cloneable) `Participation`.
   A `Participation` has methods
   for accounting the allocation and freeing of memory.
   
Actual memory allocation is handled by the participant itself,
using the global heap.

The `usize`'s handled by methods are in bytes, but they are nominal
and need not be completely precise.

```
mod memquota::raw {

  pub struct MemoryQuotaTracker(
	Mutex<TrackerInner>

  pub struct TrackerInner {
	Config {
	  max,
	  low_water,
	}
	total_used,
	ps: SlotMap<PId, PRecord>
	reclaimation_task_wakeup: Condvar,

  struct PRecord {
	used: usize, // not 100% accurate, can lag, and be (boundedly) an overestimate
	reclaiming: bool, // does a ReclaimingToken exist, see below
    participation_clones: u32,
	p: Box<dyn Participant>,
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

  pub struct Participation {
	id: PId,
	// quota we have preemptively claimed for use by this Participation
	// has been added to PRecord.used
	// but not yet returned by Participation.claim
	//
	// this arranges that most of the time we don't have to hammer a
	// single cache line
	local_quota: u16,
	#[deref] // Actually, have an accessor
	tracker: MemoryQuotaTracker

  impl Participation {
	fn claim(&mut self, usize) -> Result<()> {
	   try to take usize from local_quota,
	   failing that, get from tracker,
	   possibly taking extra to put into local quota

	fn release(&mut self usize) /* infallible */ {
	   self.local_quota += usize;
	   if local quota too big, call tracker.release

  impl Drop for Participation
    decrement participation_clones
	if zero, forget the participant (subtracting its PRecord.used from TrackerInner_used)

  // gives you another view of the same particant
  impl Clone for Participation {
	// clone's local_quota is set to 0.

  impl MemoryQuotaTracker {
	pub fn new_participant(&Arc<self>, Box<dyn Participant>) -> Participation;

	fn claim(&self, pid: PId, req: usize) -> Result {
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
		let mut heap: Heap<RoughTime, PId> = ps.iter().collect();
		while self.used > self.low_water {
		  let oldest = heap.pop_lowest();
          let next_oldest = heap.peek_lowest();
		  self.ps[oldest].reclaiming = true;
	      // fudge next_oldest by something to do with number of loop iterations,
		  // to avoid one-allocation-each-time ping pong between multiple caches
		  self.ps[oldest].reclaim(next_oldest, self.used - self.low_water, ReclaimingToken { });
		  while self.ps[oldest].reclaiming { condvar wait }
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
	/// "this participant is reclaiming by collapsing completely.
	/// all memory it uses will be eventually `release`d,
	/// but this may not have happened yet".
	///
	/// The `reclaim()` method won't be called again.
	fn forget_participant(self) {
```

## Plan for caches

We may or may not use this "shared quota, delete oldest thing" notion.
If we don't, then we have something completely other
and don't reuse any of this API even the lower level.

A cache knows its oldest data and will need to know how old each thing it has, is.

On reclaim, it discards the oldest things until it reaches roughly (at least) next_oldest,
or has freed the amount requested.
If that's not enough, tracker will call reclaim again.
