# Service-side PoW

This document describes the implementation plan for service-side PoW.
Specifically, it currently talks about seed rotation and checking PoW solves,
but not yet the priority queue or control loop algorithm.

Related spec docs:

* [Onion service proof-of-work: Scheme v1, Equi-X and Blake2b][pow-v1]
* [HS PoW Common protocol][pow-common]

## What this code is intended to do

* We need some code to keep track of seeds for each TP
* There needs to be some kind of periodic timer to update those seeds
* The information about the current seed for each TP that we are publishing needs to get to the
  publisher
* When processing requests, we need to access various pieces of state (including some that are
  fundamentally global per-onion-service) in order to filter out invalid PoW solves:
  * Used nonces datastructure
  * Verifier for the correct seed (implies that access to the verifier should be keyed on `SeedHead`
    since that's all we have access to when processing a request, we don't know the TP)
  * Total effort value, which must somehow be updated upon successful requets
* At some point after we have verified the solve, the code dequeuing requests in order to send them
  to the backend that generates responses needs to be able to see the effort associated with that
  request.

## General background

* Seeds are unique to a given time period (TP) — that is, two different TPs must never have the same
  seed.
  * This is because the client uses `KP_hs_blinded_id` (which is per-TP) as a input to the PoW
    function, but the only key that the client gives us to check the solution is the first 4 bytes
    of the seed. Thus, we must have some way of ensuring that we're using the correct
    `KP_hs_blinded_id` when checking the PoW solve. We could try multiple if one of them fails, but
    that would make executing a DoS attack easier, and seems like not the best solution.
  * We make the choice to have the expiration time of the seeds be the same for all of the TPs, to
    simplify the logic. However, this could create a problem of linkability between HsDescs for
    different time periods for the same service, so we should consider whether that is a problem and
    fix it if it might be before stabilizing PoW.
* Seeds are rotated every "update period" (115 - 120 minutes long).
  * When there's a new TP, we generate a new seed for that TP, but use the same expiration time as
    we do for all the seeds.
* We need to ensure that in the set of seeds that are the current or previous seed in all TPs that
  we still have active descriptors for, the seed heads (first 4 bytes of the seed) are all unique.
  This ensures that when we receive a introduction request, we can know both what seed and TP are
  being used.

## Proposed PoW module

I am describing a version of this where the `PowManager` doesn't have a separate update loop, and
piggybacks of the update loop in `IptManager`. However, the version where `PowManager` has its own
update loop is just a small change if we decide that's better.

This `pow` module exists in the `tor-hsservice` crate:

```rust
pub(crate) struct PowManager(RwLock<State>)

struct State {
    seeds: HashMap<TimePeriod, ArrayVec<Seed, 2>>,

    verifiers: HashMap<SeedHead, Verifier>,

    next_expiration_time: SystemTime,

    used_nonces: HashMap<SeedHead, Mutex<ReplayLog<replay::ProofOfWork>>>,

    total_effort: Mutex<Effort>,

    // this will also have:
    // * REND_HANDLED
    // * HAD_QUEUE
    // * MAX_TRIMMED_EFFORT
    // As per https://spec.torproject.org/hspow-spec/common-protocol.html#service-effort-periodic
}

// type that can be serialized / deserialized to disk
// we may just want to implement the serde traits on the PowManager directly instead, if that's easy
// This will be a member of StateRecord in tor-hsservice/src/ipt_mgr/persist.rs
pub(crate) struct PowManagerRecord {
    // seeds
    // expiration time
    // total effort
    // used_nonces are not in here but will in the future be persisted via ReplayLog
}

// Both the IptManager and the Reactor will have a Arc<Mutex<PowManager>>
impl PowManager {
    // Called from IptManager::new
    // The sender/receiver pair will replace the existing rend_req_tx / rend_req_rx in lib.rs
    pub(crate) fn new(pow_replay_log_dir: InstanceRawSubdir) -> (Self, mpsc::Sender, RendQueueReceiver);

    // Both called from tor-hsservice/src/ipt_mgr/persist.rs
    pub(crate) fn to_record(&self) -> PowManagerRecord;
    // Upon loading from disk, we will delete stale replay logs from replay_log_dir,
    // using read_directory / parse_log_leafname / remove_file
    pub(crate) fn from_record(record: PowManagerRecord, replay_log_dir: InstanceRawSubdir) -> Self;

    // Called from IptManager::idempotently_progress_things_now
    // Would be called in our update loop instead of there, if we took that path
    // This will also handle deleting old ReplayLog files.
    pub(crate) fn rotate_seeds_if_expiring(&mut self, now: TrackingNow);

    // Called from publisher Reactor::upload_for_time_period
    pub(crate) fn get_pow_params(&self, time_period: TimePeriod) -> PowParams;

    // This is called from RendQueueSender
    fn check_solve(solve: ProofOfWorkV1) -> Result<(), PowSolveError>;
}

pub(crate) enum PowSolveError {
    InvalidSeedHead,
    NonceAlreadyUsed,
    InvalidSolve,
    // maybe some more detailed stuff.
    // or maybe we don't want to provide detail
}

// If PoW is not compiled in, this will be a dummy that is just a mpsc::Receiver
pub(crate) struct RendQueueReceiver {
    rx: mpsc::Receiver,

    // This may be something different / more complicated
    queue: BinaryHeap<RendRequest>,

    pow_manager: Arc<PowManager>,
}

impl Stream<RendRequest> for RendQueueReceiver;
```

## Threads and locking

We expect to have one (or possibly more, on powerful machines) PoW verification thread per IPT.

From the PoW verification threads, the following tasks must be performed:

* Checking PoW solves (requires a `&Verifier` for a given `SeedHead`)
* Updating used nonces (requires a `&mut ReplayLog`)
* Updating total effort (requires `&mut Effort`)

From the update loop, the following tasks must be performed:

* Updating the list of which `Verifier` instances are valid (requires `&mut` on the datastructure
  containing `Verifier`s)
* Updating the list of which `ReplayLog`s are valid (requires `&mut` on the datastructure
  containing `ReplayLog`s)
* Resetting total effort (requires `&mut Effort`)

The updating of `Effort` and of any particular `ReplayLog` are fundamentally synchronous operations
that must block. However, the checking of PoW solves only needs to block when the list of valid
`Verifier`s is being updated.

This can be accomplished by the proposed design, where:

* Everything that needs to be updated upon seed rotation is behind a `RwLock`.
  This allows concurrency between the verifier threads, while still letting us block to update the
  list of which `Verifier`s and `ReplayLog`s are valid.
* `ReplayLog`s will each be in a `Mutex`, allowing verification threads to exclusively update them
  when needed, without blocking unnecessarily.
* `Effort` is in a `Mutex` on its own, allowing verification threads to exclusively update it
  without blocking unnecessarily.

Essentially, this design is:

* Put everything behind a `RwLock`
* Put the things within that lock that need to be updated by verification threads behind `Mutex`es.

### Alternatives

* Put entire `PowManager` in a single `Mutex`
  * This would force PoW verification to be limited by a global lock (which would be unacceptably
    slow), unless we implemented some separate mechanism for each verification thread to only lock
    the mutex to obtain a `Arc<Verifier>`, which would force us to implement some other method to
    invalidate those on expiry. While that's definitely doable (for instance, by using a
    `TimerangeBound<Verifier>`), it seems more complex than using a `RwLock`.
  * This would also force updating the `ReplayLog` and updating the `Effort` to block each other,
    which, while only a small slowdown, would be better avoided.
* Put entire `HashMap<SeedHead, ReplayLog>` in a `Mutex`
  * This would probably work fine, it just reduces concurrency without benefit.

## Making `ReplayLog` generic

Make `ReplayLog` generic over types that implement the `ReplayLogType` trait:

```rust
trait ReplayLogType {
    type Name; // IptLocalId, Seed
    type Message; // Introduce2, Nonce

    fn format_filename(name: Name) -> String;
    fn hash_message(message: Message) -> H;
    fn parse_log_leafname(leaf: &OsStr) -> Result<(Name, &str), Cow<'static, str>>;
}

struct IptReplayLog;
struct ProofOfWorkReplayLog;
```

Replace `IptLocalId` and `Introduce2` in `ReplayLog<T>` with `T::Name` and `T::message`.

It would also be good to add a method to `ReplayLog` to delete old log files:

```rust
// Not sure what the error type should be
fn cleanup_log_files(&self, exempt: Vec<Self::Name>) -> Result<(), _>;
```

That way, the `PowManager` code does not need to keep any details about the log directory.

[pow-v1]: https://spec.torproject.org/hspow-spec/v1-equix.html
[pow-common]: https://spec.torproject.org/hspow-spec/common-protocol.html
