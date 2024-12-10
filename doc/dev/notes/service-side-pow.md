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
pub(crate) struct PowManager {
    seeds: postage::watch::Sender<HashMap<TimePeriod, ArrayVec<Seed, 2>>>,
    expiration_time: SystemTime,
    used_nonces: Arc<Mutex<HashSet<(SeedHead, Nonce)>>>,
    total_effort: Arc<Mutex<Effort>>,
    // this will also have:
    // * REND_HANDLED
    // * HAD_QUEUE
    // * MAX_TRIMMED_EFFORT
    // As per https://spec.torproject.org/hspow-spec/common-protocol.html#service-effort-periodic
}

// type that can be serialized / deserialized to disk
// we may just want to implement the serde traits on the PowManager directly instead, if that's easy
pub(crate) struct PowManagerRecord {
    // seeds
    // expiration time
    // total effort
    // used_nonces are not in here but will in the future be persisted via ReplayLog
}

// Both the IptManager and the Reactor will have a Arc<Mutex<PowManager>>
impl PowManager {
    // Called from IptManager::new
    pub(crate) fn new() -> Self;

    // Called from tor-hsservice/src/ipt_mgr/persist.rs
    pub(crate) fn to_record(&self) -> PowManagerRecord;
    pub(crate) fn from_record(record: PowManagerRecord) -> Self;

    // Called from IptManager::idempotently_progress_things_now
    // Would be called in our update loop instead of there, if we took that path
    pub(crate) fn rotate_seeds_if_expiring(&mut self, now: TrackingNow);

    // Called from IptManager::idempotently_progress_things_now
    pub(crate) fn make_ipt_pow_instance(&self) -> IptPowInstance;

    // Called from publisher Reactor::upload_for_time_period
    pub(crate) fn get_pow_params(&self, time_period: TimePeriod) -> PowParams;
}

// Each RendRequestContext will have one of these
pub(crate) struct IptPowInstance {
    verifiers: HashMap<SeedHead, Verifier>,
    seeds_rx: postage::watch::Receiver<HashMap<TimePeriod, ArrayVec<Seed, 2>>>,
    used_nonces: Arc<Mutex<HashSet<(SeedHead, Nonce)>>>,
    total_effort: Arc<Mutex<Effort>>,
}

impl IptPowInstance {
    // This is called from IptMsgHandler::handle_msg
    pub(crate) fn check_solve(solve: ProofOfWorkV1) -> Result<(), PowSolveError>;
}

pub(crate) enum PowSolveError {
    InvalidSeedHead,
    NonceAlreadyUsed,
    InvalidSolve,
    // maybe some more detailed stuff.
    // or maybe we don't want to provide detail
}
```

## Remaining questions

* How should the priority queue of accepted requests work? `Arc<Mutex<BinaryHeap>>`? Something else?

[pow-v1]: https://spec.torproject.org/hspow-spec/v1-equix.html
[pow-common]: https://spec.torproject.org/hspow-spec/common-protocol.html
