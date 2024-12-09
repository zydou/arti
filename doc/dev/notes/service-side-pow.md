# Service-side PoW

This document describes the implementation plan for service-side PoW.
Specifically, it currently talks about seed rotation and checking PoW solves,
but not yet the priority queue or control loop algorithm.

Related spec docs:

* [Onion service proof-of-work: Scheme v1, Equi-X and Blake2b][pow-v1]
* [HS PoW Common protocol][pow-common]

## Seed rotation

### Conceptual overview

* Seeds are unique to a given time period (TP) — that is, two different TPs must never have the same seed.
  * This is because the client uses `KP_hs_blinded_id` (which is per-TP) as a input to the PoW function, but the only key that the client gives us to check the solution is the first 4 bytes of the seed. Thus, we must have some way of ensuring that we're using the correct `KP_hs_blinded_id` when checking the PoW solve. We could try multiple if one of them fails, but that would make executing a DoS attack easier, and seems like not the best solution.
  * We make the choice to have the expiration time of the seeds be the same for all of the TPs, to simplify the logic. The constraint could be relaxed if there's a good reason to do so.
* Seeds are rotated every "update period" (115 - 120 minutes long).
  * When there's a new TP, we generate a new seed for that TP, but use the same expiration time as we do for all the seeds.
* We need to ensure that in the set of seeds that are the current or previous seed in all TPs that we still have active descriptors for, the seed heads (first 4 bytes of the seed) are all unique. This ensures that when we receive a introduction request, we can know both what seed and TP are being used.

### Code modifications

(Current draft MR: [!2657][2657])

* We will make a new `PowState` struct that will contain:
  * The various seeds, as a `HashMap<TimePeriod, (Seed, Option<Seed>)>` or similar. The first `Seed` is the current one, the second `Option<Seed>` is the previously used seed.
  * The expiration time of the current seed.
  * `PowState` will contain more than just this as described in the next section.
* The `IptManager`'s `State` will contain the `PowState`
* We need to decide how to communicate the seeds to the publisher. Here are some options:
  1. Have the publisher be the thing that owns the `PowState` instead of the `IptManager`, and get it via a method on `PowState`. I initially had this design but decided to move the `PowState` to the `IptManager` after discussion with Diziet.
  2. Have the publisher have a `Arc<Mutex<PowState>>`, and call a method on it to get the seed for a given TP
    * This method will take a list of TPs that the publisher gets from `NetDir::hs_all_time_periods`, and will also be responsible for cleaning up old seeds that are not in that set.
  3. Communicate via `IptSet`, by adding a `HashMap<TimePeriod, Option<PowParams>>`. That hashmap will be updated in `IptManager::idempotently_progress_things_now`, using `NetDir::hs_all_time_periods` to ensure we generate PowParams for all relevant time periods. This has the downside that there could be a race where a new period is entered after the `IptSet` was updated but before it was published, and we would need to figure out how to handle that. The `PowParams` are in a `Option`al in order to be able to distinguish that from PoW being disabled.

In case 1, the `IptManager` would likely need to end up with a `Arc<Mutex<PowState>>` or similar (in order to facilitate the checking of PoW seeds), so option 1 and 2 end up being basically the same, with both the publisher and `IptManager` having a `Arc<Mutex<PowState>>`.

I will proceed describing a design using option 2, having the publisher and `IptManager` both have a `Arc<Mutex<PowState>>`, since that seems like the simplest and least brittle design to me.

The actual rotation of the seeds and updating of the expiry time will happen in `IptManager::idempotently_progress_things_now`. It could happen in a lot of places, but `IptManager` has convenient infrastructure for doing so and is a perfectly reasonable place to do it.

## Checking solves

### Conceptual overview

* When we receive a INTRODUCE2 request, we want to verify that the `SeedHead` is one that we expect (either the current or previous seed for a TP that we are expecting). Figuring out this seed head will also tell us what TP the solve is for.
* We update our list of previously used nonces for that `SeedHead`, rejecting the request if it is using a previously-used nonce.
* We check the PoW solve, accepting the request if it is valid, and rejecting it if not.
* If the request was valid, we update our bookkeeping about the total effort we've seen.

### Code modifications

* We create a `IptPowInstance` struct as follows:

```rust
/// Data structure used by each IPT to verify PoW solves in incoming requests.
///
/// This largely communicates with [`PowState`], but is separate from that so
/// that each IPT can have its own `Verifier` instances without any locking.
struct IptPowInstance {
    /// A [`Verifier`] instance for every currently valid [`SeedHead`].
    verifiers: HashMap<SeedHead, Verifier>,
    /// A channel on which we receive new [`Seed`]s (from [`PowState`]), to be
    /// added to `verifiers`, as well as information about old seeds that have
    /// expired and must be removed.
    seed_updates_rx: mpsc::Receiver<SeedUpdate>,
    /// A channel on which we send information about the [`Effort`] that was
    /// set for valid requests.
    valid_efforts_tx: mpsc::Sender<Effort>,
    /// Information about which [`Nonce`]s have been seen so far.
    // TODO: Replace with something based on ReplayLog
    used_nonces: Arc<Mutex<HashSet<(SeedHead, Nonce)>>>,
}

/// Information sent from [`PowState`] to [`IptPowInstance`] about a new
/// [`Seed`], as well as about old seeds that have expired and should no longer
/// be accepted.
///
/// These are bundled into a single update, because when we generate a new seed
/// we ensure it doesn't collide with a previous seed, but we don't check about
/// seeds prior to that. Thus, we want to make sure that the expiration and
/// addition of a new seed happen atomically.
struct SeedUpdate {
    /// The new [`Seed`] to start accepting.
    new_seed: Seed,
    /// The [`TimePeriod`] which this new [`Seed`] is associated with.
    time_period: TimePeriod,
    /// A [`Seed`] that should be expired. This is not the "previous" seed (which
    /// we still want to accept requests with), but the one before that.
    expire_old_seed: Option<SeedHead>,
}
```

* Each `RendRequestContext` has a `IptPowInstance` object
  * These `IptPowInstance` objects are created by calling `PowState::new_ipt_pow_instance`.
* To `PowState`, we add:
  * A `Vec<mpsc::Sender<SeedUpdate>>`, to which we will send notices when we update the valid seeds
  * A `Vec<mpsc::Receiver<Effort>>`, which we will use to update bookkeeping.
  * A `Effort` "`total_effort`", as described as "`TOTAL_EFFORT`" in the [PoW common protocol][pow-common].
  * Other bookeeping required for the control loop algorithm described in the [PoW common protocol][pow-common] (these currently do exist in [!2657][2657], but I'm not describing them here as this document does not describe the control loop yet)
* In `IptMsgHandler::handle_msg`, the `IptPowInstance` is used to check the PoW solve, as described in the "conceptual overview" above.

[pow-v1]: https://spec.torproject.org/hspow-spec/v1-equix.html
[pow-common]: https://spec.torproject.org/hspow-spec/common-protocol.html
[2657]: https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/2657
