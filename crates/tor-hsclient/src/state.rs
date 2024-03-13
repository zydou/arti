//! Implement a cache for onion descriptors and the facility to remember a bit
//! about onion service history.

use std::fmt::Debug;
use std::mem;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures::task::{SpawnError, SpawnExt as _};
use futures::FutureExt as _;

use async_trait::async_trait;
use educe::Educe;
use either::Either::{self, *};
use postage::stream::Stream as _;
use tracing::{debug, error, trace};

use safelog::sensitive as sv;
use tor_basic_utils::define_accessor_trait;
use tor_circmgr::isolation::Isolation;
use tor_error::{debug_report, error_report, internal, Bug, ErrorReport as _};
use tor_hscrypto::pk::HsId;
use tor_netdir::NetDir;
use tor_rtcompat::Runtime;

use crate::isol_map;
use crate::{ConnError, HsClientConnector, HsClientSecretKeys};

slotmap::new_key_type! {
    struct TableIndex;
}

/// Configuration, currently just some retry parameters
#[derive(Default, Debug)]
// This is not really public.
// It has to be `pub` because it appears in one of the methods in `MockableConnectorData`.
// That has to be because that trait is a bound on a parameter for `HsClientConnector`.
// `Config` is not re-exported.  (This is isomorphic to the trait sealing pattern.)
//
// This means that this struct cannot live in the crate root, so we put it here.
pub struct Config {
    /// Retry parameters
    pub(crate) retry: tor_circmgr::CircuitTiming,
}

define_accessor_trait! {
    /// Configuration for an HS client connector
    ///
    /// If the HS client connector gains new configurabilities, this trait will gain additional
    /// supertraits, as an API break.
    ///
    /// Prefer to use `TorClientConfig`, which will always implement this trait.
    //
    // This arrangement is very like that for `CircMgrConfig`.
    pub trait HsClientConnectorConfig {
        circuit_timing: tor_circmgr::CircuitTiming,
    }
}

/// Number of times we're willing to iterate round the state machine loop
///
/// **Not** the number of retries of failed descriptor downloads, circuits, etc.
///
/// The state machine loop is a condition variable loop.
/// It repeatedly transforms the [`ServiceState`] to try to get to `Open`,
/// converting stale data to `Closed` and `Closed` to `Working`, and so on.
/// This ought only to go forwards so in principle we could use an infinite loop.
/// But if we have a logic error, we want to crash eventually.
/// The `rechecks` counter is for detecting such a situation.
///
/// This is fairly arbitrary, but we shouldn't get anywhere near it.
///
/// Note that this is **not** a number of operational retries
/// of fallible retriable operations.
/// Such retries are handled in [`connect.rs`](crate::connect).
const MAX_RECHECKS: u32 = 10;

/// C Tor `MaxCircuitDirtiness`
///
/// As per
///    <https://gitlab.torproject.org/tpo/core/arti/-/issues/913#note_2914433>
///
/// And C Tor's `tor(1)`, which says:
///
/// > MaxCircuitDirtiness NUM
/// >
/// > Feel free to reuse a circuit that was first used at most NUM
/// > seconds ago, but never attach a new stream to a circuit that is
/// > too old.  For hidden services, this applies to the last time a
/// > circuit was used, not the first.  Circuits with streams
/// > constructed with SOCKS authentication via SocksPorts that have
/// > KeepAliveIsolateSOCKSAuth also remain alive for
/// > MaxCircuitDirtiness seconds after carrying the last such
/// > stream. (Default: 10 minutes)
///
/// However, we're not entirely sure this is the right behaviour.
/// See <https://gitlab.torproject.org/tpo/core/arti/-/issues/916>
///
// TODO SPEC: Explain C Tor `MaxCircuitDirtiness` behaviour
//
// TODO HS CFG: This should be configurable somehow
const RETAIN_CIRCUIT_AFTER_LAST_USE: Duration = Duration::from_secs(10 * 60);

/// How long to retain cached data about a hidden service
///
/// This is simply to reclaim space, not for correctness.
/// So we only check this during housekeeping, not operation.
///
/// The starting point for this interval is the last time we used the data,
/// or a circuit derived from it.
///
/// Note that this is a *maximum* for the length of time we will retain a descriptor;
/// HS descriptors' lifetimes (as declared in the descriptor) *are* honoured;
/// but that's done by the code in `connect.rs`, not here.
///
/// We're not sure this is the right value.
/// See <https://gitlab.torproject.org/tpo/core/arti/-/issues/916>
//
// TODO SPEC: State how long IPT and descriptor data should be retained after use
//
// TODO HS CFG: Perhaps this should be configurable somehow?
const RETAIN_DATA_AFTER_LAST_USE: Duration = Duration::from_secs(48 * 3600 /*hours*/);

/// Hidden services;, our connections to them, and history of connections, etc.
///
/// Table containing state of our ideas about services.
/// Data structure is keyed (indexed) by:
///  * `HsId`, hidden service identity
///  * any secret keys we are to use
///  * circuit isolation
///
/// We treat different values for any of the above as completely independent,
/// except that we try isolation joining (narrowing) if everything else matches.
///
/// In other words,
///  * Two HS connection requests cannot share state and effort
///    (descriptor downloads, descriptors, intro pt history)
///    unless the client authg keys to be used are the same.
///  * This criterion is checked before looking at isolations,
///    which may further restrict sharing:
///    Two HS connection requests will only share state subject to isolations.
///
/// Here "state and effort" includes underlying circuits such as hsdir circuits,
/// since each HS connection state will use `launch_specific_isolated` for those.
#[derive(Default, Debug)]
pub(crate) struct Services<D: MockableConnectorData> {
    /// The actual records of our connections/attempts for each service, as separated
    records: isol_map::MultikeyIsolatedMap<TableIndex, HsId, HsClientSecretKeys, ServiceState<D>>,

    /// Configuration
    ///
    /// `Arc` so that it can be shared with individual hs connector tasks
    config: Arc<Config>,
}

/// Entry in the 2nd-level lookup array
#[allow(dead_code)] // This alias is here for documentation if nothing else
type ServiceRecord<D> = isol_map::Record<HsClientSecretKeys, ServiceState<D>>;

/// Value in the `Services` data structure
///
/// State and history of of our connections, including connection to any connection task.
///
/// `last_used` is used to expire data eventually.
//
// TODO unify this with channels and circuits.  See arti#778.
#[derive(Educe)]
#[educe(Debug)]
enum ServiceState<D: MockableConnectorData> {
    /// We don't have a circuit
    Closed {
        /// The state
        data: D,
        /// Last time we touched this, including reuse
        last_used: Instant,
    },
    /// We have an open circuit, which we can (hopefully) just use
    Open {
        /// The state
        data: D,
        /// The circuit
        #[educe(Debug(ignore))]
        circuit: Arc<D::ClientCirc>,
        /// Last time we touched this, including reuse
        ///
        /// This is set when we created the circuit, and updated when we
        /// hand out this circuit again in response to a new request.
        ///
        /// We believe this mirrors C Tor behaviour;
        /// see [`RETAIN_CIRCUIT_AFTER_LAST_USE`].
        last_used: Instant,
        /// We have a task that will close the circuit when required
        ///
        /// This field serves to require construction sites of Open
        /// to demonstrate that there *is* an expiry task.
        /// In the future, it may also serve to cancel old expiry tasks.
        circuit_expiry_task: CircuitExpiryTask,
    },
    /// We have a task trying to find the service and establish the circuit
    ///
    /// CachedData is owned by the task.
    Working {
        /// Signals instances of `get_or_launch_connection` when the task completes
        barrier_recv: postage::barrier::Receiver,
        /// Where the task will store the error.
        ///
        /// Lock hierarchy: this lock is "inside" the big lock on `Services`.
        error: Arc<Mutex<Option<ConnError>>>,
    },
    /// Dummy value for use with temporary mem replace
    Dummy,
}

impl<D: MockableConnectorData> ServiceState<D> {
    /// Make a new (blank) `ServiceState::Closed`
    fn blank(runtime: &impl Runtime) -> Self {
        ServiceState::Closed {
            data: D::default(),
            last_used: runtime.now(),
        }
    }
}

/// "Continuation" return type from `obtain_circuit_or_continuation_info`
type Continuation = (Arc<Mutex<Option<ConnError>>>, postage::barrier::Receiver);

/// Represents a task which is waiting to see when the circuit needs to be expired
///
/// TODO: Replace this with a task handle that cancels the task when dropped.
/// Until then, if the circuit is closed before then, the expiry task will
/// uselessly wake up some time later.
#[derive(Debug)] // Not Clone
struct CircuitExpiryTask {}
// impl Drop already, partly to allow explicit drop(CircuitExpiryTask) without clippy complaint
impl Drop for CircuitExpiryTask {
    fn drop(&mut self) {}
}

/// Obtain a circuit from the `Services` table, or return a continuation
///
/// This is the workhorse function for `get_or_launch_connection`.
///
/// `get_or_launch_connection`, together with `obtain_circuit_or_continuation_info`,
/// form a condition variable loop:
///
/// We check to see if we have a circuit.  If so, we return it.
/// Otherwise, we make sure that a circuit is being constructed,
/// and then go into a condvar wait;
/// we'll be signaled when the construction completes.
///
/// So the connection task we spawn does not return the circuit, or error,
/// via an inter-task stream.
/// It stores it in the data structure and wakes up all the client tasks.
/// (This means there is only one success path for the client task code.)
///
/// There are some wrinkles:
///
/// ### Existence of this as a separate function
///
/// The usual structure for a condition variable loop would be something like this:
///
/// ```rust,ignore
/// loop {
///    test state and maybe break;
///    cv.wait(guard).await; // consumes guard, unlocking after enqueueing us as a waiter
///    guard = lock();
/// }
/// ```
///
/// However, Rust does not currently understand that the mutex is not
/// actually a captured variable held across an await point,
/// when the variable is consumed before the await, and re-stored afterwards.
/// As a result, the async future becomes erroneously `!Send`:
/// <https://github.com/rust-lang/rust/issues/104883>.
/// We want the unstable feature `-Zdrop-tracking`:
/// <https://github.com/rust-lang/rust/issues/97331>.
///
/// Instead, to convince the compiler, we must use a scope-based drop of the mutex guard.
/// That means converting the "test state and maybe break" part into a sub-function.
/// That's what this function is.
///
/// It returns `Right` if the loop should be exited, returning the circuit to the caller.
/// It returns `Left` if the loop needs to do a condition variable wait.
///
/// ### We're using a barrier as a condition variable
///
/// We want to be signaled when the task exits.  Indeed, *only* when it exits.
/// This functionality is most conveniently in a `postage::barrier`.
///
/// ### Nested loops
///
/// Sometimes we want to go round again *without* unlocking.
/// Sometimes we must unlock and wait and relock.
///
/// The drop tracking workaround (see above) means we have to do these two
/// in separate scopes.
/// So there are two nested loops: one here, and one in `get_or_launch_connection`.
/// They both use the same backstop rechecks counter.
fn obtain_circuit_or_continuation_info<D: MockableConnectorData>(
    connector: &HsClientConnector<impl Runtime, D>,
    netdir: &Arc<NetDir>,
    hsid: &HsId,
    secret_keys: &HsClientSecretKeys,
    table_index: TableIndex,
    rechecks: &mut impl Iterator,
    mut guard: MutexGuard<'_, Services<D>>,
) -> Result<Either<Continuation, Arc<D::ClientCirc>>, ConnError> {
    let blank_state = || ServiceState::blank(&connector.runtime);

    for _recheck in rechecks {
        let record = guard
            .records
            .by_index_mut(table_index)
            .ok_or_else(|| internal!("guard table entry vanished!"))?;
        let state = &mut **record;

        trace!("HS conn state: {state:?}");

        let (data, barrier_send) = match state {
            ServiceState::Open {
                data: _,
                circuit,
                last_used,
                circuit_expiry_task: _,
            } => {
                let now = connector.runtime.now();
                if !D::circuit_is_ok(circuit) {
                    // Well that's no good, we need a fresh one, but keep the data
                    let data = match mem::replace(state, ServiceState::Dummy) {
                        ServiceState::Open {
                            data,
                            last_used: _,
                            circuit: _,
                            circuit_expiry_task: _,
                        } => data,
                        _ => panic!("state changed between matches"),
                    };
                    *state = ServiceState::Closed {
                        data,
                        last_used: now,
                    };
                    continue;
                }
                *last_used = now;
                // No need to tell expiry task about revised expiry time;
                // it will see the new last_used when it wakes up at the old expiry time.

                return Ok::<_, ConnError>(Right(circuit.clone()));
            }
            ServiceState::Working {
                barrier_recv,
                error,
            } => {
                if !matches!(
                    barrier_recv.try_recv(),
                    Err(postage::stream::TryRecvError::Pending)
                ) {
                    // This information is stale; the task no longer exists.
                    // We want information from a fresh task.
                    *state = blank_state();
                    continue;
                }
                let barrier_recv = barrier_recv.clone();

                // This clone of the error field Arc<Mutex<..>> allows us to collect errors
                // which happened due to the currently-running task, which we have just
                // found exists.  Ie, it will see errors that occurred after we entered
                // `get_or_launch`.  Stale errors, from previous tasks, were cleared above.
                let error = error.clone();

                // Wait for the task to complete (at which point it drops the barrier)
                return Ok(Left((error, barrier_recv)));
            }
            ServiceState::Closed { .. } => {
                let (barrier_send, barrier_recv) = postage::barrier::channel();
                let data = match mem::replace(
                    state,
                    ServiceState::Working {
                        barrier_recv,
                        error: Arc::new(Mutex::new(None)),
                    },
                ) {
                    ServiceState::Closed { data, .. } => data,
                    _ => panic!("state changed between matches"),
                };
                (data, barrier_send)
            }
            ServiceState::Dummy => {
                *state = blank_state();
                return Err(internal!("HS connector found dummy state").into());
            }
        };

        // Make a connection
        let runtime = &connector.runtime;
        let connector = (*connector).clone();
        let config = guard.config.clone();
        let netdir = netdir.clone();
        let secret_keys = secret_keys.clone();
        let hsid = *hsid;
        let connect_future = async move {
            let mut data = data;

            let got = AssertUnwindSafe(D::connect(
                &connector,
                netdir,
                config,
                hsid,
                &mut data,
                secret_keys,
            ))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| {
                data = D::default();
                Err(internal!("hidden service connector task panicked!").into())
            });
            let now = connector.runtime.now();
            let last_used = now;

            let got = got.and_then(|circuit| {
                let circuit_expiry_task = ServiceState::spawn_circuit_expiry_task(
                    &connector,
                    hsid,
                    table_index,
                    last_used,
                    now,
                )
                .map_err(|cause| ConnError::Spawn {
                    spawning: "circuit expiry task",
                    cause: cause.into(),
                })?;
                Ok((circuit, circuit_expiry_task))
            });

            let got_error = got.as_ref().map(|_| ()).map_err(Clone::clone);

            // block for handling inability to store
            let stored = async {
                let mut guard = connector.services()?;
                let record = guard
                    .records
                    .by_index_mut(table_index)
                    .ok_or_else(|| internal!("HS table entry removed while task running"))?;
                // Always match this, so we check what we're overwriting
                let state = &mut **record;
                let error_store = match state {
                    ServiceState::Working { error, .. } => error,
                    _ => return Err(internal!("HS task found state other than Working")),
                };

                match got {
                    Ok((circuit, circuit_expiry_task)) => {
                        *state = ServiceState::Open {
                            data,
                            circuit,
                            last_used,
                            circuit_expiry_task,
                        }
                    }
                    Err(error) => {
                        let mut error_store = error_store
                            .lock()
                            .map_err(|_| internal!("Working error poisoned, cannot store error"))?;
                        *error_store = Some(error);
                    }
                };

                Ok(())
            }
            .await;

            match (got_error, stored) {
                (Ok::<(), ConnError>(()), Ok::<(), Bug>(())) => {}
                (Err(got_error), Ok(())) => {
                    debug_report!(got_error, "HS connection failure for {}", sv(hsid));
                }
                (Ok(()), Err(bug)) => {
                    error_report!(
                        bug,
                        "internal error storing built HS circuit for {}",
                        sv(hsid)
                    );
                }
                (Err(got_error), Err(bug)) => {
                    // We're reporting two errors, so we'll construct the event
                    // manually.
                    error!(
                        "internal error storing HS connection error for {}: {}; {}",
                        sv(hsid),
                        got_error.report(),
                        bug.report(),
                    );
                }
            };
            drop(barrier_send);
        };
        runtime
            .spawn_obj(Box::new(connect_future).into())
            .map_err(|cause| ConnError::Spawn {
                spawning: "connection task",
                cause: cause.into(),
            })?;
    }

    Err(internal!("HS connector state management malfunction (exceeded MAX_RECHECKS").into())
}

impl<D: MockableConnectorData> Services<D> {
    /// Create a new empty `Services`
    pub(crate) fn new(config: Config) -> Self {
        Services {
            records: Default::default(),
            config: Arc::new(config),
        }
    }

    /// Connect to a hidden service
    // We *do* drop guard.  There is *one* await point, just after drop(guard).
    pub(crate) async fn get_or_launch_connection(
        connector: &HsClientConnector<impl Runtime, D>,
        netdir: &Arc<NetDir>,
        hs_id: HsId,
        isolation: Box<dyn Isolation>,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Arc<D::ClientCirc>, ConnError> {
        let blank_state = || ServiceState::blank(&connector.runtime);

        let mut rechecks = 0..MAX_RECHECKS;

        let mut obtain = |table_index, guard| {
            obtain_circuit_or_continuation_info(
                connector,
                netdir,
                &hs_id,
                &secret_keys,
                table_index,
                &mut rechecks,
                guard,
            )
        };

        let mut got;
        let table_index;
        {
            let mut guard = connector.services()?;
            let services = &mut *guard;

            trace!("HS conn get_or_launch: {hs_id:?} {isolation:?} {secret_keys:?}");
            //trace!("HS conn services: {services:?}");

            table_index =
                services
                    .records
                    .index_or_insert_with(&hs_id, &secret_keys, isolation, blank_state);

            let guard = guard;
            got = obtain(table_index, guard);
        }
        loop {
            // The parts of this loop which run after a `Left` is returned
            // logically belong in the case in `obtain_circuit_or_continuation_info`
            // for `ServiceState::Working`, where that function decides we need to wait.
            // This code has to be out here to help the compiler's drop tracking.
            {
                // Block to scope the acquisition of `error`, a guard
                // for the mutex-protected error field in the state,
                // and, for neatness, barrier_recv.

                let (error, mut barrier_recv) = match got? {
                    Right(ret) => return Ok(ret),
                    Left(continuation) => continuation,
                };

                barrier_recv.recv().await;

                let error = error
                    .lock()
                    .map_err(|_| internal!("Working error poisoned"))?;
                if let Some(error) = &*error {
                    return Err(error.clone());
                }
            }

            let guard = connector.services()?;

            got = obtain(table_index, guard);
        }
    }

    /// Perform housekeeping - delete data we aren't interested in any more
    pub(crate) fn run_housekeeping(&mut self, now: Instant) {
        self.expire_old_data(now);
    }

    /// Delete data we aren't interested in any more
    fn expire_old_data(&mut self, now: Instant) {
        self.records
            .retain(|hsid, record, _table_index| match &**record {
                ServiceState::Closed { data: _, last_used } => {
                    let Some(expiry_time) = last_used.checked_add(RETAIN_DATA_AFTER_LAST_USE)
                    else {
                        return false;
                    };
                    now <= expiry_time
                }
                ServiceState::Open { .. } | ServiceState::Working { .. } => true,
                ServiceState::Dummy { .. } => {
                    error!("found dummy data during HS housekeeping, for {}", sv(hsid));
                    false
                }
            });
    }
}

impl<D: MockableConnectorData> ServiceState<D> {
    /// Spawn a task that will drop our reference to the rendezvous circuit
    /// at `table_index` when it has gone too long without any use.
    ///
    /// According to [`RETAIN_CIRCUIT_AFTER_LAST_USE`].
    //
    // As it happens, this function is always called with `last_used` equal to `now`,
    // but we pass separate arguments for clarity.
    fn spawn_circuit_expiry_task(
        connector: &HsClientConnector<impl Runtime, D>,
        hsid: HsId,
        table_index: TableIndex,
        last_used: Instant,
        now: Instant,
    ) -> Result<CircuitExpiryTask, SpawnError> {
        /// Returns the duration until expiry, or `None` if it should expire now
        fn calculate_expiry_wait(last_used: Instant, now: Instant) -> Option<Duration> {
            let expiry = last_used
                .checked_add(RETAIN_CIRCUIT_AFTER_LAST_USE)
                .or_else(|| {
                    error!("time overflow calculating HS circuit expiry, killing circuit!");
                    None
                })?;
            let wait = expiry.checked_duration_since(now).unwrap_or_default();
            if wait == Duration::ZERO {
                return None;
            }
            Some(wait)
        }

        let mut maybe_wait = calculate_expiry_wait(last_used, now);
        let () = connector.runtime.spawn({
            let connector = connector.clone();
            async move {
                // This loop is slightly odd.  The wait ought naturally to be at the end,
                // but that would mean a useless re-lock and re-check right after creation,
                // or jumping into the middle of the loop.
                loop {
                    if let Some(yes_wait) = maybe_wait {
                        connector.runtime.sleep(yes_wait).await;
                    }
                    // If it's None, we can't rely on that to say we should expire it,
                    // since that information crossed a time when we didn't hold the lock.

                    let Ok(mut guard) = connector.services() else {
                        break;
                    };
                    let Some(record) = guard.records.by_index_mut(table_index) else {
                        break;
                    };
                    let state = &mut **record;
                    let last_used = match state {
                        ServiceState::Closed { .. } => break,
                        ServiceState::Open { last_used, .. } => *last_used,
                        ServiceState::Working { .. } => break, // someone else will respawn
                        ServiceState::Dummy => break,          // someone else will (report and) fix
                    };
                    maybe_wait = calculate_expiry_wait(last_used, connector.runtime.now());
                    if maybe_wait.is_none() {
                        match mem::replace(state, ServiceState::Dummy) {
                            ServiceState::Open {
                                data,
                                circuit,
                                last_used,
                                circuit_expiry_task,
                            } => {
                                debug!("HS connection expires: {hsid}");
                                drop(circuit);
                                drop(circuit_expiry_task); // that's us
                                *state = ServiceState::Closed { data, last_used };
                                break;
                            }
                            _ => panic!("state now {state:?} even though we just saw it Open"),
                        }
                    }
                }
            }
        })?;
        Ok(CircuitExpiryTask {})
    }
}

/// Mocking for actual HS connection work, to let us test the `Services` state machine
//
// Does *not* mock circmgr, chanmgr, etc. - those won't be used by the tests, since our
// `connect` won't call them.  But mocking them pollutes many types with `R` and is
// generally tiresome.  So let's not.  Instead the tests can make dummy ones.
//
// This trait is actually crate-private, since it isn't re-exported, but it must
// be `pub` because it appears as a default for a type parameter in HsClientConnector.
#[async_trait]
pub trait MockableConnectorData: Default + Debug + Send + Sync + 'static {
    /// Client circuit
    type ClientCirc: Sync + Send + 'static;

    /// Mock state
    type MockGlobalState: Clone + Sync + Send + 'static;

    /// Connect
    async fn connect<R: Runtime>(
        connector: &HsClientConnector<R, Self>,
        netdir: Arc<NetDir>,
        config: Arc<Config>,
        hsid: HsId,
        data: &mut Self,
        secret_keys: HsClientSecretKeys,
    ) -> Result<Arc<Self::ClientCirc>, ConnError>;

    /// Is circuit OK?  Ie, not `.is_closing()`.
    fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool;
}

#[cfg(test)]
pub(crate) mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::*;
    use futures::{poll, SinkExt};
    use std::fmt;
    use std::task::Poll::{self, *};
    use tokio::pin;
    use tokio_crate as tokio;
    use tor_rtcompat::{test_with_one_runtime, SleepProvider};
    use tor_rtmock::MockRuntime;
    use tracing_test::traced_test;

    use ConnError as E;

    #[derive(Debug, Default)]
    struct MockData {
        connect_called: usize,
    }

    /// Type indicating what our `connect()` should return; it always makes a fresh MockCirc
    type MockGive = Poll<Result<(), E>>;

    #[derive(Debug, Clone)]
    struct MockGlobalState {
        // things will appear here when we have more sophisticated tests
        give: postage::watch::Receiver<MockGive>,
    }

    #[derive(Clone, Educe)]
    #[educe(Debug)]
    struct MockCirc {
        #[educe(Debug(method = "debug_arc_mutex"))]
        ok: Arc<Mutex<bool>>,
        connect_called: usize,
    }

    fn debug_arc_mutex(val: &Arc<Mutex<impl Debug>>, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "@{:?}", Arc::as_ptr(val))?;
        let guard = val.lock();
        let guard = guard.or_else(|g| {
            write!(f, ",POISON")?;
            Ok::<_, fmt::Error>(g.into_inner())
        })?;
        write!(f, " ")?;
        Debug::fmt(&*guard, f)
    }

    impl PartialEq for MockCirc {
        fn eq(&self, other: &MockCirc) -> bool {
            Arc::ptr_eq(&self.ok, &other.ok)
        }
    }

    impl MockCirc {
        fn new(connect_called: usize) -> Self {
            let ok = Arc::new(Mutex::new(true));
            MockCirc { ok, connect_called }
        }
    }

    #[async_trait]
    impl MockableConnectorData for MockData {
        type ClientCirc = MockCirc;
        type MockGlobalState = MockGlobalState;

        async fn connect<R: Runtime>(
            connector: &HsClientConnector<R, MockData>,
            _netdir: Arc<NetDir>,
            _config: Arc<Config>,
            _hsid: HsId,
            data: &mut MockData,
            _secret_keys: HsClientSecretKeys,
        ) -> Result<Arc<Self::ClientCirc>, E> {
            data.connect_called += 1;
            let make = {
                let connect_called = data.connect_called;
                move |()| Arc::new(MockCirc::new(connect_called))
            };
            let mut give = connector.mock_for_state.give.clone();
            if let Ready(ret) = &*give.borrow() {
                return ret.clone().map(make);
            }
            loop {
                match give.recv().await.expect("EOF on mock_global_state stream") {
                    Pending => {}
                    Ready(ret) => return ret.map(make),
                }
            }
        }

        fn circuit_is_ok(circuit: &Self::ClientCirc) -> bool {
            *circuit.ok.lock().unwrap()
        }
    }

    /// Makes a non-empty `HsClientSecretKeys`, containing (somehow) `kk`
    fn mk_keys(kk: u8) -> HsClientSecretKeys {
        let mut ss = [0_u8; 32];
        ss[0] = kk;
        let keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&ss);
        let mut b = HsClientSecretKeysBuilder::default();
        #[allow(deprecated)]
        b.ks_hsc_intro_auth(keypair.into());
        b.build().unwrap()
    }

    fn mk_hsconn<R: Runtime>(
        runtime: R,
    ) -> (
        HsClientConnector<R, MockData>,
        HsClientSecretKeys,
        postage::watch::Sender<MockGive>,
    ) {
        let chanmgr = tor_chanmgr::ChanMgr::new(
            runtime.clone(),
            &Default::default(),
            tor_chanmgr::Dormancy::Dormant,
            &Default::default(),
        );
        let guardmgr = tor_guardmgr::GuardMgr::new(
            runtime.clone(),
            tor_persist::TestingStateMgr::new(),
            &tor_guardmgr::TestConfig::default(),
        )
        .unwrap();

        let circmgr = tor_circmgr::CircMgr::new(
            &tor_circmgr::TestConfig::default(),
            tor_persist::TestingStateMgr::new(),
            &runtime,
            Arc::new(chanmgr),
            guardmgr,
        )
        .unwrap();
        let circpool = HsCircPool::new(&circmgr);
        let (give_send, give) = postage::watch::channel_with(Ready(Ok(())));
        let mock_for_state = MockGlobalState { give };
        #[allow(clippy::let_and_return)] // we'll probably add more in this function
        let hscc = HsClientConnector {
            runtime,
            circpool,
            services: Default::default(),
            mock_for_state,
        };
        let keys = HsClientSecretKeysBuilder::default().build().unwrap();
        (hscc, keys, give_send)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn mk_isol(s: &str) -> Option<NarrowableIsolation> {
        Some(NarrowableIsolation(s.into()))
    }

    async fn launch_one(
        hsconn: &HsClientConnector<impl Runtime, MockData>,
        id: u8,
        secret_keys: &HsClientSecretKeys,
        isolation: Option<NarrowableIsolation>,
    ) -> Result<Arc<MockCirc>, ConnError> {
        let netdir = tor_netdir::testnet::construct_netdir()
            .unwrap_if_sufficient()
            .unwrap();
        let netdir = Arc::new(netdir);

        let hs_id = {
            let mut hs_id = [0_u8; 32];
            hs_id[0] = id;
            hs_id.into()
        };
        #[allow(clippy::redundant_closure)] // srsly, that would be worse
        let isolation = isolation.unwrap_or_default().into();
        Services::get_or_launch_connection(hsconn, &netdir, hs_id, isolation, secret_keys.clone())
            .await
    }

    #[derive(Default, Debug, Clone)]
    // TODO move this to tor-circmgr under a test feature?
    pub(crate) struct NarrowableIsolation(pub(crate) String);
    impl tor_circmgr::isolation::IsolationHelper for NarrowableIsolation {
        fn compatible_same_type(&self, other: &Self) -> bool {
            self.join_same_type(other).is_some()
        }
        fn join_same_type(&self, other: &Self) -> Option<Self> {
            Some(if self.0.starts_with(&other.0) {
                self.clone()
            } else if other.0.starts_with(&self.0) {
                other.clone()
            } else {
                return None;
            })
        }
    }

    #[test]
    #[traced_test]
    fn simple() {
        test_with_one_runtime!(|runtime| async {
            let (hsconn, keys, _give_send) = mk_hsconn(runtime);

            let circuit = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            eprintln!("{:?}", circuit);
        });
    }

    #[test]
    #[traced_test]
    fn expiry() {
        MockRuntime::test_with_various(|runtime| async move {
            // This is the amount by which we adjust clock advances to make sure we
            // hit more or less than a particular value, to avoid edge cases and
            // cope with real time advancing too.
            // This does *not* represent an actual delay to real test runs.
            const TIMEOUT_SLOP: Duration = Duration::from_secs(10);

            let (hsconn, keys, _give_send) = mk_hsconn(runtime.clone());

            let advance = |duration| {
                let hsconn = hsconn.clone();
                let runtime = &runtime;
                async move {
                    // let expiry task get going and choose its expiry (wakeup) time
                    runtime.progress_until_stalled().await;
                    // TODO: Make this use runtime.advance_by() when that's not very slow
                    runtime.mock_sleep().advance(duration);
                    // let expiry task run
                    runtime.progress_until_stalled().await;
                    hsconn.services().unwrap().run_housekeeping(runtime.now());
                }
            };

            // make circuit1
            let circuit1 = launch_one(&hsconn, 0, &keys, None).await.unwrap();

            // expire it
            advance(RETAIN_CIRCUIT_AFTER_LAST_USE + TIMEOUT_SLOP).await;

            // make circuit2 (a)
            let circuit2a = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_ne!(circuit1, circuit2a);

            // nearly expire it, then reuse it
            advance(RETAIN_CIRCUIT_AFTER_LAST_USE - TIMEOUT_SLOP).await;
            let circuit2b = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_eq!(circuit2a, circuit2b);

            // nearly expire it again, then reuse it
            advance(RETAIN_CIRCUIT_AFTER_LAST_USE - TIMEOUT_SLOP).await;
            let circuit2c = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_eq!(circuit2a, circuit2c);

            // actually expire it
            advance(RETAIN_CIRCUIT_AFTER_LAST_USE + TIMEOUT_SLOP).await;
            let circuit3 = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_ne!(circuit2c, circuit3);
            assert_eq!(circuit3.connect_called, 3);

            advance(RETAIN_DATA_AFTER_LAST_USE + Duration::from_secs(10)).await;
            let circuit4 = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_eq!(circuit4.connect_called, 1);
        });
    }

    #[test]
    #[traced_test]
    fn coalesce() {
        test_with_one_runtime!(|runtime| async {
            let (hsconn, keys, mut give_send) = mk_hsconn(runtime);

            give_send.send(Pending).await.unwrap();

            let c1f = launch_one(&hsconn, 0, &keys, None);
            pin!(c1f);
            for _ in 0..10 {
                assert!(poll!(&mut c1f).is_pending());
            }

            // c2f will find Working
            let c2f = launch_one(&hsconn, 0, &keys, None);
            pin!(c2f);
            for _ in 0..10 {
                assert!(poll!(&mut c1f).is_pending());
                assert!(poll!(&mut c2f).is_pending());
            }

            give_send.send(Ready(Ok(()))).await.unwrap();

            let c1 = c1f.await.unwrap();
            let c2 = c2f.await.unwrap();
            assert_eq!(c1, c2);

            // c2 will find Open
            let c3 = launch_one(&hsconn, 0, &keys, None).await.unwrap();
            assert_eq!(c1, c3);

            assert_ne!(c1, launch_one(&hsconn, 1, &keys, None).await.unwrap());
            assert_ne!(
                c1,
                launch_one(&hsconn, 0, &mk_keys(42), None).await.unwrap()
            );

            let c_isol_1 = launch_one(&hsconn, 0, &keys, mk_isol("a")).await.unwrap();
            assert_eq!(c1, c_isol_1); // We can reuse, but now we've narrowed the isol

            let c_isol_2 = launch_one(&hsconn, 0, &keys, mk_isol("b")).await.unwrap();
            assert_ne!(c1, c_isol_2);
        });
    }
}
