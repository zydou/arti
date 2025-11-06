//! Executor for running tests with mocked environment
//!
//! See [`MockExecutor`]

use std::any::Any;
use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt::{self, Debug, Display};
use std::future::Future;
use std::io::{self, Write as _};
use std::iter;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use futures::FutureExt as _;
use futures::pin_mut;
use futures::task::{FutureObj, Spawn, SpawnError};

use assert_matches::assert_matches;
use educe::Educe;
use itertools::Either::{self, *};
use itertools::{chain, izip};
use slotmap_careful::DenseSlotMap;
use std::backtrace::Backtrace;
use strum::EnumIter;

// NB: when using traced_test, the trace! and error! output here is generally suppressed
// in tests of other crates.  To see it, you can write something like this
// (in the dev-dependencies of the crate whose tests you're running):
//    tracing-test = { version = "0.2.4", features = ["no-env-filter"] }
use tracing::{error, trace};

use oneshot_fused_workaround::{self as oneshot, Canceled};
use tor_error::error_report;
use tor_rtcompat::{Blocking, ToplevelBlockOn};

use Poll::*;
use TaskState::*;

/// Type-erased future, one for each of our (normal) tasks
type TaskFuture = FutureObj<'static, ()>;

/// Future for the argument to `block_on`, which is handled specially
type MainFuture<'m> = Pin<&'m mut dyn Future<Output = ()>>;

//---------- principal data structures ----------

/// Executor for running tests with mocked environment
///
/// For test cases which don't actually wait for anything in the real world.
///
/// This is the executor.
/// It implements [`Spawn`] and [`ToplevelBlockOn`]
///
/// It will usually be used as part of a `MockRuntime`.
///
/// To run futures, call [`ToplevelBlockOn::block_on`]
///
/// # Restricted environment
///
/// Tests run with this executor must not attempt to block
/// on anything "outside":
/// every future that anything awaits must (eventually) be woken directly
/// *by some other task* in the same test case.
///
/// (By directly we mean that the [`Waker::wake`] call is made
/// by that waking future, before that future itself awaits anything.)
///
/// # Panics
///
/// The executor will panic
/// if the toplevel future (passed to `block_on`)
/// doesn't complete (without externally blocking),
/// but instead waits for something.
///
/// The executor will malfunction or panic if reentered.
/// (Eg, if `block_on` is reentered.)
#[derive(Clone, Default, Educe)]
#[educe(Debug)]
pub struct MockExecutor {
    /// Mutable state
    #[educe(Debug(ignore))]
    shared: Arc<Shared>,
}

/// Shared state and ancillary information
///
/// This is always within an `Arc`.
#[derive(Default)]
struct Shared {
    /// Shared state
    data: Mutex<Data>,
    /// Condition variable for thread scheduling
    ///
    /// Signaled when [`Data.thread_to_run`](struct.Data.html#structfield.thread_to_run)
    /// is modified.
    thread_condvar: std::sync::Condvar,
}

/// Task id, module to hide `Ti` alias
mod task_id {
    slotmap_careful::new_key_type! {
        /// Task ID, usually called `TaskId`
        ///
        /// Short name in special `task_id` module so that [`Debug`] is nice
        pub(super) struct Ti;
    }
}
use task_id::Ti as TaskId;

/// Executor's state
///
/// ### Task state machine
///
/// A task is created in `tasks`, `Awake`, so also in `awake`.
///
/// When we poll it, we take it out of `awake` and set it to `Asleep`,
/// and then call `poll()`.
/// Any time after that, it can be made `Awake` again (and put back onto `awake`)
/// by the waker ([`ActualWaker`], wrapped in [`Waker`]).
///
/// The task's future is of course also present here in this data structure.
/// However, during poll we must release the lock,
/// so we cannot borrow the future from `Data`.
/// Instead, we move it out.  So `Task.fut` is an `Option`.
///
/// ### "Main" task - the argument to `block_on`
///
/// The signature of `BlockOn::block_on` accepts a non-`'static` future
/// (and a non-`Send`/`Sync` one).
///
/// So we cannot store that future in `Data` because `Data` is `'static`.
/// Instead, this main task future is passed as an argument down the call stack.
/// In the data structure we simply store a placeholder, `TaskFutureInfo::Main`.
#[derive(Educe, derive_more::Debug)]
#[educe(Default)]
struct Data {
    /// Tasks
    ///
    /// Includes tasks spawned with `spawn`,
    /// and also the future passed to `block_on`.
    #[debug("{:?}", DebugTasks(self, || tasks.keys()))]
    tasks: DenseSlotMap<TaskId, Task>,

    /// `awake` lists precisely: tasks that are `Awake`, plus maybe stale `TaskId`s
    ///
    /// Tasks are pushed onto the *back* when woken,
    /// so back is the most recently woken.
    #[debug("{:?}", DebugTasks(self, || awake.iter().cloned()))]
    awake: VecDeque<TaskId>,

    /// If a future from `progress_until_stalled` exists
    progressing_until_stalled: Option<ProgressingUntilStalled>,

    /// Scheduling policy
    scheduling: SchedulingPolicy,

    /// (Sub)thread we want to run now
    ///
    /// At any one time only one thread is meant to be running.
    /// Other threads are blocked in condvar wait, waiting for this to change.
    ///
    /// **Modified only** within
    /// [`thread_context_switch_send_instruction_to_run`](Shared::thread_context_switch_send_instruction_to_run),
    /// which takes responsibility for preserving the following **invariants**:
    ///
    ///  1. no-one but the named thread is allowed to modify this field.
    ///  2. after modifying this field, signal `thread_condvar`
    #[educe(Default(expression = "ThreadDescriptor::Executor"))]
    thread_to_run: ThreadDescriptor,
}

/// How we should schedule?
#[derive(Debug, Clone, Default, EnumIter)]
#[non_exhaustive]
pub enum SchedulingPolicy {
    /// Task *most* recently woken is run
    ///
    /// This is the default.
    ///
    /// It will expose starvation bugs if a task never sleeps.
    /// (Which is a good thing in tests.)
    #[default]
    Stack,
    /// Task *least* recently woken is run.
    Queue,
}

/// Record of a single task
///
/// Tracks a spawned task, or the main task (the argument to `block_on`).
///
/// Stored in [`Data`]`.tasks`.
struct Task {
    /// For debugging output
    desc: String,
    /// Has this been woken via a waker?  (And is it in `Data.awake`?)
    ///
    /// **Set to `Awake` only by [`Task::set_awake`]**,
    /// preserving the invariant that
    /// every `Awake` task is in [`Data.awake`](struct.Data.html#structfield.awake).
    state: TaskState,
    /// The actual future (or a placeholder for it)
    ///
    /// May be `None` briefly in the executor main loop, because we've
    /// temporarily moved it out so we can poll it,
    /// or if this is a Subthread task which is currently running sync code
    /// (in which case we're blocked in the executor waiting to be
    /// woken up by [`thread_context_switch`](Shared::thread_context_switch).
    ///
    /// Note that the `None` can be observed outside the main loop, because
    /// the main loop unlocks while it polls, so other (non-main-loop) code
    /// might see it.
    fut: Option<TaskFutureInfo>,
}

/// A future as stored in our record of a [`Task`]
#[derive(Educe)]
#[educe(Debug)]
enum TaskFutureInfo {
    /// The [`Future`].  All is normal.
    Normal(#[educe(Debug(ignore))] TaskFuture),
    /// The future isn't here because this task is the main future for `block_on`
    Main,
    /// This task is actually a [`Subthread`](MockExecutor::subthread_spawn)
    ///
    /// Instead of polling it, we'll switch to it with
    /// [`thread_context_switch`](Shared::thread_context_switch).
    Subthread,
}

/// State of a task - do we think it needs to be polled?
///
/// Stored in [`Task`]`.state`.
#[derive(Debug)]
enum TaskState {
    /// Awake - needs to be polled
    ///
    /// Established by [`waker.wake()`](Waker::wake)
    Awake,
    /// Asleep - does *not* need to be polled
    ///
    /// Established each time just before we call the future's [`poll`](Future::poll)
    Asleep(Vec<SleepLocation>),
}

/// Actual implementor of `Wake` for use in a `Waker`
///
/// Futures (eg, channels from [`futures`]) will use this to wake a task
/// when it should be polled.
///
/// This type must not be `Cloned` with the `Data` lock held.
/// Consequently, a `Waker` mustn't either.
struct ActualWaker {
    /// Executor state
    ///
    /// The Waker mustn't to hold a strong reference to the executor,
    /// since typically a task holds a future that holds a Waker,
    /// and the executor holds the task - so that would be a cycle.
    data: Weak<Shared>,

    /// Which task this is
    id: TaskId,
}

/// State used for an in-progress call to
/// [`progress_until_stalled`][`MockExecutor::progress_until_stalled`]
///
/// If present in [`Data`], an (async) call to `progress_until_stalled`
/// is in progress.
///
/// The future from `progress_until_stalled`, [`ProgressUntilStalledFuture`]
/// is a normal-ish future.
/// It can be polled in the normal way.
/// When it is polled, it looks here, in `finished`, to see if it's `Ready`.
///
/// The future is made ready, and woken (via `waker`),
/// by bespoke code in the task executor loop.
///
/// When `ProgressUntilStalledFuture` (maybe completes and) is dropped,
/// its `Drop` impl is used to remove this from `Data.progressing_until_stalled`.
#[derive(Debug)]
struct ProgressingUntilStalled {
    /// Have we, in fact, stalled?
    ///
    /// Made `Ready` by special code in the executor loop
    finished: Poll<()>,

    /// Waker
    ///
    /// Signalled by special code in the executor loop
    waker: Option<Waker>,
}

/// Future from
/// [`progress_until_stalled`][`MockExecutor::progress_until_stalled`]
///
/// See [`ProgressingUntilStalled`] for an overview of this aspect of the contraption.
///
/// Existence of this struct implies `Data.progressing_until_stalled` is `Some`.
/// There can only be one at a time.
#[derive(Educe)]
#[educe(Debug)]
struct ProgressUntilStalledFuture {
    /// Executor's state; this future's state is in `.progressing_until_stalled`
    #[educe(Debug(ignore))]
    shared: Arc<Shared>,
}

/// Identifies a thread we know about - the executor thread, or a Subthread
///
/// Not related to `std::thread::ThreadId`.
///
/// See [`spawn_subthread`](MockExecutor::subthread_spawn) for definition of a Subthread.
///
/// This being a thread-local and not scoped by which `MockExecutor` we're talking about
/// means that we can't cope if there are multiple `MockExecutor`s involved in the same thread.
/// That's OK (and documented).
#[derive(Copy, Clone, Eq, PartialEq, derive_more::Debug)]
enum ThreadDescriptor {
    /// Foreign - neither the (running) executor, nor a Subthread
    #[debug("FOREIGN")]
    Foreign,
    /// The executor.
    #[debug("Exe")]
    Executor,
    /// This task, which is a Subthread.
    #[debug("{_0:?}")]
    Subthread(TaskId),
}

/// Marker indicating that this task is a Subthread, not an async task.
///
/// See [`spawn_subthread`](MockExecutor::subthread_spawn) for definition of a Subthread.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct IsSubthread;

/// [`Shared::subthread_yield`] should set our task awake before switching to the executor
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SetAwake;

thread_local! {
    /// Identifies this thread.
    pub static THREAD_DESCRIPTOR: Cell<ThreadDescriptor> = const {
        Cell::new(ThreadDescriptor::Foreign)
    };
}

//---------- creation ----------

impl MockExecutor {
    /// Make a `MockExecutor` with default parameters
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a `MockExecutor` with a specific `SchedulingPolicy`
    pub fn with_scheduling(scheduling: SchedulingPolicy) -> Self {
        Data {
            scheduling,
            ..Default::default()
        }
        .into()
    }
}

impl From<Data> for MockExecutor {
    fn from(data: Data) -> MockExecutor {
        let shared = Shared {
            data: Mutex::new(data),
            thread_condvar: std::sync::Condvar::new(),
        };
        MockExecutor {
            shared: Arc::new(shared),
        }
    }
}

//---------- spawning ----------

impl MockExecutor {
    /// Spawn a task and return something to identify it
    ///
    /// `desc` should `Display` as some kind of short string (ideally without spaces)
    /// and will be used in the `Debug` impl and trace log messages from `MockExecutor`.
    ///
    /// The returned value is an opaque task identifier which is very cheap to clone
    /// and which can be used by the caller in debug logging,
    /// if it's desired to correlate with the debug output from `MockExecutor`.
    /// Most callers will want to ignore it.
    ///
    /// This method is infallible.  (The `MockExecutor` cannot be shut down.)
    pub fn spawn_identified(
        &self,
        desc: impl Display,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> impl Debug + Clone + Send + 'static {
        self.spawn_internal(desc.to_string(), FutureObj::from(Box::new(fut)))
    }

    /// Spawn a task and return its output for further usage
    ///
    /// `desc` should `Display` as some kind of short string (ideally without spaces)
    /// and will be used in the `Debug` impl and trace log messages from `MockExecutor`.
    pub fn spawn_join<T: Debug + Send + 'static>(
        &self,
        desc: impl Display,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> impl Future<Output = T> {
        let (tx, rx) = oneshot::channel();
        self.spawn_identified(desc, async move {
            let res = fut.await;
            tx.send(res)
                .expect("Failed to send future's output, did future panic?");
        });
        rx.map(|m| m.expect("Failed to receive future's output"))
    }

    /// Spawn a task and return its `TaskId`
    ///
    /// Convenience method for use by `spawn_identified` and `spawn_obj`.
    /// The future passed to `block_on` is not handled here.
    fn spawn_internal(&self, desc: String, fut: TaskFuture) -> TaskId {
        let mut data = self.shared.lock();
        data.insert_task(desc, TaskFutureInfo::Normal(fut))
    }
}

impl Data {
    /// Insert a task given its `TaskFutureInfo` and return its `TaskId`.
    fn insert_task(&mut self, desc: String, fut: TaskFutureInfo) -> TaskId {
        let state = Awake;
        let id = self.tasks.insert(Task {
            state,
            desc,
            fut: Some(fut),
        });
        self.awake.push_back(id);
        trace!("MockExecutor spawned {:?}={:?}", id, self.tasks[id]);
        id
    }
}

impl Spawn for MockExecutor {
    fn spawn_obj(&self, future: TaskFuture) -> Result<(), SpawnError> {
        self.spawn_internal("spawn_obj".into(), future);
        Ok(())
    }
}

impl Blocking for MockExecutor {
    type ThreadHandle<T: Send + 'static> = Pin<Box<dyn Future<Output = T>>>;

    fn spawn_blocking<F, T>(&self, f: F) -> Self::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        assert_matches!(
            THREAD_DESCRIPTOR.get(),
            ThreadDescriptor::Executor | ThreadDescriptor::Subthread(_),
            "MockExecutor::spawn_blocking_io only allowed from future or subthread, being run by this executor"
        );
        Box::pin(
            self.subthread_spawn("spawn_blocking", f)
                .map(|x| x.expect("Error in spawn_blocking subthread.")),
        )
    }

    fn reenter_block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
        F::Output: Send + 'static,
    {
        self.subthread_block_on_future(future)
    }
}

//---------- block_on ----------

impl ToplevelBlockOn for MockExecutor {
    fn block_on<F>(&self, input_fut: F) -> F::Output
    where
        F: Future,
    {
        let mut value: Option<F::Output> = None;

        // Box this just so that we can conveniently control precisely when it's dropped.
        // (We could do this with Option and Pin::set but that seems clumsier.)
        let mut input_fut = Box::pin(input_fut);

        let run_store_fut = {
            let value = &mut value;
            let input_fut = &mut input_fut;
            async {
                trace!("MockExecutor block_on future...");
                let t = input_fut.await;
                trace!("MockExecutor block_on future returned...");
                *value = Some(t);
                trace!("MockExecutor block_on future exiting.");
            }
        };

        {
            pin_mut!(run_store_fut);

            let main_id = self
                .shared
                .lock()
                .insert_task("main".into(), TaskFutureInfo::Main);
            trace!("MockExecutor {main_id:?} is task for block_on");
            self.execute_to_completion(run_store_fut);
        }

        #[allow(clippy::let_and_return)] // clarity
        let value = value.take().unwrap_or_else(|| {
            // eprintln can be captured by libtest, but the debug_dump goes to io::stderr.
            // use the latter, so that the debug dump is prefixed by this message.
            let _: io::Result<()> = writeln!(io::stderr(), "all futures blocked, crashing...");
            // write to tracing too, so the tracing log is clear about when we crashed
            error!("all futures blocked, crashing...");

            // Sequencing here is subtle.
            //
            // We should do the dump before dropping the input future, because the input
            // future is likely to own things that, when dropped, wake up other tasks,
            // rendering the dump inaccurate.
            //
            // But also, dropping the input future may well drop a ProgressUntilStalledFuture
            // which then reenters us.  More generally, we mustn't call user code
            // with the lock held.
            //
            // And, we mustn't panic with the data lock held.
            //
            // If value was Some, then this closure is dropped without being called,
            // which drops the future after it has yielded the value, which is correct.
            {
                let mut data = self.shared.lock();
                data.debug_dump();
            }
            drop(input_fut);

            panic!(
                r"
all futures blocked. waiting for the real world? or deadlocked (waiting for each other) ?
"
            );
        });

        value
    }
}

//---------- execution - core implementation ----------

impl MockExecutor {
    /// Keep polling tasks until nothing more can be done
    ///
    /// Ie, stop when `awake` is empty and `progressing_until_stalled` is `None`.
    fn execute_to_completion(&self, mut main_fut: MainFuture) {
        trace!("MockExecutor execute_to_completion...");
        loop {
            self.execute_until_first_stall(main_fut.as_mut());

            // Handle `progressing_until_stalled`
            let pus_waker = {
                let mut data = self.shared.lock();
                let pus = &mut data.progressing_until_stalled;
                trace!("MockExecutor execute_to_completion PUS={:?}", &pus);
                let Some(pus) = pus else {
                    // No progressing_until_stalled, we're actually done.
                    break;
                };
                assert_eq!(
                    pus.finished, Pending,
                    "ProgressingUntilStalled finished twice?!"
                );
                pus.finished = Ready(());

                // Release the lock temporarily so that ActualWaker::clone doesn't deadlock
                let waker = pus
                    .waker
                    .take()
                    .expect("ProgressUntilStalledFuture not ever polled!");
                drop(data);
                let waker_copy = waker.clone();
                let mut data = self.shared.lock();

                let pus = &mut data.progressing_until_stalled;
                if let Some(double) = pus
                    .as_mut()
                    .expect("progressing_until_stalled updated under our feet!")
                    .waker
                    .replace(waker)
                {
                    panic!("double progressing_until_stalled.waker! {double:?}");
                }

                waker_copy
            };
            pus_waker.wake();
        }
        trace!("MockExecutor execute_to_completion done");
    }

    /// Keep polling tasks until `awake` is empty
    ///
    /// (Ignores `progressing_until_stalled` - so if one is active,
    /// will return when all other tasks have blocked.)
    ///
    /// # Panics
    ///
    /// Might malfunction or panic if called reentrantly
    fn execute_until_first_stall(&self, main_fut: MainFuture) {
        trace!("MockExecutor execute_until_first_stall ...");

        assert_eq!(
            THREAD_DESCRIPTOR.get(),
            ThreadDescriptor::Foreign,
            "MockExecutor executor re-entered"
        );
        THREAD_DESCRIPTOR.set(ThreadDescriptor::Executor);

        let r = catch_unwind(AssertUnwindSafe(|| self.executor_main_loop(main_fut)));

        THREAD_DESCRIPTOR.set(ThreadDescriptor::Foreign);

        match r {
            Ok(()) => trace!("MockExecutor execute_until_first_stall done."),
            Err(e) => {
                trace!("MockExecutor executor, or async task, panicked!");
                panic_any(e)
            }
        }
    }

    /// Keep polling tasks until `awake` is empty (inner, executor main loop)
    ///
    /// This is only called from [`MockExecutor::execute_until_first_stall`],
    /// so it could also be called `execute_until_first_stall_inner`.
    #[allow(clippy::cognitive_complexity)]
    fn executor_main_loop(&self, mut main_fut: MainFuture) {
        'outer: loop {
            // Take a `Awake` task off `awake` and make it `Asleep`
            let (id, mut fut) = 'inner: loop {
                let mut data = self.shared.lock();
                let Some(id) = data.schedule() else {
                    break 'outer;
                };
                let Some(task) = data.tasks.get_mut(id) else {
                    trace!("MockExecutor {id:?} vanished");
                    continue;
                };
                task.state = Asleep(vec![]);
                let fut = task.fut.take().expect("future missing from task!");
                break 'inner (id, fut);
            };

            // Poll the selected task
            trace!("MockExecutor {id:?} polling...");
            let waker = ActualWaker::make_waker(&self.shared, id);
            let mut cx = Context::from_waker(&waker);
            let r: Either<Poll<()>, IsSubthread> = match &mut fut {
                TaskFutureInfo::Normal(fut) => Left(fut.poll_unpin(&mut cx)),
                TaskFutureInfo::Main => Left(main_fut.as_mut().poll(&mut cx)),
                TaskFutureInfo::Subthread => Right(IsSubthread),
            };

            // Deal with the returned `Poll`
            let _fut_drop_late;
            {
                let mut data = self.shared.lock();
                let task = data
                    .tasks
                    .get_mut(id)
                    .expect("task vanished while we were polling it");

                match r {
                    Left(Pending) => {
                        trace!("MockExecutor {id:?} -> Pending");
                        if task.fut.is_some() {
                            panic!("task reinserted while we polled it?!");
                        }
                        // The task might have been woken *by its own poll method*.
                        // That's why we set it to `Asleep` *earlier* rather than here.
                        // All we need to do is put the future back.
                        task.fut = Some(fut);
                    }
                    Left(Ready(())) => {
                        trace!("MockExecutor {id:?} -> Ready");
                        // Oh, it finished!
                        // It might be in `awake`, but that's allowed to contain stale tasks,
                        // so we *don't* need to scan that list and remove it.
                        data.tasks.remove(id);
                        // It is important that we don't drop `fut` until we have released
                        // the data lock, since it is an external type and might try to reenter
                        // us (eg by calling spawn).  If we do that here, we risk deadlock.
                        // So, move `fut` to a variable with scope outside the block with `data`.
                        _fut_drop_late = fut;
                    }
                    Right(IsSubthread) => {
                        trace!("MockExecutor {id:?} -> Ready, waking Subthread");
                        // Task is a subthread, which has called thread_context_switch
                        // to switch to us.  We "poll" it by switching back.

                        // Put back `TFI::Subthread`, which was moved out temporarily, above.
                        task.fut = Some(fut);

                        self.shared.thread_context_switch(
                            data,
                            ThreadDescriptor::Executor,
                            ThreadDescriptor::Subthread(id),
                        );

                        // Now, if the Subthread still exists, that's because it's switched
                        // back to us, and is waiting in subthread_block_on_future again.
                        // Or it might have ended, in which case it's not in `tasks` any more.
                        // In any case we can go back to scheduling futures.
                    }
                }
            }
        }
    }
}

impl Data {
    /// Return the next task to run
    ///
    /// The task is removed from `awake`, but **`state` is not set to `Asleep`**.
    /// The caller must restore the invariant!
    fn schedule(&mut self) -> Option<TaskId> {
        use SchedulingPolicy as SP;
        match self.scheduling {
            SP::Stack => self.awake.pop_back(),
            SP::Queue => self.awake.pop_front(),
        }
    }
}

impl ActualWaker {
    /// Obtain a strong reference to the executor's data
    fn upgrade_data(&self) -> Option<Arc<Shared>> {
        self.data.upgrade()
    }

    /// Wake the task corresponding to this `ActualWaker`
    ///
    /// This is like `<Self as std::task::Wake>::wake()` but takes `&self`, not `Arc`
    fn wake(&self) {
        let Some(data) = self.upgrade_data() else {
            // The executor is gone!  Don't try to wake.
            return;
        };
        let mut data = data.lock();
        let data = &mut *data;
        trace!("MockExecutor {:?} wake", &self.id);
        let Some(task) = data.tasks.get_mut(self.id) else {
            return;
        };
        task.set_awake(self.id, &mut data.awake);
    }

    /// Create and return a `Waker` for task `id`
    fn make_waker(shared: &Arc<Shared>, id: TaskId) -> Waker {
        ActualWaker {
            data: Arc::downgrade(shared),
            id,
        }
        .new_waker()
    }
}

//---------- "progress until stalled" functionality ----------

impl MockExecutor {
    /// Run tasks in the current executor until every other task is waiting
    ///
    /// # Panics
    ///
    /// Might malfunction or panic if more than one such call is running at once.
    ///
    /// (Ie, you must `.await` or drop the returned `Future`
    /// before calling this method again.)
    ///
    /// Must be called and awaited within a future being run by `self`.
    pub fn progress_until_stalled(&self) -> impl Future<Output = ()> + use<> {
        let mut data = self.shared.lock();
        assert!(
            data.progressing_until_stalled.is_none(),
            "progress_until_stalled called more than once"
        );
        trace!("MockExecutor progress_until_stalled...");
        data.progressing_until_stalled = Some(ProgressingUntilStalled {
            finished: Pending,
            waker: None,
        });
        ProgressUntilStalledFuture {
            shared: self.shared.clone(),
        }
    }
}

impl Future for ProgressUntilStalledFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        let waker = cx.waker().clone();
        let mut data = self.shared.lock();
        let pus = data.progressing_until_stalled.as_mut();
        trace!("MockExecutor progress_until_stalled polling... {:?}", &pus);
        let pus = pus.expect("ProgressingUntilStalled missing");
        pus.waker = Some(waker);
        pus.finished
    }
}

impl Drop for ProgressUntilStalledFuture {
    fn drop(&mut self) {
        self.shared.lock().progressing_until_stalled = None;
    }
}

//---------- (sub)threads ----------

impl MockExecutor {
    /// Spawn a "Subthread", for processing in a sync context
    ///
    /// `call` will be run on a separate thread, called a "Subthread".
    ///
    /// But it will **not run simultaneously** with the executor,
    /// nor with other Subthreads.
    /// So Subthreads are somewhat like coroutines.
    ///
    /// `call` must be capable of making progress without waiting for any other Subthreads.
    /// `call` may wait for async futures, using
    /// [`subthread_block_on_future`](MockExecutor::subthread_block_on_future).
    ///
    /// Subthreads may be used for cpubound activity,
    /// or synchronous IO (such as large volumes of disk activity),
    /// provided that the synchronous code will reliably make progress,
    /// without waiting (directly or indirectly) for any async task or Subthread -
    /// except via `subthread_block_on_future`.
    ///
    /// # Subthreads vs raw `std::thread` threads
    ///
    /// Programs using `MockExecutor` may use `std::thread` threads directly.
    /// However, this is not recommended.  There are severe limitations:
    ///
    ///  * Only a Subthread can re-enter the async context from sync code:
    ///    this must be done with
    ///    using [`subthread_block_on_future`](MockExecutor::subthread_block_on_future).
    ///    (Re-entering the executor with
    ///    [`block_on`](tor_rtcompat::ToplevelBlockOn::block_on)
    ///    is not allowed.)
    ///  * If async tasks want to suspend waiting for synchronous code,
    ///    the synchronous code must run on a Subthread.
    ///    This allows the `MockExecutor` to know when
    ///    that synchronous code is still making progress.
    ///    (This is needed for
    ///    [`progress_until_stalled`](MockExecutor::progress_until_stalled)
    ///    and the facilities which use it, such as
    ///    [`MockRuntime::advance_until_stalled`](crate::MockRuntime::advance_until_stalled).)
    ///  * Subthreads never run in parallel -
    ///    they only run as scheduled deterministically by the `MockExecutor`.
    ///    So using Subthreads eliminates a source of test nonndeterminism.
    ///    (Execution order is still varied due to explicitly varying the scheduling policy.)
    ///
    /// # Panics, abuse, and malfunctions
    ///
    /// If `call` panics and unwinds, `spawn_subthread` yields `Err`.
    /// The application code should to do something about it if this happens,
    /// typically, logging errors, tearing things down, or failing a test case.
    ///
    /// If the executor doesn't run, the subthread will not run either, and will remain stuck.
    /// (So, typically, if the thread supposed to run the executor panics,
    /// for example because a future or the executor itself panics,
    /// all the subthreads will become stuck - effectively, they'll be leaked.)
    ///
    /// `spawn_subthread` panics if OS thread spawning fails.
    /// (Like `std::thread::spawn()` does.)
    ///
    /// `MockExecutor`s will malfunction or panic if
    /// any executor invocation method (eg `block_on`) is called on a Subthread.
    pub fn subthread_spawn<T: Send + 'static>(
        &self,
        desc: impl Display,
        call: impl FnOnce() -> T + Send + 'static,
    ) -> impl Future<Output = Result<T, Box<dyn Any + Send>>> + Unpin + Send + Sync + 'static {
        let desc = desc.to_string();
        let (output_tx, output_rx) = oneshot::channel();

        // NB: we don't know which thread we're on!
        // In principle we might be on another Subthread.
        // So we can't context switch here.  That would be very confusing.
        //
        // Instead, we prepare the new Subthread as follows:
        //   - There is a task in the executor
        //   - The task is ready to be polled, whenever the executor decides to
        //   - The thread starts running right away, but immediately waits until it is scheduled
        // See `subthread_entrypoint`.

        {
            let mut data = self.shared.lock();
            let id = data.insert_task(desc.clone(), TaskFutureInfo::Subthread);

            let _: std::thread::JoinHandle<()> = std::thread::Builder::new()
                .name(desc)
                .spawn({
                    let shared = self.shared.clone();
                    move || shared.subthread_entrypoint(id, call, output_tx)
                })
                .expect("spawn failed");
        }

        output_rx.map(|r| {
            r.unwrap_or_else(|_: Canceled| panic!("Subthread cancelled but should be impossible!"))
        })
    }

    /// Call an async `Future` from a Subthread
    ///
    /// Blocks the Subthread, and arranges to run async tasks,
    /// including `fut`, until `fut` completes.
    ///
    /// `fut` is polled on the executor thread, not on the Subthread.
    /// (We may change that in the future, allowing passing a non-`Send` future.)
    ///
    /// # Panics, abuse, and malfunctions
    ///
    /// `subthread_block_on_future` will malfunction or panic
    /// if called on a thread that isn't a Subthread from the same `MockExecutor`
    /// (ie a thread made with [`spawn_subthread`](MockExecutor::subthread_spawn)).
    ///
    /// If `fut` itself panics, the executor will panic.
    ///
    /// If the executor isn't running, `subthread_block_on_future` will hang indefinitely.
    /// See `spawn_subthread`.
    #[allow(clippy::cognitive_complexity)] // Splitting this up would be worse
    pub fn subthread_block_on_future<T: Send + 'static>(&self, fut: impl Future<Output = T>) -> T {
        let id = match THREAD_DESCRIPTOR.get() {
            ThreadDescriptor::Subthread(id) => id,
            ThreadDescriptor::Executor => {
                panic!("subthread_block_on_future called from MockExecutor thread (async task?)")
            }
            ThreadDescriptor::Foreign => panic!(
                "subthread_block_on_future called on foreign thread (not spawned with spawn_subthread)"
            ),
        };
        trace!("MockExecutor thread {id:?}, subthread_block_on_future...");
        let mut fut = pin!(fut);

        // We yield once before the first poll, and once after Ready, to shake up the
        // execution order a bit, depending on the scheduling policy.
        let yield_ = |set_awake| self.shared.subthread_yield(id, set_awake);
        yield_(Some(SetAwake));

        let ret = loop {
            // Poll the provided future
            trace!("MockExecutor thread {id:?}, s.t._block_on_future polling...");
            let waker = ActualWaker::make_waker(&self.shared, id);
            let mut cx = Context::from_waker(&waker);
            let r: Poll<T> = fut.as_mut().poll(&mut cx);

            if let Ready(r) = r {
                trace!("MockExecutor thread {id:?}, s.t._block_on_future poll -> Ready");
                break r;
            }

            // Pending.  Switch back to the exeuctor thread.
            // When the future becomes ready, the Waker will be woken, waking the task,
            // so that the executor will "poll" us again.
            trace!("MockExecutor thread {id:?}, s.t._block_on_future poll -> Pending");

            yield_(None);
        };

        yield_(Some(SetAwake));

        trace!("MockExecutor thread {id:?}, subthread_block_on_future complete.");

        ret
    }
}

impl Shared {
    /// Main entrypoint function for a Subthread
    ///
    /// Entered on a new `std::thread` thread created by
    /// [`subthread_spawn`](MockExecutor::subthread_spawn).
    ///
    /// When `call` completes, sends its returned value `T` to `output_tx`.
    fn subthread_entrypoint<T: Send + 'static>(
        self: Arc<Self>,
        id: TaskId,
        call: impl FnOnce() -> T + Send + 'static,
        output_tx: oneshot::Sender<Result<T, Box<dyn Any + Send>>>,
    ) {
        THREAD_DESCRIPTOR.set(ThreadDescriptor::Subthread(id));
        trace!("MockExecutor thread {id:?}, entrypoint");

        // We start out Awake, but we wait for the executor to tell us to run.
        // This will be done the first time the task is "polled".
        {
            let data = self.lock();
            self.thread_context_switch_waitfor_instruction_to_run(
                data,
                ThreadDescriptor::Subthread(id),
            );
        }

        trace!("MockExecutor thread {id:?}, entering user code");

        // Run the user's actual thread function.
        // This will typically reenter us via subthread_block_on_future.
        let ret = catch_unwind(AssertUnwindSafe(call));

        trace!("MockExecutor thread {id:?}, completed user code");

        // This makes the return value from subthread_spawn ready.
        // It will be polled by the executor in due course, presumably.

        output_tx.send(ret).unwrap_or_else(
            #[allow(clippy::unnecessary_lazy_evaluations)]
            |_| {}, // receiver dropped, maybe executor dropped or something?
        );

        {
            let mut data = self.lock();

            // Never poll this task again (so never schedule this thread)
            let _: Task = data.tasks.remove(id).expect("Subthread task vanished!");

            // Tell the executor it is scheduled now.
            // We carry on exiting, in parallel (holding the data lock).
            self.thread_context_switch_send_instruction_to_run(
                &mut data,
                ThreadDescriptor::Subthread(id),
                ThreadDescriptor::Executor,
            );
        }
    }

    /// Yield back to the executor from a subthread
    ///
    /// Checks that things are in order
    /// (in particular, that this task is in the data structure as a subhtread)
    /// and switches to the executor thread.
    ///
    /// The caller must arrange that the task gets woken.
    ///
    /// With [`SetAwake`], sets our task awake, so that we'll be polled
    /// again as soon as we get to the top of the executor's queue.
    /// Otherwise, we'll be reentered after someone wakes a [`Waker`] for the task.
    fn subthread_yield(&self, us: TaskId, set_awake: Option<SetAwake>) {
        let mut data = self.lock();
        {
            let data = &mut *data;
            let task = data.tasks.get_mut(us).expect("Subthread task vanished!");
            match &task.fut {
                Some(TaskFutureInfo::Subthread) => {}
                other => panic!("subthread_block_on_future but TFI {other:?}"),
            };
            if let Some(SetAwake) = set_awake {
                task.set_awake(us, &mut data.awake);
            }
        }
        self.thread_context_switch(
            data,
            ThreadDescriptor::Subthread(us),
            ThreadDescriptor::Executor,
        );
    }

    /// Switch from (sub)thread `us` to (sub)thread `them`
    ///
    /// Returns when someone calls `thread_context_switch(.., us)`.
    fn thread_context_switch(
        &self,
        mut data: MutexGuard<Data>,
        us: ThreadDescriptor,
        them: ThreadDescriptor,
    ) {
        trace!("MockExecutor thread {us:?}, switching to {them:?}");
        self.thread_context_switch_send_instruction_to_run(&mut data, us, them);
        self.thread_context_switch_waitfor_instruction_to_run(data, us);
    }

    /// Instruct the (sub)thread `them` to run
    ///
    /// Update `thread_to_run`, which will wake up `them`'s
    /// call to `thread_context_switch_waitfor_instruction_to_run`.
    ///
    /// Must be called from (sub)thread `us`.
    /// Part of `thread_context_switch`, not normally called directly.
    fn thread_context_switch_send_instruction_to_run(
        &self,
        data: &mut MutexGuard<Data>,
        us: ThreadDescriptor,
        them: ThreadDescriptor,
    ) {
        assert_eq!(data.thread_to_run, us);
        data.thread_to_run = them;
        self.thread_condvar.notify_all();
    }

    /// Await an instruction for this thread, `us`, to run
    ///
    /// Waits for `thread_to_run` to be `us`,
    /// waiting for `thread_condvar` as necessary.
    ///
    /// Part of `thread_context_switch`, not normally called directly.
    fn thread_context_switch_waitfor_instruction_to_run(
        &self,
        data: MutexGuard<Data>,
        us: ThreadDescriptor,
    ) {
        #[allow(let_underscore_lock)]
        let _: MutexGuard<_> = self
            .thread_condvar
            .wait_while(data, |data| {
                let live = data.thread_to_run;
                let resume = live == us;
                if resume {
                    trace!("MockExecutor thread {us:?}, resuming");
                } else {
                    trace!("MockExecutor thread {us:?}, waiting for {live:?}");
                }
                // We're in `.wait_while`, not `.wait_until`.  Confusing.
                !resume
            })
            .expect("data lock poisoned");
    }
}

//---------- ancillary and convenience functions ----------

/// Trait to let us assert at compile time that something is nicely `Sync` etc.
#[allow(dead_code)] // yes, we don't *use* anything from this trait
trait EnsureSyncSend: Sync + Send + 'static {}
impl EnsureSyncSend for ActualWaker {}
impl EnsureSyncSend for MockExecutor {}

impl MockExecutor {
    /// Return the number of tasks running in this executor
    ///
    /// One possible use is for a test case to check that task(s)
    /// that ought to have exited, have indeed done so.
    ///
    /// In the usual case, the answer will be at least 1,
    /// because it counts the future passed to
    /// [`block_on`](MockExecutor::block_on)
    /// (perhaps via [`MockRuntime::test_with_various`](crate::MockRuntime::test_with_various)).
    pub fn n_tasks(&self) -> usize {
        self.shared.lock().tasks.len()
    }
}

impl Shared {
    /// Lock and obtain the guard
    ///
    /// Convenience method which panics on poison
    fn lock(&self) -> MutexGuard<Data> {
        self.data.lock().expect("data lock poisoned")
    }
}

impl Task {
    /// Set task `id` to `Awake` and arrange that it will be polled.
    fn set_awake(&mut self, id: TaskId, data_awake: &mut VecDeque<TaskId>) {
        match self.state {
            Awake => {}
            Asleep(_) => {
                self.state = Awake;
                data_awake.push_back(id);
            }
        }
    }
}

//---------- ActualWaker as RawWaker ----------

/// Using [`ActualWaker`] in a [`RawWaker`]
///
/// We need to make a
/// [`Waker`] (the safe, type-erased, waker, used by actual futures)
/// which contains an
/// [`ActualWaker`] (our actual waker implementation, also safe).
///
/// `std` offers `Waker::from<Arc<impl Wake>>`.
/// But we want a bespoke `Clone` implementation, so we don't want to use `Arc`.
///
/// So instead, we implement the `RawWaker` API in terms of `ActualWaker`.
/// We keep the `ActualWaker` in a `Box`, and actually `clone` it (and the `Box`).
///
/// SAFETY
///
///  * The data pointer is `Box::<ActualWaker>::into_raw()`
///  * We share these when we clone
///  * No-one is allowed `&mut ActualWaker` unless there are no other clones
///  * So we may make references `&ActualWaker`
impl ActualWaker {
    /// Wrap up an [`ActualWaker`] as a type-erased [`Waker`] for passing to futures etc.
    fn new_waker(self) -> Waker {
        unsafe { Waker::from_raw(self.raw_new()) }
    }

    /// Helper: wrap up an [`ActualWaker`] as a [`RawWaker`].
    fn raw_new(self) -> RawWaker {
        let self_: Box<ActualWaker> = self.into();
        let self_: *mut ActualWaker = Box::into_raw(self_);
        let self_: *const () = self_ as _;
        RawWaker::new(self_, &RAW_WAKER_VTABLE)
    }

    /// Implementation of [`RawWakerVTable`]'s `clone`
    unsafe fn raw_clone(self_: *const ()) -> RawWaker {
        unsafe {
            let self_: *const ActualWaker = self_ as _;
            let self_: &ActualWaker = self_.as_ref().unwrap_unchecked();
            let copy: ActualWaker = self_.clone();
            copy.raw_new()
        }
    }

    /// Implementation of [`RawWakerVTable`]'s `wake`
    unsafe fn raw_wake(self_: *const ()) {
        unsafe {
            Self::raw_wake_by_ref(self_);
            Self::raw_drop(self_);
        }
    }

    /// Implementation of [`RawWakerVTable`]'s `wake_ref_by`
    unsafe fn raw_wake_by_ref(self_: *const ()) {
        unsafe {
            let self_: *const ActualWaker = self_ as _;
            let self_: &ActualWaker = self_.as_ref().unwrap_unchecked();
            self_.wake();
        }
    }

    /// Implementation of [`RawWakerVTable`]'s `drop`
    unsafe fn raw_drop(self_: *const ()) {
        unsafe {
            let self_: *mut ActualWaker = self_ as _;
            let self_: Box<ActualWaker> = Box::from_raw(self_);
            drop(self_);
        }
    }
}

/// vtable for `Box<ActualWaker>` as `RawWaker`
//
// This ought to be in the impl block above, but
//   "associated `static` items are not allowed"
static RAW_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    ActualWaker::raw_clone,
    ActualWaker::raw_wake,
    ActualWaker::raw_wake_by_ref,
    ActualWaker::raw_drop,
);

//---------- Sleep location tracking and dumping ----------

/// We record "where a future went to sleep" as (just) a backtrace
///
/// This type alias allows us to mock `Backtrace` for miri.
/// (It also insulates from future choices about sleep location representation.0
#[cfg(not(miri))]
type SleepLocation = Backtrace;

impl Data {
    /// Dump tasks and their sleep location backtraces
    fn dump_backtraces(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (id, task) in self.tasks.iter() {
            let prefix = |f: &mut fmt::Formatter| write!(f, "{id:?}={task:?}: ");
            match &task.state {
                Awake => {
                    prefix(f)?;
                    writeln!(f, "awake")?;
                }
                Asleep(locs) => {
                    let n = locs.len();
                    for (i, loc) in locs.iter().enumerate() {
                        prefix(f)?;
                        writeln!(f, "asleep, backtrace {i}/{n}:\n{loc}",)?;
                    }
                    if n == 0 {
                        prefix(f)?;
                        writeln!(f, "asleep, no backtraces, Waker never cloned, stuck!",)?;
                    }
                }
            }
        }
        writeln!(
            f,
            "\nNote: there might be spurious traces, see docs for MockExecutor::debug_dump\n"
        )?;
        Ok(())
    }
}

/// Track sleep locations via `<Waker as Clone>`.
///
/// See [`MockExecutor::debug_dump`] for the explanation.
impl Clone for ActualWaker {
    fn clone(&self) -> Self {
        let id = self.id;

        if let Some(data) = self.upgrade_data() {
            // If the executor is gone, there is nothing to adjust
            let mut data = data.lock();
            if let Some(task) = data.tasks.get_mut(self.id) {
                match &mut task.state {
                    Awake => trace!("MockExecutor cloned waker for awake task {id:?}"),
                    Asleep(locs) => locs.push(SleepLocation::force_capture()),
                }
            } else {
                trace!("MockExecutor cloned waker for dead task {id:?}");
            }
        }

        ActualWaker {
            data: self.data.clone(),
            id,
        }
    }
}

//---------- API for full debug dump ----------

/// Debugging dump of a `MockExecutor`'s state
///
/// Returned by [`MockExecutor::as_debug_dump`]
//
// Existence implies backtraces have been resolved
//
// We use `Either` so that we can also use this internally when we have &mut Data.
pub struct DebugDump<'a>(Either<&'a Data, MutexGuard<'a, Data>>);

impl MockExecutor {
    /// Dump the executor's state including backtraces of waiting tasks, to stderr
    ///
    /// This is considerably more extensive than simply
    /// `MockExecutor as Debug`.
    ///
    /// (This is a convenience method, which wraps
    /// [`MockExecutor::as_debug_dump()`].
    ///
    /// ### Backtrace salience (possible spurious traces)
    ///
    /// **Summary**
    ///
    /// The technique used to capture backtraces when futures sleep is not 100% exact.
    /// It will usually show all the actual sleeping sites,
    /// but it might also show other backtraces which were part of
    /// the implementation of some complex relevant future.
    ///
    /// **Details**
    ///
    /// When a future's implementation wants to sleep,
    /// it needs to record the [`Waker`] (from the [`Context`])
    /// so that the "other end" can call `.wake()` on it later,
    /// when the future should be woken.
    ///
    /// Since `Context.waker()` gives `&Waker`, borrowed from the `Context`,
    /// the future must clone the `Waker`,
    /// and it must do so in within the `poll()` call.
    ///
    /// A future which is waiting in a `select!` will typically
    /// show multiple traces, one for each branch.
    /// But,
    /// if a future sleeps on one thing, and then when polled again later,
    /// sleeps on something different, without waking up in between,
    /// both backtrace locations will be shown.
    /// And,
    /// a complicated future contraption *might* clone the `Waker` more times.
    /// So not every backtrace will necessarily be informative.
    ///
    /// ### Panics
    ///
    /// Panics on write errors.
    pub fn debug_dump(&self) {
        self.as_debug_dump().to_stderr();
    }

    /// Dump the executor's state including backtraces of waiting tasks
    ///
    /// This is considerably more extensive than simply
    /// `MockExecutor as Debug`.
    ///
    /// Returns an object for formatting with [`Debug`].
    /// To simply print the dump to stderr (eg in a test),
    /// use [`.debug_dump()`](MockExecutor::debug_dump).
    ///
    /// **Backtrace salience (possible spurious traces)** -
    /// see [`.debug_dump()`](MockExecutor::debug_dump).
    pub fn as_debug_dump(&self) -> DebugDump {
        let data = self.shared.lock();
        DebugDump(Right(data))
    }
}

impl Data {
    /// Convenience function: dump including backtraces, to stderr
    fn debug_dump(&mut self) {
        DebugDump(Left(self)).to_stderr();
    }
}

impl DebugDump<'_> {
    /// Convenience function: dump tasks and backtraces to stderr
    #[allow(clippy::wrong_self_convention)] // "to_stderr" doesn't mean "convert to stderr"
    fn to_stderr(self) {
        write!(io::stderr().lock(), "{:?}", self)
            .unwrap_or_else(|e| error_report!(e, "failed to write debug dump to stderr"));
    }
}

//---------- bespoke Debug impls ----------

impl Debug for DebugDump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let self_: &Data = &self.0;

        writeln!(f, "MockExecutor state:\n{self_:#?}")?;
        writeln!(f, "MockExecutor task dump:")?;
        self_.dump_backtraces(f)?;

        Ok(())
    }
}

// See `impl Debug for Data` for notes on the output
impl Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Task { desc, state, fut } = self;
        write!(f, "{:?}", desc)?;
        write!(f, "=")?;
        match fut {
            None => write!(f, "P")?,
            Some(TaskFutureInfo::Normal(_)) => write!(f, "f")?,
            Some(TaskFutureInfo::Main) => write!(f, "m")?,
            Some(TaskFutureInfo::Subthread) => write!(f, "T")?,
        }
        match state {
            Awake => write!(f, "W")?,
            Asleep(locs) => write!(f, "s{}", locs.len())?,
        };
        Ok(())
    }
}

/// Helper: `Debug`s as a list of tasks, given the `Data` for lookups and a list of the ids
///
/// `Task`s in `Data` are printed as `Ti(ID)"SPEC"=FLAGS"`.
///
/// `FLAGS` are:
///
///  * `T`: this task is for a Subthread (from subthread_spawn).
///  * `P`: this task is being polled (its `TaskFutureInfo` is absent)
///  * `f`: this is a normal task with a future and its future is present in `Data`
///  * `m`: this is the main task from `block_on`
///
///  * `W`: the task is awake
///  * `s<n>`: the task is asleep, and `<n>` is the number of recorded sleeping locations
//
// We do it this way because the naive dump from derive is very expansive
// and makes it impossible to see the wood for the trees.
// This very compact representation it easier to find a task of interest in the output.
//
// This is implemented in `impl Debug for Task`.
//
//
// rustc doesn't think automatically-derived Debug impls count for whether a thing is used.
// This has caused quite some fallout.  https://github.com/rust-lang/rust/pull/85200
// I think derive_more emits #[automatically_derived], so that even though we use this
// in our Debug impl, that construction is unused.
#[allow(dead_code)]
struct DebugTasks<'d, F>(&'d Data, F);

// See `impl Debug for Data` for notes on the output
impl<F, I> Debug for DebugTasks<'_, F>
where
    F: Fn() -> I,
    I: Iterator<Item = TaskId>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DebugTasks(data, ids) = self;
        for (id, delim) in izip!(ids(), chain!(iter::once(""), iter::repeat(" ")),) {
            write!(f, "{delim}{id:?}")?;
            match data.tasks.get(id) {
                None => write!(f, "-")?,
                Some(task) => write!(f, "={task:?}")?,
            }
        }
        Ok(())
    }
}

/// Mock `Backtrace` for miri
///
/// See also the not-miri `type SleepLocation`, alias above.
#[cfg(miri)]
mod miri_sleep_location {
    #[derive(Debug, derive_more::Display)]
    #[display("<SleepLocation>")]
    pub(super) struct SleepLocation {}

    impl SleepLocation {
        pub(super) fn force_capture() -> Self {
            SleepLocation {}
        }
    }
}
#[cfg(miri)]
use miri_sleep_location::SleepLocation;

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use futures::channel::mpsc;
    use futures::{SinkExt as _, StreamExt as _};
    use strum::IntoEnumIterator;
    use tracing::info;

    #[cfg(not(miri))] // trace! asks for the time, which miri doesn't support
    use tracing_test::traced_test;

    fn various_mock_executors() -> impl Iterator<Item = MockExecutor> {
        // This duplicates the part of the logic in MockRuntime::test_with_various which
        // relates to MockExecutor, because we don't have a MockRuntime::builder.
        // The only parameter to MockExecutor is its scheduling policy, so this seems fine.
        SchedulingPolicy::iter().map(|scheduling| {
            eprintln!("===== MockExecutor::with_scheduling({scheduling:?}) =====");
            MockExecutor::with_scheduling(scheduling)
        })
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    fn simple() {
        let runtime = MockExecutor::default();
        let val = runtime.block_on(async { 42 });
        assert_eq!(val, 42);
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    fn stall() {
        let runtime = MockExecutor::default();

        runtime.block_on({
            let runtime = runtime.clone();
            async move {
                const N: usize = 3;
                let (mut txs, mut rxs): (Vec<_>, Vec<_>) =
                    (0..N).map(|_| mpsc::channel::<usize>(5)).unzip();

                let mut rx_n = rxs.pop().unwrap();

                for (i, mut rx) in rxs.into_iter().enumerate() {
                    runtime.spawn_identified(i, {
                        let mut txs = txs.clone();
                        async move {
                            loop {
                                eprintln!("task {i} rx...");
                                let v = rx.next().await.unwrap();
                                let nv = v + 1;
                                eprintln!("task {i} rx {v}, tx {nv}");
                                let v = nv;
                                txs[v].send(v).await.unwrap();
                            }
                        }
                    });
                }

                dbg!();
                let _: mpsc::TryRecvError = rx_n.try_next().unwrap_err();

                dbg!();
                runtime.progress_until_stalled().await;

                dbg!();
                let _: mpsc::TryRecvError = rx_n.try_next().unwrap_err();

                dbg!();
                txs[0].send(0).await.unwrap();

                dbg!();
                runtime.progress_until_stalled().await;

                dbg!();
                let r = rx_n.next().await;
                assert_eq!(r, Some(N - 1));

                dbg!();
                let _: mpsc::TryRecvError = rx_n.try_next().unwrap_err();

                runtime.spawn_identified("tx", {
                    let txs = txs.clone();
                    async {
                        eprintln!("sending task...");
                        for (i, mut tx) in txs.into_iter().enumerate() {
                            eprintln!("sending 0 to {i}...");
                            tx.send(0).await.unwrap();
                        }
                        eprintln!("sending task done");
                    }
                });

                runtime.debug_dump();

                for i in 0..txs.len() {
                    eprintln!("main {i} wait stall...");
                    runtime.progress_until_stalled().await;
                    eprintln!("main {i} rx wait...");
                    let r = rx_n.next().await;
                    eprintln!("main {i} rx = {r:?}");
                    assert!(r == Some(0) || r == Some(N - 1));
                }

                eprintln!("finishing...");
                runtime.progress_until_stalled().await;
                eprintln!("finished.");
            }
        });
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    fn spawn_blocking() {
        let runtime = MockExecutor::default();

        runtime.block_on({
            let runtime = runtime.clone();
            async move {
                let thr_1 = runtime.spawn_blocking(|| 42);
                let thr_2 = runtime.spawn_blocking(|| 99);

                assert_eq!(thr_2.await, 99);
                assert_eq!(thr_1.await, 42);
            }
        });
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    fn drop_reentrancy() {
        // Check that dropping a completed task future is done *outside* the data lock.
        // Involves a contrived future whose Drop impl reenters the executor.
        //
        // If `_fut_drop_late = fut` in execute_until_first_stall (the main loop)
        // is replaced with `drop(fut)` (dropping the future at the wrong moment),
        // we do indeed get deadlock, so this test case is working.

        struct ReentersOnDrop {
            runtime: MockExecutor,
        }
        impl Future for ReentersOnDrop {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<()> {
                Poll::Ready(())
            }
        }
        impl Drop for ReentersOnDrop {
            fn drop(&mut self) {
                self.runtime
                    .spawn_identified("dummy", futures::future::ready(()));
            }
        }

        for runtime in various_mock_executors() {
            runtime.block_on(async {
                runtime.spawn_identified("trapper", {
                    let runtime = runtime.clone();
                    ReentersOnDrop { runtime }
                });
            });
        }
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    fn subthread_oneshot() {
        for runtime in various_mock_executors() {
            runtime.block_on(async {
                let (tx, rx) = oneshot::channel();
                info!("spawning subthread");
                let thr = runtime.subthread_spawn("thr1", {
                    let runtime = runtime.clone();
                    move || {
                        info!("subthread_block_on_future...");
                        let i = runtime.subthread_block_on_future(rx).unwrap();
                        info!("subthread_block_on_future => {i}");
                        i + 1
                    }
                });
                info!("main task sending");
                tx.send(12).unwrap();
                info!("main task sent");
                let r = thr.await.unwrap();
                info!("main task thr => {r}");
                assert_eq!(r, 13);
            });
        }
    }

    #[cfg_attr(not(miri), traced_test)]
    #[test]
    #[allow(clippy::cognitive_complexity)] // It's is not that complicated, really.
    fn subthread_pingpong() {
        for runtime in various_mock_executors() {
            runtime.block_on(async {
                let (mut i_tx, mut i_rx) = mpsc::channel(1);
                let (mut o_tx, mut o_rx) = mpsc::channel(1);
                info!("spawning subthread");
                let thr = runtime.subthread_spawn("thr", {
                    let runtime = runtime.clone();
                    move || {
                        while let Some(i) = {
                            info!("thread receiving ...");
                            runtime.subthread_block_on_future(i_rx.next())
                        } {
                            let o = i + 12;
                            info!("thread received {i}, sending {o}");
                            runtime.subthread_block_on_future(o_tx.send(o)).unwrap();
                            info!("thread sent {o}");
                        }
                        info!("thread exiting");
                        42
                    }
                });
                for i in 0..2 {
                    info!("main task sending {i}");
                    i_tx.send(i).await.unwrap();
                    info!("main task sent {i}");
                    let o = o_rx.next().await.unwrap();
                    info!("main task recv => {o}");
                    assert_eq!(o, i + 12);
                }
                info!("main task dropping sender");
                drop(i_tx);
                info!("main task awaiting thread");
                let r = thr.await.unwrap();
                info!("main task complete");
                assert_eq!(r, 42);
            });
        }
    }
}
