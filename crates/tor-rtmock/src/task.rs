//! Executor for running tests with mocked environment
//!
//! See [`MockExecutor`]

use std::collections::VecDeque;
use std::fmt::{self, Debug, Display};
use std::future::Future;
use std::io::{self, Write as _};
use std::iter;
use std::mem;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use futures::pin_mut;
use futures::task::{FutureObj, Spawn, SpawnError};
use futures::FutureExt as _;

use backtrace::Backtrace;
use educe::Educe;
use itertools::Either;
use itertools::{chain, izip};
use slotmap::DenseSlotMap;
use strum::EnumIter;
use tracing::trace;

use tor_error::error_report;
use tor_rtcompat::BlockOn;

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
/// It implements [`Spawn`] and [`BlockOn`]
///
/// It will usually be used as part of a `MockRuntime`.
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
/// This executor will malfunction or panic if reentered.
#[derive(Clone, Default, Educe)]
#[educe(Debug)]
pub struct MockExecutor {
    /// Mutable state
    #[educe(Debug(ignore))]
    data: ArcMutexData,
}

/// Mutable state, wrapper type mostly so we can provide `.lock()`
#[derive(Clone, Default)]
struct ArcMutexData(Arc<Mutex<Data>>);

/// Task id, module to hide `Ti` alias
mod task_id {
    slotmap::new_key_type! {
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
#[derive(Default)]
struct Data {
    /// Tasks
    ///
    /// Includes tasks spawned with `spawn`,
    /// and also the future passed to `block_on`.
    tasks: DenseSlotMap<TaskId, Task>,

    /// `awake` lists precisely: tasks that are `Awake`, plus maybe stale `TaskId`s
    ///
    /// Tasks are pushed onto the *back* when woken,
    /// so back is the most recently woken.
    awake: VecDeque<TaskId>,

    /// If a future from `progress_until_stalled` exists
    progressing_until_stalled: Option<ProgressingUntilStalled>,

    /// Scheduling policy
    scheduling: SchedulingPolicy,
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
    state: TaskState,
    /// The actual future (or a placeholder for it)
    ///
    /// May be `None` because we've temporarily moved it out so we can poll it
    fut: Option<TaskFutureInfo>,
}

/// A future as stored in our record of a [`Task`]
enum TaskFutureInfo {
    /// The [`Future`].  All is normal.
    Normal(TaskFuture),
    /// The future isn't here because this task is the main future for `block_on`
    Main,
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
    data: ArcMutexData,

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
    data: ArcMutexData,
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
        MockExecutor {
            data: ArcMutexData(Arc::new(Mutex::new(data))),
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
    /// This method is infalliable.  (The `MockExecutor` cannot be shut down.)
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
        let (tx, rx) = tor_async_utils::oneshot::channel();
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
        let mut data = self.data.lock();
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
        self.spawn_internal("".into(), future);
        Ok(())
    }
}

//---------- block_on ----------

impl BlockOn for MockExecutor {
    /// Run `fut` to completion, synchronously
    ///
    /// # Panics
    ///
    /// Might malfunction or panic if:
    ///
    /// * The provided future doesn't complete (without externally blocking),
    ///    but instead waits for something.
    ///
    /// * The `MockExecutor` is reentered.  (Eg, `block_on` is reentered.)
    fn block_on<F>(&self, fut: F) -> F::Output
    where
        F: Future,
    {
        let mut value: Option<F::Output> = None;
        let fut = {
            let value = &mut value;
            async move {
                trace!("MockExecutor block_on future...");
                let t = fut.await;
                trace!("MockExecutor block_on future returned...");
                *value = Some(t);
                trace!("MockExecutor block_on future exiting.");
            }
        };

        {
            pin_mut!(fut);
            self.data
                .lock()
                .insert_task("main".into(), TaskFutureInfo::Main);
            self.execute_to_completion(fut);
        }

        #[allow(clippy::let_and_return)] // clarity
        let value = value.take().unwrap_or_else(|| {
            let mut data = self.data.lock();
            data.debug_dump();
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
                let mut data = self.data.lock();
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
                let mut data = self.data.lock();

                let pus = &mut data.progressing_until_stalled;
                if let Some(double) = mem::replace(
                    &mut pus
                        .as_mut()
                        .expect("progressing_until_stalled updated under our feet!")
                        .waker,
                    Some(waker),
                ) {
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
    #[allow(clippy::cognitive_complexity)]
    fn execute_until_first_stall(&self, mut main_fut: MainFuture) {
        trace!("MockExecutor execute_until_first_stall ...");
        'outer: loop {
            // Take a `Awake` task off `awake` and make it `Polling`
            let (id, mut fut) = 'inner: loop {
                let mut data = self.data.lock();
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
            let waker = ActualWaker {
                data: self.data.clone(),
                id,
            }
            .new_waker();
            trace!("MockExecutor {id:?} polling...");
            let mut cx = Context::from_waker(&waker);
            let r = match &mut fut {
                TaskFutureInfo::Normal(fut) => fut.poll_unpin(&mut cx),
                TaskFutureInfo::Main => main_fut.as_mut().poll(&mut cx),
            };

            // Deal with the returned `Poll`
            {
                let mut data = self.data.lock();
                let task = data
                    .tasks
                    .get_mut(id)
                    .expect("task vanished while we were polling it");

                match r {
                    Pending => {
                        trace!("MockExecutor {id:?} -> Pending");
                        if task.fut.is_some() {
                            panic!("task reinserted while we polled it?!");
                        }
                        // The task might have been woken *by its own poll method*.
                        // That's why we set it to `Asleep` *earlier* rather than here.
                        // All we need to do is put the future back.
                        task.fut = Some(fut);
                    }
                    Ready(()) => {
                        trace!("MockExecutor {id:?} -> Ready");
                        // Oh, it finished!
                        // It might be in `awake`, but that's allowed to contain stale tasks,
                        // so we *don't* need to scan that list and remove it.
                        data.tasks.remove(id);
                    }
                }
            }
        }
        trace!("MockExecutor execute_until_first_stall done.");
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
    /// Wake the task corresponding to this `ActualWaker`
    ///
    /// This is like `<Self as std::task::Wake>::wake()` but takes `&self`, not `Arc`
    fn wake(&self) {
        let mut data = self.data.lock();
        trace!("MockExecutor {:?} wake", &self.id);
        let Some(task) = data.tasks.get_mut(self.id) else {
            return;
        };
        match task.state {
            Awake => {}
            Asleep(_) => {
                task.state = Awake;
                data.awake.push_back(self.id);
            }
        }
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
    pub fn progress_until_stalled(&self) -> impl Future<Output = ()> {
        let mut data = self.data.lock();
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
            data: self.data.clone(),
        }
    }
}

impl Future for ProgressUntilStalledFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        let waker = cx.waker().clone();
        let mut data = self.data.lock();
        let pus = data.progressing_until_stalled.as_mut();
        trace!("MockExecutor progress_until_stalled polling... {:?}", &pus);
        let pus = pus.expect("ProgressingUntilStalled missing");
        pus.waker = Some(waker);
        pus.finished
    }
}

impl Drop for ProgressUntilStalledFuture {
    fn drop(&mut self) {
        self.data.lock().progressing_until_stalled = None;
    }
}

//---------- ancillary and convenience functions ----------

/// Trait to let us assert at compile time that something is nicely `Sync` etc.
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
        self.data.lock().tasks.len()
    }
}

impl ArcMutexData {
    /// Lock and obtain the guard
    ///
    /// Convenience method which panics on poison
    fn lock(&self) -> MutexGuard<Data> {
        self.0.lock().expect("data lock poisoned")
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
        let self_: *const ActualWaker = self_ as _;
        let self_: &ActualWaker = self_.as_ref().unwrap_unchecked();
        let copy: ActualWaker = self_.clone();
        copy.raw_new()
    }

    /// Implementation of [`RawWakerVTable`]'s `wake`
    unsafe fn raw_wake(self_: *const ()) {
        Self::raw_wake_by_ref(self_);
        Self::raw_drop(self_);
    }

    /// Implementation of [`RawWakerVTable`]'s `wake_ref_by`
    unsafe fn raw_wake_by_ref(self_: *const ()) {
        let self_: *const ActualWaker = self_ as _;
        let self_: &ActualWaker = self_.as_ref().unwrap_unchecked();
        self_.wake();
    }

    /// Implementation of [`RawWakerVTable`]'s `drop`
    unsafe fn raw_drop(self_: *const ()) {
        let self_: *mut ActualWaker = self_ as _;
        let self_: Box<ActualWaker> = Box::from_raw(self_);
        drop(self_);
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

/// Proof token that `resolve_backtraces` has been called.
#[derive(Clone, Copy)]
struct BacktracesResolved {}

/// We record "where a future went to sleep" as (just) a backtrace
type SleepLocation = Backtrace;

impl Data {
    /// Resolve backtraces (for debug dump)
    fn resolve_backtraces(&mut self) -> BacktracesResolved {
        for (_id, task) in &mut self.tasks {
            match &mut task.state {
                Awake => {}
                Asleep(locs) => {
                    for loc in locs {
                        loc.resolve();
                    }
                }
            }
        }
        BacktracesResolved {}
    }

    /// Dump tasks and their sleep location backtraces
    ///
    /// `resolve_backtraces` must have been called.
    /// (This split allows us to make a wrapper that can be `Debug`,
    /// where the printing has to work with `&` not `&mut`.)
    fn dump_backtraces(&self, f: &mut fmt::Formatter, _: BacktracesResolved) -> fmt::Result {
        for (id, task) in &self.tasks {
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
                        writeln!(f, "asleep, backtrace {i}/{n}:\n{loc:?}",)?;
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

        {
            let mut data = self.data.lock();
            if let Some(task) = data.tasks.get_mut(self.id) {
                match &mut task.state {
                    Awake => trace!("MockExecutor cloned waker for awake task {id:?}"),
                    Asleep(locs) => locs.push(SleepLocation::new_unresolved()),
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
pub struct DebugDump<'a>(Either<&'a Data, MutexGuard<'a, Data>>, BacktracesResolved);

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
        let mut data = self.data.lock();
        let resolved = data.resolve_backtraces();
        DebugDump(Either::Right(data), resolved)
    }
}

impl Data {
    /// Convenience function: dump including backtraces, to stderr
    fn debug_dump(&mut self) {
        let resolved = self.resolve_backtraces();
        DebugDump(Either::Left(self), resolved).to_stderr();
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
        self_.dump_backtraces(f, self.1)?;

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
        }
        match state {
            Awake => write!(f, "W")?,
            Asleep(locs) => write!(f, "s{}", locs.len())?,
        };
        Ok(())
    }
}

/// Helper: `Debug`s as a list of tasks, given the `Data` for lookups and a list of the ids
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

/// `Task`s in `Data` are printed as `Ti(ID)"SPEC"=FLAGS"`.
///
/// `FLAGS` are:
///
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
impl Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Data {
            tasks,
            awake,
            progressing_until_stalled: pus,
            scheduling,
        } = self;
        let mut s = f.debug_struct("Data");
        s.field("tasks", &DebugTasks(self, || tasks.keys()));
        s.field("awake", &DebugTasks(self, || awake.iter().cloned()));
        s.field("p.u.s", pus);
        s.field("scheduling", scheduling);
        s.finish()
    }
}

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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use futures::channel::mpsc;
    use futures::{SinkExt as _, StreamExt as _};

    #[cfg(not(miri))] // trace! asks for the time, which miri doesn't support
    use tracing_test::traced_test;

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
}
