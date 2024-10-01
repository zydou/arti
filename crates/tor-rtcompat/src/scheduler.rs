//! Utilities for dealing with periodic recurring tasks.

use crate::SleepProvider;
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{Stream, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};

use pin_project::pin_project;

/// An error returned while telling a [`TaskSchedule`] to sleep.
///
/// Unlike regular "sleep" functions, the sleep operations on a [`TaskSchedule`]
/// can fail because there are no [`TaskHandle`]s left.
///
/// Note that it is *not* an error if the `sleep` function is interrupted,
/// cancelled, or  or rescheduled for a later time: See [`TaskSchedule::sleep`]
/// for more information.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SleepError {
    /// The final [`TaskHandle`] for this [`TaskSchedule`] has been dropped: the
    /// task should exit.
    #[error("All task handles dropped: task exiting.")]
    ScheduleDropped,
}

/// A command sent from task handles to schedule objects.
#[derive(Copy, Clone)]
enum SchedulerCommand {
    /// Run the task now.
    Fire,
    /// Run the task at the provided `Instant`.
    FireAt(Instant),
    /// Cancel a pending execution, if there is one.
    Cancel,
    /// Pause execution without cancelling any running timers.  (Those timers
    /// will fire after we resume execution.)
    Suspend,
    /// Resume execution.  If there is a pending timer, start waiting for it again;
    /// otherwise, fire immediately.
    Resume,
}

/// A remotely-controllable trigger for recurring tasks.
///
/// This implements [`Stream`], and is intended to be used in a `while` loop; you should
/// wrap your recurring task in a `while schedule.next().await.is_some()` or similar.
#[pin_project(project = TaskScheduleP)]
pub struct TaskSchedule<R: SleepProvider> {
    /// If we're waiting for a deadline to expire, the future for that.
    sleep: Option<Pin<Box<R::SleepFuture>>>,
    /// Receiver of scheduler commands from handles.
    rx: UnboundedReceiver<SchedulerCommand>,
    /// Runtime.
    rt: R,
    /// Whether or not to yield a result immediately when polled, once.
    ///
    /// This is used to avoid having to create a `SleepFuture` with zero duration,
    /// which is potentially a bit wasteful.
    instant_fire: bool,
    /// Whether we are currently "suspended".  If we are suspended, we won't
    /// start executing again till we're explicitly "resumed".
    suspended: bool,
}

/// A handle used to control a [`TaskSchedule`].
///
/// When the final handle is dropped, the computation governed by the
/// `TaskSchedule` should terminate.
#[derive(Clone)]
pub struct TaskHandle {
    /// Sender of scheduler commands to the corresponding schedule.
    tx: UnboundedSender<SchedulerCommand>,
}

impl<R: SleepProvider> TaskSchedule<R> {
    /// Create a new schedule, and corresponding handle.
    pub fn new(rt: R) -> (Self, TaskHandle) {
        let (tx, rx) = mpsc::unbounded();
        (
            Self {
                sleep: None,
                rx,
                rt,
                // Start off ready.
                instant_fire: true,
                suspended: false,
            },
            TaskHandle { tx },
        )
    }

    /// Trigger the schedule after `dur`.
    pub fn fire_in(&mut self, dur: Duration) {
        self.instant_fire = false;
        self.sleep = Some(Box::pin(self.rt.sleep(dur)));
    }

    /// Trigger the schedule instantly.
    pub fn fire(&mut self) {
        self.instant_fire = true;
        self.sleep = None;
    }

    /// Wait until `Dur` has elapsed.
    ///
    /// This call is equivalent to [`SleepProvider::sleep`], except that the
    /// resulting future will respect calls to the functions on this schedule's
    /// associated [`TaskHandle`].
    ///
    /// Alternatively, you can view this function as equivalent to
    /// `self.fire_in(dur); self.next().await;`, only  with the intent made more
    /// explicit.
    ///
    /// If the associated [`TaskHandle`] for this schedule is suspended, then
    /// this method will not return until the schedule is unsuspended _and_ the
    /// timer elapses.  If the associated [`TaskHandle`] is cancelled, then this
    /// method will not return at all, until the schedule is re-activated by
    /// [`TaskHandle::fire`] or [`TaskHandle::fire_at`].
    ///
    /// Finally, if every associated [`TaskHandle`] has been dropped, then this
    /// method will return an error.
    pub async fn sleep(&mut self, dur: Duration) -> Result<(), SleepError> {
        self.fire_in(dur);
        self.next().await.ok_or(SleepError::ScheduleDropped)
    }

    /// As
    /// [`sleep_until_wallclock`](crate::SleepProviderExt::sleep_until_wallclock),
    /// but respect messages from this schedule's associated [`TaskHandle`].
    pub async fn sleep_until_wallclock(&mut self, when: SystemTime) -> Result<(), SleepError> {
        loop {
            let (finished, delay) = crate::timer::calc_next_delay(self.rt.wallclock(), when);
            self.sleep(delay).await?;
            if finished {
                return Ok(());
            }
        }
    }
}

impl TaskHandle {
    /// Trigger this handle's corresponding schedule now.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn fire(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Fire).is_ok()
    }
    /// Trigger this handle's corresponding schedule at `instant`.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn fire_at(&self, instant: Instant) -> bool {
        self.tx
            .unbounded_send(SchedulerCommand::FireAt(instant))
            .is_ok()
    }
    /// Cancel a pending firing of the handle's corresponding schedule.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn cancel(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Cancel).is_ok()
    }

    /// Suspend execution of the corresponding schedule.
    ///
    /// If the schedule is ready now, it will become pending; it won't become
    /// ready again until `resume()` is called. If the schedule is waiting for a
    /// timer, the timer will keep counting, but the schedule won't become ready
    /// until the timer has elapsed _and_ `resume()` has been called.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn suspend(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Suspend).is_ok()
    }

    /// Resume execution of the corresponding schedule.
    ///
    /// This method undoes the effect of a call to `suspend()`: the schedule
    /// will fire again if it is ready (or when it becomes ready).
    ///
    /// This method won't cause the schedule to fire if it was already
    /// cancelled. For that, use the `fire()` or fire_at()` methods.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn resume(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Resume).is_ok()
    }
}

// NOTE(eta): implemented on the *pin projection*, not the original type, because we don't want
//            to require `R: Unpin`. Accordingly, all the fields are mutable references.
impl<R: SleepProvider> TaskScheduleP<'_, R> {
    /// Handle an internal command.
    fn handle_command(&mut self, cmd: SchedulerCommand) {
        match cmd {
            SchedulerCommand::Fire => {
                *self.instant_fire = true;
                *self.sleep = None;
            }
            SchedulerCommand::FireAt(instant) => {
                let now = self.rt.now();
                let dur = instant.saturating_duration_since(now);
                *self.instant_fire = false;
                *self.sleep = Some(Box::pin(self.rt.sleep(dur)));
            }
            SchedulerCommand::Cancel => {
                *self.instant_fire = false;
                *self.sleep = None;
            }
            SchedulerCommand::Suspend => {
                *self.suspended = true;
            }
            SchedulerCommand::Resume => {
                *self.suspended = false;
            }
        }
    }
}

impl<R: SleepProvider> Stream for TaskSchedule<R> {
    type Item = ();

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        while let Poll::Ready(maybe_cmd) = this.rx.poll_next_unpin(cx) {
            match maybe_cmd {
                Some(c) => this.handle_command(c),
                None => {
                    // All task handles dropped; return end of stream.
                    return Poll::Ready(None);
                }
            }
        }
        if *this.suspended {
            return Poll::Pending;
        }
        if *this.instant_fire {
            *this.instant_fire = false;
            return Poll::Ready(Some(()));
        }
        if this
            .sleep
            .as_mut()
            .map(|x| x.as_mut().poll(cx).is_ready())
            .unwrap_or(false)
        {
            *this.sleep = None;
            return Poll::Ready(Some(()));
        }
        Poll::Pending
    }
}

// test_with_all_runtimes! only exists if these features are satisfied.
#[cfg(all(
    test,
    any(feature = "native-tls", feature = "rustls"),
    any(feature = "tokio", feature = "async-std"),
    not(miri), // Several of these use real SystemTime
))]
mod test {
    use crate::scheduler::TaskSchedule;
    use crate::{test_with_all_runtimes, SleepProvider};
    use futures::FutureExt;
    use futures::StreamExt;
    use std::time::{Duration, Instant};

    #[test]
    fn it_fires_immediately() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, _hdl) = TaskSchedule::new(rt);
            assert!(sch.next().now_or_never().is_some());
        });
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn it_dies_if_dropped() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt);
            drop(hdl);
            assert!(sch.next().now_or_never().unwrap().is_none());
        });
    }

    #[test]
    fn it_fires_on_demand() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt);
            assert!(sch.next().now_or_never().is_some());

            assert!(sch.next().now_or_never().is_none());
            assert!(hdl.fire());
            assert!(sch.next().now_or_never().is_some());
            assert!(sch.next().now_or_never().is_none());
        });
    }

    #[test]
    fn it_cancels_instant_firings() {
        // NOTE(eta): this test very much assumes that unbounded channels will
        //            transmit things instantly. If it breaks, that's probably why.
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt);
            assert!(sch.next().now_or_never().is_some());

            assert!(sch.next().now_or_never().is_none());
            assert!(hdl.fire());
            assert!(hdl.cancel());
            assert!(sch.next().now_or_never().is_none());
        });
    }

    #[test]
    fn it_fires_after_self_reschedule() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, _hdl) = TaskSchedule::new(rt);
            assert!(sch.next().now_or_never().is_some());

            sch.fire_in(Duration::from_millis(100));

            assert!(sch.next().now_or_never().is_none());
            assert!(sch.next().await.is_some());
            assert!(sch.next().now_or_never().is_none());
        });
    }

    #[test]
    fn it_fires_after_external_reschedule() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt);
            assert!(sch.next().now_or_never().is_some());

            hdl.fire_at(Instant::now() + Duration::from_millis(100));

            assert!(sch.next().now_or_never().is_none());
            assert!(sch.next().await.is_some());
            assert!(sch.next().now_or_never().is_none());
        });
    }

    // This test is disabled because it was flaky when the CI servers were
    // heavily loaded. (See #545.)
    //
    // TODO: Let's fix this test and make it more reliable, then re-enable it.
    #[test]
    #[ignore]
    fn it_cancels_delayed_firings() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt.clone());
            assert!(sch.next().now_or_never().is_some());

            hdl.fire_at(Instant::now() + Duration::from_millis(100));

            assert!(sch.next().now_or_never().is_none());

            rt.sleep(Duration::from_millis(50)).await;

            assert!(sch.next().now_or_never().is_none());

            hdl.cancel();

            assert!(sch.next().now_or_never().is_none());

            rt.sleep(Duration::from_millis(100)).await;

            assert!(sch.next().now_or_never().is_none());
        });
    }

    #[test]
    fn last_fire_wins() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt.clone());
            assert!(sch.next().now_or_never().is_some());

            hdl.fire_at(Instant::now() + Duration::from_millis(100));
            hdl.fire();

            assert!(sch.next().now_or_never().is_some());
            assert!(sch.next().now_or_never().is_none());

            rt.sleep(Duration::from_millis(150)).await;

            assert!(sch.next().now_or_never().is_none());
        });
    }

    #[test]
    fn suspend_and_resume_with_fire() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt.clone());
            hdl.fire();
            hdl.suspend();

            assert!(sch.next().now_or_never().is_none());
            hdl.resume();
            assert!(sch.next().now_or_never().is_some());
        });
    }

    #[test]
    fn suspend_and_resume_with_sleep() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt.clone());
            sch.fire_in(Duration::from_millis(100));
            hdl.suspend();

            assert!(sch.next().now_or_never().is_none());
            hdl.resume();
            assert!(sch.next().now_or_never().is_none());
            assert!(sch.next().await.is_some());
        });
    }

    #[test]
    fn suspend_and_resume_with_nothing() {
        test_with_all_runtimes!(|rt| async move {
            let (mut sch, hdl) = TaskSchedule::new(rt.clone());
            assert!(sch.next().now_or_never().is_some());
            hdl.suspend();

            assert!(sch.next().now_or_never().is_none());
            hdl.resume();
        });
    }
}
