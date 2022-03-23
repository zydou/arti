//! Utilities for dealing with periodic recurring tasks.

use crate::SleepProvider;
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{Stream, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use pin_project::pin_project;

/// A command sent from task handles to schedule objects.
#[derive(Copy, Clone)]
enum SchedulerCommand {
    /// Run the task now.
    Fire,
    /// Run the task after the provided duration.
    FireIn(Duration),
    /// Cancel a pending execution, if there is one.
    Cancel,
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
}

/// A handle used to control a [`TaskSchedule`].
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
            },
            TaskHandle { tx },
        )
    }

    /// Trigger the schedule after `dur`.
    pub fn fire_in(&mut self, dur: Duration) {
        self.instant_fire = false;
        self.sleep = Some(Box::pin(self.rt.sleep(dur)));
    }
}

impl TaskHandle {
    /// Trigger this handle's corresponding schedule now.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn fire(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Fire).is_ok()
    }
    /// Trigger this handle's corresponding schedule after `dur`.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn fire_in(&self, dur: Duration) -> bool {
        self.tx
            .unbounded_send(SchedulerCommand::FireIn(dur))
            .is_ok()
    }
    /// Cancel a pending firing of the handle's corresponding schedule.
    ///
    /// Returns `true` if the schedule still exists, and `false` otherwise.
    pub fn cancel(&self) -> bool {
        self.tx.unbounded_send(SchedulerCommand::Cancel).is_ok()
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
            SchedulerCommand::FireIn(dur) => {
                *self.instant_fire = false;
                *self.sleep = Some(Box::pin(self.rt.sleep(dur)));
            }
            SchedulerCommand::Cancel => {
                *self.instant_fire = false;
                *self.sleep = None;
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
