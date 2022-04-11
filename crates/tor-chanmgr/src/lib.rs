//! `tor-chanmgr`: Manage a set of channels on the Tor network.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a channel is a connection to a Tor relay.  It can be
//! direct via TLS, or indirect via TLS over a pluggable transport.
//! (For now, only direct channels are supported.)
//!
//! Since a channel can be used for more than one circuit, it's
//! important to reuse channels when possible.  This crate implements
//! a [`ChanMgr`] type that can be used to create channels on demand,
//! and return existing channels when they already exist.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod builder;
mod err;
mod event;
mod mgr;
#[cfg(test)]
mod testing;

use futures::task::SpawnExt;
use futures::StreamExt;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tor_linkspec::{ChanTarget, OwnedChanTarget};
use tor_proto::channel::Channel;

pub use err::Error;

use tor_rtcompat::Runtime;

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

pub use event::{ConnBlockage, ConnStatus, ConnStatusEvents};
use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};

/// A Type that remembers a set of live channels, and launches new
/// ones on request.
///
/// Use the [ChanMgr::get_or_launch] function to create a new channel, or
/// get one if it exists.
pub struct ChanMgr<R: Runtime> {
    /// Internal channel manager object that does the actual work.
    mgr: mgr::AbstractChanMgr<builder::ChanBuilder<R>>,

    /// Stream of [`ConnStatus`] events.
    bootstrap_status: event::ConnStatusEvents,
}

/// Description of how we got a channel.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ChanProvenance {
    /// This channel was newly launched, or was in progress and finished while
    /// we were waiting.
    NewlyCreated,
    /// This channel already existed when we asked for it.
    Preexisting,
}

impl<R: Runtime> ChanMgr<R> {
    /// Construct a new channel manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `ChanMgr::launch_background_tasks`.
    pub fn new(runtime: R) -> Self {
        let (sender, receiver) = event::channel();
        let builder = builder::ChanBuilder::new(runtime, sender);
        let mgr = mgr::AbstractChanMgr::new(builder);
        ChanMgr {
            mgr,
            bootstrap_status: receiver,
        }
    }

    /// Launch the periodic daemon task required by the manager to function properly.
    ///
    /// Returns a [`TaskHandle`] that can be used to manage the daemon task.
    pub fn launch_background_tasks(self: &Arc<Self>, runtime: &R) -> Result<Vec<TaskHandle>> {
        let (sched, handle) = TaskSchedule::new(runtime.clone());
        runtime
            .spawn(Self::continually_expire_channels(
                sched,
                Arc::downgrade(self),
            ))
            .map_err(|e| Error::from_spawn("channel expiration task", e))?;
        Ok(vec![handle])
    }

    /// Try to get a suitable channel to the provided `target`,
    /// launching one if one does not exist.
    ///
    /// If there is already a channel launch attempt in progress, this
    /// function will wait until that launch is complete, and succeed
    /// or fail depending on its outcome.
    pub async fn get_or_launch<T: ChanTarget + ?Sized>(
        &self,
        target: &T,
    ) -> Result<(Channel, ChanProvenance)> {
        let ed_identity = target.ed_identity();
        let targetinfo = OwnedChanTarget::from_chan_target(target);

        let (chan, provenance) = self.mgr.get_or_launch(*ed_identity, targetinfo).await?;
        // Double-check the match to make sure that the RSA identity is
        // what we wanted too.
        chan.check_match(target)
            .map_err(Error::from_proto_no_skew)?;
        Ok((chan, provenance))
    }

    /// Return a stream of [`ConnStatus`] events to tell us about changes
    /// in our ability to connect to the internet.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    pub fn bootstrap_events(&self) -> ConnStatusEvents {
        self.bootstrap_status.clone()
    }

    /// Expire all channels that have been unused for too long.
    ///
    /// Return the duration from now until next channel expires.
    pub fn expire_channels(&self) -> Duration {
        self.mgr.expire_channels()
    }

    /// Periodically expire any channels that have been unused beyond
    /// the maximum duration allowed.
    ///
    /// Exist when we find that `chanmgr` is dropped
    ///
    /// This is a daemon task that runs indefinitely in the background
    async fn continually_expire_channels(mut sched: TaskSchedule<R>, chanmgr: Weak<Self>) {
        while sched.next().await.is_some() {
            let delay = if let Some(cm) = Weak::upgrade(&chanmgr) {
                cm.expire_channels()
            } else {
                // channel manager is closed.
                return;
            };
            // This will sometimes be an underestimate, but it's no big deal; we just sleep some more.
            sched.fire_in(Duration::from_secs(delay.as_secs()));
        }
    }
}
