//! Code to collect and publish information about a client's bootstrapping
//! status.

use std::{borrow::Cow, fmt};

use derive_more::Display;
use futures::{channel::oneshot, future, Stream, StreamExt};

/// Information about how ready a [`crate::TorClient`] is to handle requests.
///
/// Note that this status does not change monotonically: a `TorClient` can
/// become more _or less_ bootstrapped over time. (For example, a client can
/// become less bootstrapped if it loses its internet connectivity, or if its
/// directory information expires before it's able to replace it.)
//
// # Note
//
// We need to keep this type fairly small, since it will get cloned whenever
// it's observed on a stream.   If it grows large, we can add an Arc<> around
// its data.
#[derive(Debug, Clone, Default)]
pub struct BootstrapStatus {
    /// A placeholder field: we'll be replacing this as the branch gets support
    /// for more information sources.
    ready: bool,
}

impl BootstrapStatus {
    /// Return a rough fraction (from 0.0 to 1.0) representing how far along
    /// the client's bootstrapping efforts are.
    ///
    /// 0 is defined as "just started"; 1 is defined as "ready to use."
    pub fn as_frac(&self) -> f32 {
        if self.ready {
            1.0
        } else {
            0.0
        }
    }

    /// Return true if the status indicates that the client is ready for
    /// traffic.
    ///
    /// For the purposes of this function, the client is "ready for traffic" if,
    /// as far as we know, we can start acting on a new client request immediately.
    pub fn ready_for_traffic(&self) -> bool {
        self.ready
    }

    /// If the client is unable to make forward progress for some reason, return
    /// that reason.
    ///
    /// (Returns None if the client doesn't seem to be stuck.)
    ///
    /// # Caveats
    ///
    /// This function provides a "best effort" diagnostic: there
    /// will always be some blockage types that it can't diagnose
    /// correctly.  It may declare that Arti is stuck for reasons that
    /// are incorrect; or it may declare that the client is not stuck
    /// when in fact no progress is being made.
    ///
    /// Therefore, the caller should always use a certain amount of
    /// modesty when reporting these values to the user. For example,
    /// it's probably better to say "Arti says it's stuck because it
    /// can't make connections to the internet" rather than "You are
    /// not on the internet."
    pub fn blocked(&self) -> Option<Blockage> {
        // TODO(nickm): implement this or remove it.
        None
    }
}

/// A reason why a client believes it is stuck.
#[derive(Clone, Debug, Display)]
#[display(fmt = "{} ({})", "kind", "message")]
pub struct Blockage {
    /// Why do we think we're blocked?
    kind: BlockageKind,
    /// A human-readable message about the blockage.
    message: Cow<'static, str>,
}

/// A specific type of blockage that a client believes it is experiencing.
///
/// Used to distinguish among instances of [`Blockage`].
#[derive(Clone, Debug, Display)]
#[non_exhaustive]
pub enum BlockageKind {
    /// It looks like we can't make connections to the internet.
    #[display(fmt = "Unable to connect to the internet")]
    NoInternet,
    /// It looks like we can't reach any Tor relays.
    #[display(fmt = "Unable to reach Tor")]
    CantReachTor,
    /// We've been unable to download our directory information for some reason.
    #[display(fmt = "Stalled fetching a Tor directory")]
    DirectoryStalled,
}

impl fmt::Display for BootstrapStatus {
    /// Format this [`BootstrapStatus`].
    ///
    /// Note that the string returned by this function is designed for human
    /// readability, not for machine parsing.  Other code *should not* depend
    /// on particular elements of this string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let percent = (self.as_frac() * 100.0).round() as u32;
        if let Some(problem) = self.blocked() {
            write!(f, "Stuck at {}%: {}", percent, problem)
        } else {
            // TODO(nickm): describe what we're doing.
            write!(f, "{}%", percent)
        }
    }
}

/// Task that runs forever, updating a client's status via the provided
/// `sender`.
///
/// TODO(nickm): Eventually this will use real stream of events to see when we
/// are bootstrapped or not.  For now, it just says that we're not-ready until
/// the given Receiver fires.
///
/// TODO(nickm): This should eventually close the stream when the client is
/// dropped.
pub(crate) async fn report_status(
    mut sender: postage::watch::Sender<BootstrapStatus>,
    ready: oneshot::Receiver<()>,
) {
    {
        sender.borrow_mut().ready = false;
    }
    if ready.await.is_ok() {
        sender.borrow_mut().ready = true;
    }

    // wait forever.
    future::pending::<()>().await;
}

/// A [`Stream`] of [`BootstrapStatus`] events.
///
/// This stream isn't guaranteed to receive every change in bootstrap status; if
/// changes happen more frequently than the receiver can observe, some of them
/// will be dropped.
//
// Note: We use a wrapper type around watch::Receiver here, in order to hide its
// implementation type.  We do that because we might want to change the type in
// the future, and because some of the functionality exposed by Receiver (like
// `borrow()` and the postage::Stream trait) are extraneous to the API we want.
#[derive(Clone)]
pub struct BootstrapEvents {
    /// The receiver that implements this stream.
    pub(crate) inner: postage::watch::Receiver<BootstrapStatus>,
}

// We can't derive(Debug) since postage::watch::Receiver doesn't implement
// Debug.
impl std::fmt::Debug for BootstrapEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BootstrapEvents").finish_non_exhaustive()
    }
}

impl Stream for BootstrapEvents {
    type Item = BootstrapStatus;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}
