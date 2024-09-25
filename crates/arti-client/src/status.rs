//! Code to collect and publish information about a client's bootstrapping
//! status.

use std::{borrow::Cow, fmt, fmt::Display, time::SystemTime};

use educe::Educe;
use futures::{Stream, StreamExt};
use tor_basic_utils::skip_fmt;
use tor_chanmgr::{ConnBlockage, ConnStatus, ConnStatusEvents};
use tor_circmgr::{ClockSkewEvents, SkewEstimate};
use tor_dirmgr::{DirBlockage, DirBootstrapStatus};
use tracing::debug;

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
    /// Status for our connection to the tor network
    conn_status: ConnStatus,
    /// Status for our directory information.
    dir_status: DirBootstrapStatus,
    /// Current estimate of our clock skew.
    skew: Option<SkewEstimate>,
}

impl BootstrapStatus {
    /// Return a rough fraction (from 0.0 to 1.0) representing how far along
    /// the client's bootstrapping efforts are.
    ///
    /// 0 is defined as "just started"; 1 is defined as "ready to use."
    pub fn as_frac(&self) -> f32 {
        // Coefficients chosen arbitrarily.
        self.conn_status.frac() * 0.15 + self.dir_status.frac_at(SystemTime::now()) * 0.85
    }

    /// Return true if the status indicates that the client is ready for
    /// traffic.
    ///
    /// For the purposes of this function, the client is "ready for traffic" if,
    /// as far as we know, we can start acting on a new client request immediately.
    pub fn ready_for_traffic(&self) -> bool {
        let now = SystemTime::now();
        self.conn_status.usable() && self.dir_status.usable_at(now)
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
        if let Some(b) = self.conn_status.blockage() {
            let message = b.to_string().into();
            let kind = b.into();
            if matches!(kind, BlockageKind::ClockSkewed) && self.skew_is_noteworthy() {
                Some(Blockage {
                    kind,
                    message: format!("Clock is {}", self.skew.as_ref().expect("logic error"))
                        .into(),
                })
            } else {
                Some(Blockage { kind, message })
            }
        } else if let Some(b) = self.dir_status.blockage(SystemTime::now()) {
            let message = b.to_string().into();
            let kind = b.into();
            Some(Blockage { kind, message })
        } else {
            None
        }
    }

    /// Adjust this status based on new connection-status information.
    fn apply_conn_status(&mut self, status: ConnStatus) {
        self.conn_status = status;
    }

    /// Adjust this status based on new directory-status information.
    fn apply_dir_status(&mut self, status: DirBootstrapStatus) {
        self.dir_status = status;
    }

    /// Adjust this status based on new estimated clock skew information.
    fn apply_skew_estimate(&mut self, status: Option<SkewEstimate>) {
        self.skew = status;
    }

    /// Return true if our current clock skew estimate is considered noteworthy.
    fn skew_is_noteworthy(&self) -> bool {
        matches!(&self.skew, Some(s) if s.noteworthy())
    }
}

/// A reason why a client believes it is stuck.
#[derive(Clone, Debug, derive_more::Display)]
#[display("{} ({})", kind, message)]
pub struct Blockage {
    /// Why do we think we're blocked?
    kind: BlockageKind,
    /// A human-readable message about the blockage.
    message: Cow<'static, str>,
}

impl Blockage {
    /// Get a programmatic indication of the kind of blockage this is.
    pub fn kind(&self) -> BlockageKind {
        self.kind.clone()
    }

    /// Get a human-readable message about the blockage.
    pub fn message(&self) -> impl Display + '_ {
        &self.message
    }
}

/// A specific type of blockage that a client believes it is experiencing.
///
/// Used to distinguish among instances of [`Blockage`].
#[derive(Clone, Debug, derive_more::Display)]
#[non_exhaustive]
pub enum BlockageKind {
    /// There is some kind of problem with connecting to the network.
    #[display("We seem to be offline")]
    Offline,
    /// We can connect, but our connections seem to be filtered.
    #[display("Our internet connection seems filtered")]
    Filtering,
    /// We have some other kind of problem connecting to Tor
    #[display("Can't reach the Tor network")]
    CantReachTor,
    /// We believe our clock is set incorrectly, and that's preventing us from
    /// successfully with relays and/or from finding a directory that we trust.
    #[display("Clock is skewed.")]
    ClockSkewed,
    /// We've encountered some kind of problem downloading directory
    /// information, and it doesn't seem to be caused by any particular
    /// connection problem.
    #[display("Can't bootstrap a Tor directory.")]
    CantBootstrap,
}

impl From<ConnBlockage> for BlockageKind {
    fn from(b: ConnBlockage) -> BlockageKind {
        match b {
            ConnBlockage::NoTcp => BlockageKind::Offline,
            ConnBlockage::NoHandshake => BlockageKind::Filtering,
            ConnBlockage::CertsExpired => BlockageKind::ClockSkewed,
            _ => BlockageKind::CantReachTor,
        }
    }
}

impl From<DirBlockage> for BlockageKind {
    fn from(_: DirBlockage) -> Self {
        BlockageKind::CantBootstrap
    }
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
            write!(f, "Stuck at {}%: {}", percent, problem)?;
        } else {
            write!(
                f,
                "{}%: {}; {}",
                percent, &self.conn_status, &self.dir_status
            )?;
        }
        if let Some(skew) = &self.skew {
            if skew.noteworthy() {
                write!(f, ". Clock is {}", skew)?;
            }
        }
        Ok(())
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
    conn_status: ConnStatusEvents,
    dir_status: impl Stream<Item = DirBootstrapStatus> + Send + Unpin,
    skew_status: ClockSkewEvents,
) {
    /// Internal enumeration to combine incoming status changes.
    #[allow(clippy::large_enum_variant)]
    enum Event {
        /// A connection status change
        Conn(ConnStatus),
        /// A directory status change
        Dir(DirBootstrapStatus),
        /// A clock skew change
        Skew(Option<SkewEstimate>),
    }
    let mut stream = futures::stream::select_all(vec![
        conn_status.map(Event::Conn).boxed(),
        dir_status.map(Event::Dir).boxed(),
        skew_status.map(Event::Skew).boxed(),
    ]);

    while let Some(event) = stream.next().await {
        let mut b = sender.borrow_mut();
        match event {
            Event::Conn(e) => b.apply_conn_status(e),
            Event::Dir(e) => b.apply_dir_status(e),
            Event::Skew(e) => b.apply_skew_estimate(e),
        }
        debug!("{}", *b);
    }
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
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct BootstrapEvents {
    /// The receiver that implements this stream.
    #[educe(Debug(method = "skip_fmt"))]
    pub(crate) inner: postage::watch::Receiver<BootstrapStatus>,
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
