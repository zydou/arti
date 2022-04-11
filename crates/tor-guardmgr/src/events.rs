//! Code to remotely notify other crates about changes in the status of the
//! `GuardMgr`.

use std::{pin::Pin, task::Poll};

use crate::skew::SkewEstimate;
use educe::Educe;
use futures::{Stream, StreamExt};
use tor_basic_utils::skip_fmt;

/// A stream of [`SkewEstimate`] events.
///
/// Note that this stream can be lossy: if multiple events trigger before you
/// read from it, you will only get the most recent estimate.
//
// SEMVER NOTE: this type is re-exported from tor-circmgr.
#[derive(Clone, Educe)]
#[educe(Debug)]
pub struct ClockSkewEvents {
    /// The `postage::watch::Receiver` that we're wrapping.
    ///
    /// We wrap this type so that we don't expose its entire API, and so that we
    /// can migrate to some other implementation in the future if we want.
    #[educe(Debug(method = "skip_fmt"))]
    pub(crate) inner: postage::watch::Receiver<Option<SkewEstimate>>,
}

impl Stream for ClockSkewEvents {
    type Item = Option<SkewEstimate>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_unpin(cx)
    }
}
impl ClockSkewEvents {
    /// Return our best estimate of our current clock skew, based on reports from the
    /// guards and fallbacks we have contacted.
    pub fn get(&self) -> Option<SkewEstimate> {
        self.inner.borrow().clone()
    }
}
