use postage::watch;
use tor_cell::relaycell::flow_ctrl::XonKbpsEwma;

use super::reader::DrainRateRequest;

use crate::client::stream::flow_ctrl::state::StreamRateLimit;
use crate::util::notify::NotifySender;

// XXX: remove pub(crate) from fields
/// Control state for XON/XOFF flow control.
#[derive(Debug)]
pub(crate) struct XonXoffFlowCtrl {
    /// How we communicate rate limit updates to the
    /// [`DataWriter`](crate::client::stream::data::DataWriter).
    pub(crate) rate_limit_updater: watch::Sender<StreamRateLimit>,
    /// How we communicate requests for new drain rate updates to the
    /// [`XonXoffReader`](crate::client::stream::flow_ctrl::xon_xoff::reader::XonXoffReader).
    pub(crate) drain_rate_requester: NotifySender<DrainRateRequest>,
    /// The last rate limit we sent.
    pub(crate) last_sent_xon_xoff: Option<LastSentXonXoff>,
}

impl XonXoffFlowCtrl {
    /// Returns a new xon/xoff-based state.
    pub(crate) fn new(
        rate_limit_updater: watch::Sender<StreamRateLimit>,
        drain_rate_requester: NotifySender<DrainRateRequest>,
    ) -> Self {
        Self {
            rate_limit_updater,
            drain_rate_requester,
            last_sent_xon_xoff: None,
        }
    }
}

// XXX: remove pub(crate)
/// The last XON/XOFF message that we sent.
#[derive(Debug)]
pub(crate) enum LastSentXonXoff {
    /// XON message with a rate.
    // TODO: I'm expecting that we'll want the `XonKbpsEwma` in the future.
    // If that doesn't end up being the case, then we should remove it.
    #[expect(dead_code)]
    Xon(XonKbpsEwma),
    /// XOFF message.
    Xoff,
}
