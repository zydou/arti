use crate::congestion::sendme::StreamSendWindow;

// XXX: remove pub(crate) from fields
#[derive(Debug)]
pub(crate) struct WindowFlowCtrl {
    pub(crate) window: StreamSendWindow,
}

impl WindowFlowCtrl {
    /// Returns a new sendme-window-based state.
    // TODO: Maybe take the raw u16 and create StreamSendWindow ourselves?
    // Unclear whether we need or want to support creating this object from a
    // preexisting StreamSendWindow.
    pub(crate) fn new(window: StreamSendWindow) -> Self {
        Self { window }
    }
}
