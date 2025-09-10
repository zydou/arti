use crate::congestion::sendme::StreamSendWindow;

// XXX: remove pub(crate) from fields
#[derive(Debug)]
pub(crate) struct WindowFlowCtrl {
    pub(crate) window: StreamSendWindow,
}
