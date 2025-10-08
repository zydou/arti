//! Circuit reactor's stream window flow control.

use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKbpsEwma};
use tor_cell::relaycell::msg::{AnyRelayMsg, Sendme};
use tor_cell::relaycell::{RelayMsg, UnparsedRelayMsg};

use crate::congestion::sendme::{self, StreamSendWindow};
use crate::stream::flow_ctrl::state::FlowCtrlHooks;
use crate::{Error, Result};

#[cfg(doc)]
use crate::stream::flow_ctrl::state::StreamFlowCtrl;

/// State for window-based flow control.
#[derive(Debug)]
pub(crate) struct WindowFlowCtrl {
    /// Send window.
    window: StreamSendWindow,
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

impl FlowCtrlHooks for WindowFlowCtrl {
    fn can_send<M: RelayMsg>(&self, msg: &M) -> bool {
        !sendme::cmd_counts_towards_windows(msg.cmd()) || self.window.window() > 0
    }

    fn about_to_send(&mut self, msg: &AnyRelayMsg) -> Result<()> {
        if sendme::cmd_counts_towards_windows(msg.cmd()) {
            self.window.take().map(|_| ())
        } else {
            // TODO: Maybe make this an error?
            // Ideally caller would have checked this already.
            Ok(())
        }
    }

    fn put_for_incoming_sendme(&mut self, msg: UnparsedRelayMsg) -> Result<()> {
        let _sendme = msg
            .decode::<Sendme>()
            .map_err(|e| Error::from_bytes_err(e, "failed to decode stream sendme message"))?
            .into_msg();

        self.window.put()
    }

    fn handle_incoming_xon(&mut self, _msg: UnparsedRelayMsg) -> Result<()> {
        let msg = "XON messages not allowed with window flow control";
        Err(Error::CircProto(msg.into()))
    }

    fn handle_incoming_xoff(&mut self, _msg: UnparsedRelayMsg) -> Result<()> {
        let msg = "XOFF messages not allowed with window flow control";
        Err(Error::CircProto(msg.into()))
    }

    fn maybe_send_xon(&mut self, _rate: XonKbpsEwma, _buffer_len: usize) -> Result<Option<Xon>> {
        let msg = "XON messages cannot be sent with window flow control";
        Err(Error::CircProto(msg.into()))
    }

    fn maybe_send_xoff(&mut self, _buffer_len: usize) -> Result<Option<Xoff>> {
        let msg = "XOFF messages cannot be sent with window flow control";
        Err(Error::CircProto(msg.into()))
    }
}
