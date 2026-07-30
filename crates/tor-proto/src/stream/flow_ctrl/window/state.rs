//! Circuit reactor's stream window flow control.

use tor_cell::relaycell::flow_ctrl::{Xoff, Xon, XonKBpsEwma};
use tor_cell::relaycell::msg::{AnyRelayMsg, Sendme};
use tor_cell::relaycell::{RelayCmd, RelayMsg, UnparsedRelayMsg};

use crate::congestion::sendme::{
    self, StreamRecvWindow, StreamSendWindow, cmd_counts_towards_windows,
};
use crate::stream::flow_ctrl::state::{FlowCtrlHooks, HalfStreamFlowCtrlHooks};
use crate::stream::{RECV_WINDOW_INIT, STREAM_READER_BUFFER};
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

    fn maybe_send_xon(&mut self, _rate: XonKBpsEwma, _buffer_len: usize) -> Result<Option<Xon>> {
        let msg = "XON messages cannot be sent with window flow control";
        Err(Error::CircProto(msg.into()))
    }

    fn maybe_send_xoff(&mut self, _buffer_len: usize) -> Result<Option<Xoff>> {
        let msg = "XOFF messages cannot be sent with window flow control";
        Err(Error::CircProto(msg.into()))
    }

    fn inbound_queue_max_len(&self) -> usize {
        // SENDME-window flow control sets a maximum number of inflight DATA cells,
        // so there's an upper limit to the number of cells we typically expect on the stream
        STREAM_READER_BUFFER
    }
}

/// State for window-based flow control on a half-stream.
#[derive(Debug)]
pub(crate) struct HalfStreamWindowFlowCtrl {
    /// The original [`WindowFlowCtrl`] from the full stream.
    ///
    /// We keep this since we need to continue validating any incoming messages.
    inner: WindowFlowCtrl,
    /// The stream's receive window.
    ///
    /// When it was a full-stream, the receive window was tracked by the `DataStream`.
    /// But since the `DataStream` has gone away, we need to track it ourselves.
    recv_window: StreamRecvWindow,
}

impl HalfStreamWindowFlowCtrl {
    /// Returns a new sendme-window-based state for a half-stream.
    pub(crate) fn new(flow_ctrl: WindowFlowCtrl) -> Self {
        Self {
            inner: flow_ctrl,
            // FIXME(eta): we don't copy the receive window, instead just creating a new one,
            //             so a malicious peer can send us slightly more data than they should
            //             be able to; see arti#230.
            recv_window: StreamRecvWindow::new(RECV_WINDOW_INIT),
        }
    }
}

impl HalfStreamFlowCtrlHooks for HalfStreamWindowFlowCtrl {
    fn handle_incoming_dropped(&mut self, msg_count: u16) -> Result<()> {
        self.recv_window.decrement_n(msg_count)
    }

    fn handle_incoming_msg(&mut self, msg: UnparsedRelayMsg) -> Result<Option<UnparsedRelayMsg>> {
        match msg.cmd() {
            RelayCmd::SENDME => {
                self.inner.put_for_incoming_sendme(msg)?;
                Ok(None)
            }
            RelayCmd::XON => {
                self.inner.handle_incoming_xon(msg)?;
                Ok(None)
            }
            RelayCmd::XOFF => {
                self.inner.handle_incoming_xoff(msg)?;
                Ok(None)
            }
            cmd if cmd_counts_towards_windows(cmd) => {
                // Discard the returned bool since we aren't sending any more SENDMEs.
                let _ = self.recv_window.take()?;
                Ok(Some(msg))
            }
            // Nothing to do here.
            _ => Ok(Some(msg)),
        }
    }
}
