//! Implementation of the Fixed Window congestion control algorithm.
//!
//! This is used by the circuit reactor in order to decide when to send data and SENDMEs.
//!
//! The vanilla flow control system of fixed window SENDMEs in the spec.

use crate::Result;

use super::{
    CongestionControlAlgorithm, CongestionSignals, CongestionWindow, State,
    params::{Algorithm, FixedWindowParams},
    rtt::RoundtripTimeEstimator,
    sendme::{self, WindowParams},
};

/// Fixed window algorithm which is essentially the SENDME v0 with fixed receive and send window
/// size.
#[derive(Clone, Debug)]
pub(crate) struct FixedWindow {
    /// Window used to say how many cells we can receive.
    recvwindow: sendme::CircRecvWindow,
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
    /// The params from the consensus.
    params: FixedWindowParams,
}

impl FixedWindow {
    /// Create a new `FixedWindow` form a given initial sendwindow size.
    ///
    /// Note: the initial recvwindow size is given by [`sendme::CircParams::start`].
    pub(crate) fn new(params: FixedWindowParams) -> Self {
        let initial_window = params.circ_window_start();
        Self {
            recvwindow: sendme::CircRecvWindow::new(sendme::CircParams::start()),
            sendwindow: sendme::CircSendWindow::new(initial_window),
            params,
        }
    }
}

impl CongestionControlAlgorithm for FixedWindow {
    fn uses_stream_sendme(&self) -> bool {
        true
    }

    fn uses_xon_xoff(&self) -> bool {
        false
    }

    fn is_next_cell_sendme(&self) -> bool {
        self.sendwindow.should_record_tag()
    }

    fn can_send(&self) -> bool {
        self.sendwindow.window() > 0
    }

    fn cwnd(&self) -> Option<CongestionWindow> {
        None
    }

    fn sendme_received(
        &mut self,
        _state: &mut State,
        _rtt: &mut RoundtripTimeEstimator,
        _signals: CongestionSignals,
    ) -> Result<()> {
        self.sendwindow.put()
    }

    fn sendme_sent(&mut self) -> Result<()> {
        self.recvwindow.put();
        Ok(())
    }

    fn data_received(&mut self) -> Result<bool> {
        self.recvwindow.take()
    }

    fn data_sent(&mut self) -> Result<()> {
        self.sendwindow.take()
    }

    #[cfg(feature = "conflux")]
    fn inflight(&self) -> Option<u32> {
        None
    }

    #[cfg(test)]
    fn send_window(&self) -> u32 {
        u32::from(self.sendwindow.window())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::FixedWindow(self.params)
    }
}
