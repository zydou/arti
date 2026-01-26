//! A relay's view of the backward (towards the client) state of a circuit.

use crate::HopNum;
use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::backward::BackwardHandler;
use crate::crypto::cell::{InboundRelayLayer, RelayCellBody};
use crate::relay::RelayCircChanMsg;
use crate::util::err::ReactorError;

use tor_cell::chancell::ChanCmd;
use tor_cell::relaycell::msg::SendmeTag;

use std::result::Result as StdResult;

/// Placeholder for our custom control message type.
type CtrlMsg = ();

/// Placeholder for our custom control command type.
type CtrlCmd = ();

/// Relay-specific state for the backward reactor.
pub(crate) struct Backward {
    /// The cryptographic state for this circuit for client-bound cells.
    crypto_in: Box<dyn InboundRelayLayer + Send>,
}

impl Backward {
    /// Create a new [`Backward`].
    pub(crate) fn new(crypto_in: Box<dyn InboundRelayLayer + Send>) -> Self {
        Self { crypto_in }
    }
}

impl BackwardHandler for Backward {
    type CircChanMsg = RelayCircChanMsg;

    fn encrypt_relay_cell(
        &mut self,
        cmd: ChanCmd,
        body: &mut RelayCellBody,
        hop: Option<HopNum>,
    ) -> SendmeTag {
        // TODO(DEDUP): the hop is used on the client side
        let _ = hop;
        self.crypto_in.originate(cmd, body)
    }
}

impl ControlHandler for Backward {
    type CtrlMsg = CtrlMsg;
    type CtrlCmd = CtrlCmd;

    fn handle_cmd(&mut self, cmd: Self::CtrlCmd) -> StdResult<(), ReactorError> {
        let () = cmd;
        Ok(())
    }

    fn handle_msg(&mut self, msg: Self::CtrlMsg) -> StdResult<(), ReactorError> {
        let () = msg;
        Ok(())
    }
}
