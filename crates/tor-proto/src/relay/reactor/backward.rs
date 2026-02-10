//! A relay's view of the backward (towards the client) state of a circuit.

use crate::circuit::UniqId;
use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::backward::{BackwardCellDisposition, BackwardHandler};
use crate::crypto::cell::{InboundRelayLayer, RelayCellBody};
use crate::relay::RelayCircChanMsg;
use crate::util::err::ReactorError;
use crate::{Error, HopNum};

use tor_cell::chancell::msg::{AnyChanMsg, Relay};
use tor_cell::chancell::{BoxedCellBody, ChanCmd};
use tor_cell::relaycell::msg::SendmeTag;

use std::result::Result as StdResult;

use tracing::debug;

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

    fn handle_backward_cell(
        &mut self,
        circ_id: UniqId,
        cell: RelayCircChanMsg,
    ) -> StdResult<BackwardCellDisposition, ReactorError> {
        let disp = match cell {
            RelayCircChanMsg::Relay(c) => {
                let body = c.into_relay_body();

                let mut relay_body = body.into();
                self.crypto_in
                    .encrypt_inbound(ChanCmd::RELAY, &mut relay_body);

                let cell = AnyChanMsg::Relay(Relay::from(BoxedCellBody::from(relay_body)));

                BackwardCellDisposition::Forward(cell)
            }
            RelayCircChanMsg::RelayEarly(_) => {
                return Err(ReactorError::Err(Error::CircProto(
                    "Received inbound RELAY_EARLY cell".into(),
                )));
            }
            RelayCircChanMsg::Destroy(_) => {
                debug!(circ_id=%circ_id, "Received inbound DESTROY cell");
                return Err(ReactorError::Shutdown);
            }
            RelayCircChanMsg::PaddingNegotiate(_) => {
                return Err(ReactorError::Err(Error::CircProto(
                    "R2R PADDING_NEGOTIATE not supported".into(),
                )));
            }
        };

        Ok(disp)
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
