//! A relay's view of the forward (away from the client, towards the exit) state of a circuit.

use crate::circuit::reactor::ControlHandler;
use crate::circuit::reactor::forward::{CellDecodeResult, ForwardHandler, ForwardSender};
use crate::circuit::reactor::hop_mgr::HopMgr;
use crate::crypto::cell::OutboundRelayLayer;
use crate::crypto::cell::RelayCellBody;
use crate::relay::RelayCircChanMsg;
use crate::util::err::ReactorError;
use crate::{Error, HopNum, Result};

// TODO(circpad): once padding is stabilized, the padding module will be moved out of client.
use crate::client::circuit::padding::QueuedCellPaddingInfo;

use tor_cell::chancell::msg::{AnyChanMsg, Destroy, PaddingNegotiate, Relay, RelayEarly};
use tor_cell::chancell::{AnyChanCell, BoxedCellBody, ChanMsg};
use tor_cell::relaycell::{RelayCellFormat, RelayCmd, UnparsedRelayMsg};
use tor_error::internal;
use tor_linkspec::OwnedChanTarget;
use tor_rtcompat::Runtime;

use futures::SinkExt as _;

use std::result::Result as StdResult;

/// Placeholder for our custom control message type.
type CtrlMsg = ();

/// Placeholder for our custom control command type.
type CtrlCmd = ();

/// Relay-specific state for the forward reactor.
pub(crate) struct Forward {
    /// The cryptographic state for this circuit for inbound cells.
    crypto_out: Box<dyn OutboundRelayLayer + Send>,
}

impl Forward {
    /// Create a new [`Forward`].
    pub(crate) fn new(crypto_out: Box<dyn OutboundRelayLayer + Send>) -> Self {
        Self { crypto_out }
    }

    /// Handle a DROP message.
    #[allow(clippy::unnecessary_wraps)] // Returns Err if circ-padding is enabled
    fn handle_drop(&mut self) -> StdResult<(), ReactorError> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "circ-padding")] {
                Err(internal!("relay circuit padding not yet supported").into())
            } else {
                Ok(())
            }
        }
    }

    /// Handle an EXTEND2 cell.
    #[allow(clippy::unused_async)] // TODO(relay)
    async fn handle_extend2(&mut self) -> StdResult<(), ReactorError> {
        todo!()
    }

    /// Handle a TRUNCATE cell.
    #[allow(clippy::unused_async)] // TODO(relay)
    async fn handle_truncate(&mut self) -> StdResult<(), ReactorError> {
        // TODO(relay): when we implement this, we should try to do better than C Tor:
        // if we have some cells queued for the next hop in the circuit,
        // we should try to flush them *before* tearing it down.
        //
        // See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3487#note_3296035
        todo!()
    }

    /// Handle a RELAY_EARLY cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_relay_early_cell(&mut self, _cell: RelayEarly) -> StdResult<(), ReactorError> {
        Err(internal!("RELAY_EARLY is not implemented").into())
    }

    /// Handle a DESTROY cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_destroy_cell(&mut self, _cell: Destroy) -> StdResult<(), ReactorError> {
        Err(internal!("DESTROY is not implemented").into())
    }

    /// Handle a PADDING_NEGOTIATE cell originating from the client.
    #[allow(clippy::needless_pass_by_value)] // TODO(relay)
    fn handle_padding_negotiate(&mut self, _cell: PaddingNegotiate) -> StdResult<(), ReactorError> {
        Err(internal!("PADDING_NEGOTIATE is not implemented").into())
    }
}

impl ForwardHandler for Forward {
    type BuildSpec = OwnedChanTarget;
    type CircChanMsg = RelayCircChanMsg;

    fn decode_relay_cell<R: Runtime>(
        &mut self,
        hop_mgr: &mut HopMgr<R>,
        cell: Relay,
    ) -> Result<(Option<HopNum>, CellDecodeResult)> {
        // Note: the client reactor will return the actual source hopnum
        let hopnum = None;
        let cmd = cell.cmd();
        let mut body = cell.into_relay_body().into();
        let Some(tag) = self.crypto_out.decrypt_outbound(cmd, &mut body) else {
            return Ok((hopnum, CellDecodeResult::Unrecognizd(body)));
        };

        // The message is addressed to us! Now it's time to handle it...
        let mut hops = hop_mgr.hops().write().expect("poisoned lock");
        let decode_res = hops
            .get_mut(hopnum)
            .ok_or_else(|| internal!("msg from non-existant hop???"))?
            .inbound
            .decode(body.into())?;

        Ok((hopnum, CellDecodeResult::Recognized(tag, decode_res)))
    }

    async fn handle_meta_msg(
        &mut self,
        _hopnum: Option<HopNum>,
        msg: UnparsedRelayMsg,
        _relay_cell_format: RelayCellFormat,
    ) -> StdResult<(), ReactorError> {
        match msg.cmd() {
            RelayCmd::DROP => self.handle_drop(),
            RelayCmd::EXTEND2 => self.handle_extend2().await,
            RelayCmd::TRUNCATE => self.handle_truncate().await,
            cmd => Err(internal!("relay cmd {cmd} not supported").into()),
        }
    }

    fn handle_unrecognized_cell(
        &mut self,
        forward: Option<&mut ForwardSender>,
        body: RelayCellBody,
        info: Option<QueuedCellPaddingInfo>,
    ) -> StdResult<(), ReactorError> {
        let Some(forward) = forward else {
            return Err(Error::CircProto(
                "Asked to forward cell, but there is no forward channel?!".into(),
            )
            .into());
        };

        let msg = Relay::from(BoxedCellBody::from(body));
        let relay = AnyChanMsg::Relay(msg);
        let cell = AnyChanCell::new(Some(forward.circ_id), relay);

        // Note: this future is always `Ready`, because we checked the sink for readiness
        // before polling the input channel, so await won't block.
        forward.outbound_chan_tx.start_send_unpin((cell, info))?;

        Ok(())
    }

    async fn handle_forward_cell(&mut self, cell: RelayCircChanMsg) -> StdResult<(), ReactorError> {
        use RelayCircChanMsg::*;

        match cell {
            Relay(_) => {
                Err(internal!("relay cell should've been handled in base reactor?!").into())
            }
            RelayEarly(r) => self.handle_relay_early_cell(r),
            Destroy(d) => self.handle_destroy_cell(d),
            PaddingNegotiate(p) => self.handle_padding_negotiate(p),
        }
    }
}

impl ControlHandler for Forward {
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
