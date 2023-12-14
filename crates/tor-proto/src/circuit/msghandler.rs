//! A message handler trait for use with
//! [`ClientCirc::start_conversation`](super::ClientCirc::start_conversation).
//!
//! Although this is similar to `stream::cmdcheck`, I am deliberately leaving
//! them separate. Conceivably they should be unified at some point down the
//! road?
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayMsg, UnparsedRelayCell};

use crate::crypto::cell::HopNum;
use crate::{Error, Result};

use std::task::Context;

use super::{ConversationInHandler, MetaCellDisposition};

/// An object that checks whether incoming control messages are acceptable on a
/// circuit, and delivers them to a client if so.
///
/// The handler is supplied to
/// [`ClientCirc::start_conversation`](super::ClientCirc::start_conversation).  It
/// is used to check any incoming message whose stream ID is 0, and which would
/// otherwise not be accepted on a given circuit.
///
/// (The messages that `tor-proto` will handle on its own, and _not_ deliver, are
/// are DESTROY, DATA, SENDME, ...)  Ordinarily, any unexpected control
/// message will cause the circuit to exit with an error.
pub trait MsgHandler {
    /// Check whether this message is an acceptable one to receive in reply to
    /// our command, and handle it if so.
    ///
    /// Typically, this handler should perform only simple checks, before
    /// delivering the message to another task via some kind of channel if
    /// further processing is needed.
    ///
    /// In particular,
    /// if the circuit might be in use for anything else
    /// (eg there might be concurrent data flow)
    /// the implementor should avoid any expensive computations
    /// or highly contended locks, to avoid blocking the circuit reactor.
    ///
    /// If this function returns an error, the circuit will be closed.
    fn handle_msg(
        &mut self,
        conversation: ConversationInHandler<'_, '_, '_>,
        msg: AnyRelayMsg,
    ) -> Result<MetaCellDisposition>;
}

/// Wrapper for `MsgHandler` to implement `MetaCellHandler`
pub(super) struct UserMsgHandler<T> {
    /// From which hop to we expect to get messages?
    hop: HopNum,
    /// The handler itself.
    handler: T,
}

impl<T> UserMsgHandler<T> {
    /// Create a new UserMsgHandler to be the MetaCellHandler for incoming
    /// control messages a given circuit.
    pub(super) fn new(hop: HopNum, handler: T) -> Self {
        Self { hop, handler }
    }
}

impl<T: MsgHandler + Send> super::reactor::MetaCellHandler for UserMsgHandler<T> {
    fn expected_hop(&self) -> HopNum {
        self.hop
    }

    fn handle_msg(
        &mut self,
        cx: &mut Context<'_>,
        msg: UnparsedRelayCell,
        reactor: &mut super::reactor::Reactor,
    ) -> Result<MetaCellDisposition> {
        let cell: AnyRelayMsgOuter = msg.decode().map_err(|err| Error::BytesErr {
            object: "cell for message handler",
            err,
        })?;
        let (stream_id, msg) = cell.into_streamid_and_msg();
        if stream_id.is_some() {
            return Err(Error::CircProto(format!(
                "Invalid message type {} received with stream ID",
                msg.cmd()
            )));
        }
        let conversation = ConversationInHandler {
            reactor,
            cx,
            hop_num: self.hop,
        };
        self.handler.handle_msg(conversation, msg)
    }
}
