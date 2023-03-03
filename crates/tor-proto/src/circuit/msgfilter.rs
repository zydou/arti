//! Declare a message filter, for use with
//! [`Circuit::send_control_message`](super::Circuit::send_control_message).
//!
//! Although this is similar to `stream::cmdcheck`, I am deliberately leaving
//! them separate. Conceivably they should be unified at some point down the
//! road?
use futures::channel::mpsc;
use tor_cell::relaycell::UnparsedRelayCell;

use crate::crypto::cell::HopNum;
use crate::Result;

use super::MetaCellDisposition;

/// An object that checks whether incoming control messages are acceptable on a
/// circuit.
///
/// The filter is supplied to
/// [`Circuit::end_control_message`](super::Circuit::send_control_message).  It
/// is used to check any incoming message whose stream ID is 0, and which would
/// otherwise not be accepted on a given circuit.

/// (The messages that `tor-proto` will handle on its own, and _not_ deliver, are
/// are DESTROY, DATA, SENDME, ...)  Ordinarily, any unexpected control
/// message will cause the circuit to exit with an error.
///
/// There can only be one stream of this type created on a given circuit at
/// a time. If a such a stream already exists, this method will return an
/// error.
///
/// The caller should be sure to close the circuit if a command that _it_
/// doesn't recognize shows up.
///
/// (This function is not yet implemented; right now, it will always panic.)
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(super) trait MsgFilter {
    /// Check whether this message is an acceptable one to receive in reply to
    /// our command.
    fn check_msg(&mut self, msg: &UnparsedRelayCell) -> Result<MetaCellDisposition>;
}

/// Wrapper for `MsgFilter` to implement `MetaCellHandler`
pub(super) struct UserMsgHandler<T> {
    /// From which hop to we expect to get messages?
    hop: HopNum,
    /// An unbounded sender that we use for reporting messages that match the
    /// filter.
    sender: mpsc::UnboundedSender<Result<UnparsedRelayCell>>,
    /// The filter itself.
    filter: T,
}

impl<T> UserMsgHandler<T> {
    /// Create a new UserMsgHandler to be the MetaCellHandler for a user request.
    pub(super) fn new(
        hop: HopNum,
        sender: mpsc::UnboundedSender<Result<UnparsedRelayCell>>,
        filter: T,
    ) -> Self {
        Self {
            hop,
            sender,
            filter,
        }
    }
}

impl<T: MsgFilter + Send> super::reactor::MetaCellHandler for UserMsgHandler<T> {
    fn expected_hop(&self) -> HopNum {
        self.hop
    }

    fn handle_msg(
        &mut self,
        msg: UnparsedRelayCell,
        _reactor: &mut super::reactor::Reactor,
    ) -> Result<MetaCellDisposition> {
        match self.filter.check_msg(&msg) {
            Ok(status) => match self.sender.unbounded_send(Ok(msg)) {
                Ok(_) => Ok(status),
                Err(_) => Ok(MetaCellDisposition::UninstallHandler),
            },
            Err(e) => {
                // (It's okay to ignore send errors here, since we are already
                // closing this circuit.)
                let _ignore = self.sender.unbounded_send(Err(e.clone()));
                Err(e)
            }
        }
    }
}
