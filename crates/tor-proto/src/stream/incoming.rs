//! Incoming data stream cell handlers, shared by the relay and onion service implementations.

use tor_cell::relaycell::RelayCmd;
use tor_cell::restricted_msg;

use crate::stream::cmdcheck::{AnyCmdChecker, CmdChecker, StreamStatus};
use crate::{Error, Result};

/// A `CmdChecker` that enforces invariants for inbound data streams.
#[derive(Debug, Default)]
pub(crate) struct InboundDataCmdChecker;

restricted_msg! {
    /// An allowable incoming message on an incoming data stream.
    enum IncomingDataStreamMsg:RelayMsg {
        // SENDME is handled by the reactor.
        Data, End,
    }
}

impl CmdChecker for InboundDataCmdChecker {
    fn check_msg(&mut self, msg: &tor_cell::relaycell::UnparsedRelayMsg) -> Result<StreamStatus> {
        use StreamStatus::*;
        match msg.cmd() {
            RelayCmd::DATA => Ok(Open),
            RelayCmd::END => Ok(Closed),
            _ => Err(Error::StreamProto(format!(
                "Unexpected {} on an incoming data stream!",
                msg.cmd()
            ))),
        }
    }

    fn consume_checked_msg(&mut self, msg: tor_cell::relaycell::UnparsedRelayMsg) -> Result<()> {
        let _ = msg
            .decode::<IncomingDataStreamMsg>()
            .map_err(|err| Error::from_bytes_err(err, "cell on half-closed stream"))?;
        Ok(())
    }
}

impl InboundDataCmdChecker {
    /// Return a new boxed `DataCmdChecker` in a state suitable for a
    /// connection where an initial CONNECTED cell is not expected.
    ///
    /// This is used by hidden services, exit relays, and directory servers
    /// to accept streams.
    pub(crate) fn new_connected() -> AnyCmdChecker {
        Box::new(Self)
    }
}
