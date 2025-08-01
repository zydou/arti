//! Declare a type for streams that do hostname lookups

use crate::memquota::StreamAccount;
use crate::stream::StreamReceiver;
use crate::{Error, Result};

use futures::StreamExt;
use tor_cell::relaycell::msg::Resolved;
use tor_cell::relaycell::RelayCmd;
use tor_cell::restricted_msg;

use super::AnyCmdChecker;

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    /// The underlying RawCellStream.
    s: StreamReceiver,

    /// The memory quota account that should be used for this "stream"'s data
    ///
    /// Exists to keep the account alive
    _memquota: StreamAccount,
}

restricted_msg! {
    /// An allowable reply for a RESOLVE message.
    enum ResolveResponseMsg : RelayMsg {
        End,
        Resolved,
    }
}

impl ResolveStream {
    /// Wrap a RawCellStream into a ResolveStream.
    ///
    /// Call only after sending a RESOLVE cell.
    pub(crate) fn new(s: StreamReceiver, memquota: StreamAccount) -> Self {
        ResolveStream {
            s,
            _memquota: memquota,
        }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        use ResolveResponseMsg::*;
        let cell = match self.s.next().await {
            Some(cell) => cell?,
            None => return Err(Error::NotConnected),
        };
        let msg = match cell.decode::<ResolveResponseMsg>() {
            Ok(cell) => cell.into_msg(),
            Err(e) => {
                self.s.protocol_error();
                return Err(Error::from_bytes_err(e, "response on a resolve stream"));
            }
        };
        match msg {
            End(e) => Err(Error::EndReceived(e.reason())),
            Resolved(r) => Ok(r),
        }
    }
}

/// A `CmdChecker` that enforces correctness for incoming commands on an
/// outbound resolve stream.
#[derive(Debug, Default)]
pub(crate) struct ResolveCmdChecker {}

impl super::CmdChecker for ResolveCmdChecker {
    fn check_msg(
        &mut self,
        msg: &tor_cell::relaycell::UnparsedRelayMsg,
    ) -> Result<super::StreamStatus> {
        use super::StreamStatus::Closed;
        match msg.cmd() {
            RelayCmd::RESOLVED => Ok(Closed),
            RelayCmd::END => Ok(Closed),
            _ => Err(Error::StreamProto(format!(
                "Unexpected {} on resolve stream",
                msg.cmd()
            ))),
        }
    }

    fn consume_checked_msg(&mut self, msg: tor_cell::relaycell::UnparsedRelayMsg) -> Result<()> {
        let _ = msg
            .decode::<ResolveResponseMsg>()
            .map_err(|err| Error::from_bytes_err(err, "message on resolve stream."))?;
        Ok(())
    }
}

impl ResolveCmdChecker {
    /// Return a new boxed `DataCmdChecker` in a state suitable for a newly
    /// constructed connection.
    pub(crate) fn new_any() -> AnyCmdChecker {
        Box::<Self>::default()
    }
}
