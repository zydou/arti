//! Declare a type for streams that do hostname lookups

use crate::stream::StreamReader;
use crate::{Error, Result};
use tor_cell::relaycell::msg::{AnyRelayMsg, Resolved};
use tor_cell::relaycell::RelayMsg;

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    /// The underlying RawCellStream.
    s: StreamReader,
}

impl ResolveStream {
    /// Wrap a RawCellStream into a ResolveStream.
    ///
    /// Call only after sending a RESOLVE cell.
    #[allow(dead_code)] // need to implement a caller for this.
    pub(crate) fn new(s: StreamReader) -> Self {
        ResolveStream { s }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        let cell = self.s.recv().await?;
        match cell {
            AnyRelayMsg::End(e) => Err(Error::EndReceived(e.reason())),
            AnyRelayMsg::Resolved(r) => Ok(r),
            m => {
                self.s.protocol_error();
                Err(Error::StreamProto(format!(
                    "Unexpected {} on resolve stream",
                    m.cmd()
                )))
            }
        }
    }
}
