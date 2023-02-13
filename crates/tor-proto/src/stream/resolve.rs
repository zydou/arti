//! Declare a type for streams that do hostname lookups

use crate::stream::StreamReader;
use crate::{Error, Result};
use tor_cell::relaycell::msg::Resolved;
use tor_cell::restricted_msg;

/// A ResolveStream represents a pending DNS request made with a RESOLVE
/// cell.
pub struct ResolveStream {
    /// The underlying RawCellStream.
    s: StreamReader,
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
    pub(crate) fn new(s: StreamReader) -> Self {
        ResolveStream { s }
    }

    /// Read a message from this stream telling us the answer to our
    /// name lookup request.
    pub async fn read_msg(&mut self) -> Result<Resolved> {
        use ResolveResponseMsg::*;
        let cell = self.s.recv().await?;
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
