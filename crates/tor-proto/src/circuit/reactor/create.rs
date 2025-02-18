//! Helpers for handling CREATE* cells.

use crate::circuit::celltypes::CreateResponse;
use crate::{Error, Result};
use tor_cell::chancell;
use tor_cell::chancell::msg::{AnyChanMsg, HandshakeType};

/// An object that can put a given handshake into a ChanMsg for a CREATE*
/// cell, and unwrap a CREATED* cell.
pub(super) trait CreateHandshakeWrap {
    /// Construct an appropriate ChanMsg to hold this kind of handshake.
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg;
    /// Decode a ChanMsg to an appropriate handshake value, checking
    /// its type.
    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
pub(super) struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }

    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            CreatedFast(m) => Ok(m.into_handshake()),
            Destroy(_) => Err(Error::CircRefused(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircProto(format!(
                "Relay replied to CREATE_FAST with unexpected cell: {}",
                msg
            ))),
        }
    }
}

/// A CreateHandshakeWrap that generates CREATE2 and handles CREATED2
pub(super) struct Create2Wrap {
    /// The handshake type to put in the CREATE2 cell.
    pub(super) handshake_type: HandshakeType,
}

impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> AnyChanMsg {
        chancell::msg::Create2::new(self.handshake_type, bytes).into()
    }

    fn decode_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            Created2(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircRefused("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircProto(format!(
                "Relay replied to CREATE2 with unexpected cell {}",
                msg
            ))),
        }
    }
}
