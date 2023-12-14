//! Implementation for parsing and encoding relay cells

use std::num::NonZeroU16;

use crate::chancell::{BoxedCellBody, CELL_DATA_LEN};
use tor_bytes::{EncodeError, EncodeResult, Error, Result};
use tor_bytes::{Reader, Writer};
use tor_error::internal;

use caret::caret_int;
use rand::{CryptoRng, Rng};

pub mod extend;
#[cfg(feature = "hs")]
pub mod hs;
pub mod msg;
#[cfg(feature = "experimental-udp")]
pub mod udp;

caret_int! {
    /// A command that identifies the type of a relay cell
    pub struct RelayCmd(u8) {
        /// Start a new stream
        BEGIN = 1,
        /// Data on a stream
        DATA = 2,
        /// Close a stream
        END = 3,
        /// Acknowledge a BEGIN; stream is open
        CONNECTED = 4,
        /// Used for flow control
        SENDME = 5,
        /// Extend a circuit to a new hop; deprecated
        EXTEND = 6,
        /// Reply to EXTEND handshake; deprecated
        EXTENDED = 7,
        /// Partially close a circuit
        TRUNCATE = 8,
        /// Circuit has been partially closed
        TRUNCATED = 9,
        /// Padding cell
        DROP = 10,
        /// Start a DNS lookup
        RESOLVE = 11,
        /// Reply to a DNS lookup
        RESOLVED = 12,
        /// Start a directory stream
        BEGIN_DIR = 13,
        /// Extend a circuit to a new hop
        EXTEND2 = 14,
        /// Reply to an EXTEND2 cell.
        EXTENDED2 = 15,

        /// NOTE: UDP command are reserved but only used with experimental-udp feature

        /// UDP: Start of a stream
        CONNECT_UDP = 16,
        /// UDP: Acknowledge a CONNECT_UDP. Stream is open.
        CONNECTED_UDP = 17,
        /// UDP: Data on a UDP stream.
        DATAGRAM = 18,

        /// HS: establish an introduction point.
        ESTABLISH_INTRO = 32,
        /// HS: establish a rendezvous point.
        ESTABLISH_RENDEZVOUS = 33,
        /// HS: send introduction (client to introduction point)
        INTRODUCE1 = 34,
        /// HS: send introduction (introduction point to service)
        INTRODUCE2 = 35,
        /// HS: connect rendezvous point (service to rendezvous point)
        RENDEZVOUS1 = 36,
        /// HS: connect rendezvous point (rendezvous point to client)
        RENDEZVOUS2 = 37,
        /// HS: Response to ESTABLISH_INTRO
        INTRO_ESTABLISHED = 38,
        /// HS: Response to ESTABLISH_RENDEZVOUS
        RENDEZVOUS_ESTABLISHED = 39,
        /// HS: Response to INTRODUCE1 from introduction point to client
        INTRODUCE_ACK = 40,

        /// Padding: declare what kind of padding we want
        PADDING_NEGOTIATE = 41,
        /// Padding: reply to a PADDING_NEGOTIATE
        PADDING_NEGOTIATED = 42,
    }
}

/// Possible requirements on stream IDs for a relay command.
enum StreamIdReq {
    /// Can only be used with a stream ID of 0
    WantNone,
    /// Can only be used with a stream ID that isn't 0
    WantSome,
    /// Can be used with any stream ID
    Any,
}

impl RelayCmd {
    /// Check whether this command requires a certain kind of
    /// StreamId, and return a corresponding StreamIdReq.
    fn expects_streamid(self) -> StreamIdReq {
        match self {
            RelayCmd::BEGIN
            | RelayCmd::DATA
            | RelayCmd::END
            | RelayCmd::CONNECTED
            | RelayCmd::RESOLVE
            | RelayCmd::RESOLVED
            | RelayCmd::BEGIN_DIR => StreamIdReq::WantSome,
            #[cfg(feature = "experimental-udp")]
            RelayCmd::CONNECT_UDP | RelayCmd::CONNECTED_UDP | RelayCmd::DATAGRAM => {
                StreamIdReq::WantSome
            }
            RelayCmd::EXTEND
            | RelayCmd::EXTENDED
            | RelayCmd::TRUNCATE
            | RelayCmd::TRUNCATED
            | RelayCmd::DROP
            | RelayCmd::EXTEND2
            | RelayCmd::EXTENDED2
            | RelayCmd::ESTABLISH_INTRO
            | RelayCmd::ESTABLISH_RENDEZVOUS
            | RelayCmd::INTRODUCE1
            | RelayCmd::INTRODUCE2
            | RelayCmd::RENDEZVOUS1
            | RelayCmd::RENDEZVOUS2
            | RelayCmd::INTRO_ESTABLISHED
            | RelayCmd::RENDEZVOUS_ESTABLISHED
            | RelayCmd::INTRODUCE_ACK => StreamIdReq::WantNone,
            RelayCmd::SENDME => StreamIdReq::Any,
            _ => StreamIdReq::Any,
        }
    }
    /// Return true if this command is one that accepts the particular
    /// stream ID `id`
    pub fn accepts_streamid_val(self, id: Option<StreamId>) -> bool {
        match self.expects_streamid() {
            StreamIdReq::WantNone => id.is_none(),
            StreamIdReq::WantSome => id.is_some(),
            StreamIdReq::Any => true,
        }
    }
}

/// Identify a single stream on a circuit.
///
/// These identifiers are local to each hop on a circuit.
/// This can't be zero; if you need something that can be zero in the protocol,
/// use `Option<StreamId>`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct StreamId(NonZeroU16);

impl From<NonZeroU16> for StreamId {
    fn from(id: NonZeroU16) -> Self {
        Self(id)
    }
}

impl From<StreamId> for NonZeroU16 {
    fn from(id: StreamId) -> NonZeroU16 {
        id.0
    }
}

impl From<StreamId> for u16 {
    fn from(id: StreamId) -> u16 {
        id.0.get()
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl StreamId {
    /// Creates a `StreamId` for non-zero `stream_id`.
    ///
    /// Returns `None` when `stream_id` is zero. Messages with a zero/None stream ID
    /// apply to the circuit as a whole instead of a particular stream.
    pub fn new(stream_id: u16) -> Option<Self> {
        NonZeroU16::new(stream_id).map(Self)
    }

    /// Convenience function to convert to a `u16`; `None` is mapped to 0.
    pub fn get_or_zero(stream_id: Option<Self>) -> u16 {
        match stream_id {
            Some(stream_id) => stream_id.0.get(),
            None => 0,
        }
    }
}

/// A relay cell that has not yet been fully parsed, but where we have access to
/// the command and stream ID, for dispatching purposes.
//
// TODO prop340: Further discussion is necessary about standarizing names for
// all of the pieces of our cells.
#[derive(Clone, Debug)]
pub struct UnparsedRelayCell {
    /// The body of the cell.
    body: BoxedCellBody,
    // NOTE: we could also have a separate command and stream ID field here, but
    // we expect to be working with a TON of these, so we will be mildly
    // over-optimized and just peek into the body.
    //
    // It *is* a bit ugly to have to encode so much knowledge about the format in
    // different functions here, but that information shouldn't leak out of this module.
}
/// Position of the stream ID within the cell body.
const STREAM_ID_OFFSET: usize = 3;

impl UnparsedRelayCell {
    /// Wrap a BoxedCellBody as an UnparsedRelayCell.
    pub fn from_body(body: BoxedCellBody) -> Self {
        Self { body }
    }
    /// Return the command for this cell.
    pub fn cmd(&self) -> RelayCmd {
        /// Position of the command within the cell body.
        const CMD_OFFSET: usize = 0;
        self.body[CMD_OFFSET].into()
    }
    /// Return the stream ID for the stream that this cell corresponds to, if any.
    pub fn stream_id(&self) -> Option<StreamId> {
        StreamId::new(u16::from_be_bytes(
            self.body[STREAM_ID_OFFSET..STREAM_ID_OFFSET + 2]
                .try_into()
                .expect("two-byte slice was not two bytes long!?"),
        ))
    }
    /// Decode this unparsed cell into a given cell type.
    pub fn decode<M: RelayMsg>(self) -> Result<RelayMsgOuter<M>> {
        RelayMsgOuter::decode(self.body)
    }
}

/// A decoded and parsed relay message of unrestricted type,
/// with an accompanying optional Stream ID.
pub type AnyRelayMsgOuter = RelayMsgOuter<msg::AnyRelayMsg>;

/// Trait implemented by anything that can serve as a relay message.
///
/// Typically, this will be [`RelayMsg`] (to represent an unrestricted relay
/// message), or a restricted subset of `RelayMsg`.
pub trait RelayMsg {
    /// Return the stream command associated with this message.
    fn cmd(&self) -> RelayCmd;
    /// Encode the body of this message, not including command or length
    fn encode_onto<W: tor_bytes::Writer + ?Sized>(self, w: &mut W) -> tor_bytes::EncodeResult<()>;
    /// Extract the body of a message with command `cmd` from reader `r`.
    fn decode_from_reader(cmd: RelayCmd, r: &mut Reader<'_>) -> Result<Self>
    where
        Self: Sized;
}

/// A decoded and parsed relay message, along with an optional Stream ID.
///
/// This type represents a message that can be sent along a
/// circuit, along with the ID for an associated stream that the
/// message is meant for.
///
/// NOTE: This name is a placeholder; we intend to replace it once we have
/// standardized our vocabulary in this area.
#[derive(Debug)]
pub struct RelayMsgOuter<M> {
    /// The stream ID for the stream that this cell corresponds to.
    streamid: Option<StreamId>,
    /// The relay message for this cell.
    msg: M,
}

impl<M: RelayMsg> RelayMsgOuter<M> {
    /// Construct a new relay cell.
    pub fn new(streamid: Option<StreamId>, msg: M) -> Self {
        RelayMsgOuter { streamid, msg }
    }
    /// Consume this cell and return its components.
    pub fn into_streamid_and_msg(self) -> (Option<StreamId>, M) {
        (self.streamid, self.msg)
    }
    /// Return the command for this cell.
    pub fn cmd(&self) -> RelayCmd {
        self.msg.cmd()
    }
    /// Return the stream ID for the stream that this cell corresponds to.
    pub fn stream_id(&self) -> Option<StreamId> {
        self.streamid
    }
    /// Return the underlying message for this cell.
    pub fn msg(&self) -> &M {
        &self.msg
    }
    /// Consume this cell and return the underlying message.
    pub fn into_msg(self) -> M {
        self.msg
    }
    /// Consume this relay message and encode it as a 509-byte padded cell
    /// body.
    pub fn encode<R: Rng + CryptoRng>(self, rng: &mut R) -> crate::Result<BoxedCellBody> {
        /// We skip this much space before adding any random padding to the
        /// end of the cell
        const MIN_SPACE_BEFORE_PADDING: usize = 4;

        let (mut body, enc_len) = self.encode_to_cell()?;
        debug_assert!(enc_len <= CELL_DATA_LEN);
        if enc_len < CELL_DATA_LEN - MIN_SPACE_BEFORE_PADDING {
            rng.fill_bytes(&mut body[enc_len + MIN_SPACE_BEFORE_PADDING..]);
        }

        Ok(body)
    }

    /// Consume a relay cell and return its contents, encoded for use
    /// in a RELAY or RELAY_EARLY cell.
    fn encode_to_cell(self) -> EncodeResult<(BoxedCellBody, usize)> {
        // NOTE: This implementation is a bit optimized, since it happens to
        // literally every relay cell that we produce.

        // TODO -NM: Add a specialized implementation for making a DATA cell from
        // a body?

        /// Wrap a BoxedCellBody and implement AsMut<[u8]>
        struct BodyWrapper(BoxedCellBody);
        impl AsMut<[u8]> for BodyWrapper {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }
        /// The position of the length field within a relay cell.
        const LEN_POS: usize = 9;
        /// The position of the body a relay cell.
        const BODY_POS: usize = 11;

        let body = BodyWrapper(Box::new([0_u8; 509]));

        let mut w = crate::slicewriter::SliceWriter::new(body);
        w.write_u8(self.msg.cmd().into());
        w.write_u16(0); // "Recognized"
        debug_assert_eq!(
            w.offset().expect("Overflowed a cell with just the header!"),
            STREAM_ID_OFFSET
        );
        w.write_u16(StreamId::get_or_zero(self.streamid));
        w.write_u32(0); // Digest
                        // (It would be simpler to use NestedWriter at this point, but it uses an internal Vec that we are trying to avoid.)
        debug_assert_eq!(
            w.offset().expect("Overflowed a cell with just the header!"),
            LEN_POS
        );
        w.write_u16(0); // Length.
        debug_assert_eq!(
            w.offset().expect("Overflowed a cell with just the header!"),
            BODY_POS
        );
        self.msg.encode_onto(&mut w)?; // body
        let (mut body, written) = w.try_unwrap().map_err(|_| {
            EncodeError::Bug(internal!(
                "Encoding of relay message was too long to fit into a cell!"
            ))
        })?;
        let payload_len = written - BODY_POS;
        debug_assert!(payload_len < std::u16::MAX as usize);
        *(<&mut [u8; 2]>::try_from(&mut body.0[LEN_POS..LEN_POS + 2])
            .expect("Two-byte slice was not two bytes long!?")) =
            (payload_len as u16).to_be_bytes();
        Ok((body.0, written))
    }

    /// Parse a RELAY or RELAY_EARLY cell body into a RelayMsgOuter.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    #[allow(clippy::needless_pass_by_value)] // TODO this will go away soon.
    pub fn decode(body: BoxedCellBody) -> Result<Self> {
        let mut reader = Reader::from_slice(body.as_ref());
        Self::decode_from_reader(&mut reader)
    }
    /// Parse a RELAY or RELAY_EARLY cell body into a RelayMsgOuter from a reader.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cmd = r.take_u8()?.into();
        r.advance(2)?; // "recognized"
        let streamid = StreamId::new(r.take_u16()?);
        r.advance(4)?; // digest
        let len = r.take_u16()? as usize;
        if r.remaining() < len {
            return Err(Error::InvalidMessage(
                "Insufficient data in relay cell".into(),
            ));
        }
        r.truncate(len);
        let msg = M::decode_from_reader(cmd, r)?;
        Ok(Self { streamid, msg })
    }
}
