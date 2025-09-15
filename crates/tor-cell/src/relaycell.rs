//! Implementation for parsing and encoding relay cells

use std::num::NonZeroU16;

use crate::chancell::{BoxedCellBody, CELL_DATA_LEN};
use derive_deftly::Deftly;
use smallvec::{SmallVec, smallvec};
use tor_bytes::{EncodeError, EncodeResult, Error, Result};
use tor_bytes::{Reader, Writer};
use tor_error::internal;
use tor_memquota::derive_deftly_template_HasMemoryCost;

use caret::caret_int;
use rand::{CryptoRng, Rng};

#[cfg(feature = "conflux")]
pub mod conflux;
pub mod extend;
mod extlist;
pub mod flow_ctrl;
#[cfg(feature = "hs")]
pub mod hs;
pub mod msg;
#[cfg(feature = "experimental-udp")]
pub mod udp;

caret_int! {
    /// A command that identifies the type of a relay cell
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
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

        /// CONFLUX: Link circuits together at the receiving endpoint.
        CONFLUX_LINK = 19,
        /// CONFLUX: Confirm that the circuits were linked.
        CONFLUX_LINKED = 20,
        /// CONFLUX: Acknowledge the linkage of the circuits, for RTT measurement.
        CONFLUX_LINKED_ACK = 21,
        /// CONFLUX: Switch to another leg in an already linked circuit construction.
        CONFLUX_SWITCH = 22,

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

        /// Flow control: rate update (transmit off)
        XOFF = 43,
        /// Flow control: rate update (transmit on with rate limit)
        XON = 44,
    }
}

/// Possible requirements on stream IDs for a relay command.
enum StreamIdReq {
    /// Can only be used with a stream ID of 0
    WantNone,
    /// Can only be used with a stream ID that isn't 0
    WantSome,
    /// Can be used with any stream ID.
    ///
    /// This result is impossible with `RelayCellFormat::V1`.
    Any,
    /// Unrecognized; might be used with a stream ID or without.
    Unrecognized,
}

impl RelayCmd {
    /// Check whether this command requires a certain kind of
    /// StreamId in the provided `format`, and return a corresponding StreamIdReq.
    ///
    /// If `format` is None, return a result that is correct for _any_ version.
    fn expects_streamid(self, format: Option<RelayCellFormat>) -> StreamIdReq {
        match self {
            RelayCmd::BEGIN
            | RelayCmd::DATA
            | RelayCmd::END
            | RelayCmd::CONNECTED
            | RelayCmd::RESOLVE
            | RelayCmd::RESOLVED
            | RelayCmd::BEGIN_DIR
            | RelayCmd::XOFF
            | RelayCmd::XON => StreamIdReq::WantSome,
            // NOTE: Even when a RelayCmd is not implemented (like these UDP-based commands),
            // we need to implement expects_streamid() unconditionally.
            // Otherwise we leak more information than necessary
            // when parsing RelayCellFormat::V1 cells.
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
            | RelayCmd::CONFLUX_LINK
            | RelayCmd::CONFLUX_LINKED
            | RelayCmd::CONFLUX_LINKED_ACK
            | RelayCmd::CONFLUX_SWITCH
            | RelayCmd::ESTABLISH_INTRO
            | RelayCmd::ESTABLISH_RENDEZVOUS
            | RelayCmd::INTRODUCE1
            | RelayCmd::INTRODUCE2
            | RelayCmd::RENDEZVOUS1
            | RelayCmd::RENDEZVOUS2
            | RelayCmd::INTRO_ESTABLISHED
            | RelayCmd::RENDEZVOUS_ESTABLISHED
            | RelayCmd::INTRODUCE_ACK => StreamIdReq::WantNone,
            RelayCmd::SENDME => match format {
                // There are no stream-level SENDMES in V1, since CC is mandatory.
                // Further, the 'Any' result is not possible with V1, since
                // we need be able to decide whether a stream ID is present
                // from the value of the command.
                Some(RelayCellFormat::V1) => StreamIdReq::WantNone,
                // In V0, CC is not mandatory, so stream-level SENDMES are possible.
                Some(RelayCellFormat::V0) => StreamIdReq::Any,
                // When we're checking for general compatibility, we need to allow V0 or V1.
                None => StreamIdReq::Any,
            },
            _ => StreamIdReq::Unrecognized,
        }
    }
    /// Return true if this command is one that accepts the particular
    /// stream ID `id`.
    ///
    /// Note that this method does not consider the [`RelayCellFormat`] in use:
    /// it will return "true" for _any_ stream ID if the command is `SENDME`,
    /// and if the command is unrecognized.
    pub fn accepts_streamid_val(self, id: Option<StreamId>) -> bool {
        match self.expects_streamid(None) {
            StreamIdReq::WantNone => id.is_none(),
            StreamIdReq::WantSome => id.is_some(),
            StreamIdReq::Any => true,
            StreamIdReq::Unrecognized => true,
        }
    }
}

/// Identify a single stream on a circuit.
///
/// These identifiers are local to each hop on a circuit.
/// This can't be zero; if you need something that can be zero in the protocol,
/// use `Option<StreamId>`.
#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Debug, Hash, Deftly)]
#[derive_deftly(HasMemoryCost)]
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

/// Specifies which encoding version of RelayCell to use.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub enum RelayCellFormat {
    /// This is the "legacy" pre-prop340 format. No packing or fragmentation.
    V0,
    /// A "transitional" format for use with Counter Galois Onion encryption.
    ///
    /// It provides a 16-byte tag field, and a simplified layout for the rest of
    /// the cell.
    V1,
}

/// Internal decoder state.
#[derive(Clone, Debug)]
enum RelayCellDecoderInternal {
    /// Internal state for `RelayCellFormat::V0`
    V0,
    /// Internal state for `RelayCellFormat::V1`
    V1,
}

// TODO prop340: We should also fuzz RelayCellDecoder, but not in this fuzzer.

/// Decodes a stream of relay cell bodies into `UnparsedRelayMsg`s.
#[derive(Clone, Debug)]
pub struct RelayCellDecoder {
    /// Internal representation.
    internal: RelayCellDecoderInternal,
}

impl RelayCellDecoder {
    /// Returns a new `Decoder`, handling a stream of relay cells
    /// of the given `version`.
    pub fn new(version: RelayCellFormat) -> Self {
        match version {
            RelayCellFormat::V0 => Self {
                internal: RelayCellDecoderInternal::V0,
            },
            RelayCellFormat::V1 => Self {
                internal: RelayCellDecoderInternal::V1,
            },
        }
    }
    /// Parse a RELAY or RELAY_EARLY cell body.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    pub fn decode(&mut self, cell: BoxedCellBody) -> Result<RelayCellDecoderResult> {
        let msg_internal = match &self.internal {
            RelayCellDecoderInternal::V0 => UnparsedRelayMsgInternal::V0(cell),
            RelayCellDecoderInternal::V1 => UnparsedRelayMsgInternal::V1(cell),
        };
        Ok(RelayCellDecoderResult {
            msgs: smallvec![UnparsedRelayMsg {
                internal: msg_internal
            }],
            incomplete: None,
        })
    }
    /// Returns the `IncompleteRelayMsgInfo` describing the partial
    /// (fragmented) relay message at the end of the so-far-processed relay cell
    /// stream.
    pub fn incomplete_info(&self) -> Option<IncompleteRelayMsgInfo> {
        match &self.internal {
            // V0 and V1 don't support fragmentation, so there is never a pending fragment.
            RelayCellDecoderInternal::V0 | RelayCellDecoderInternal::V1 => None,
        }
    }
}

/// Result of calling `RelayCellDecoder::decode`.
#[derive(Debug)]
pub struct RelayCellDecoderResult {
    /// Complete messages obtained by decoding the cell. i.e. messages
    /// that were completely contained within the cell, or for which the cell
    /// contained the final fragment.
    msgs: SmallVec<[UnparsedRelayMsg; 1]>,
    /// Description of the partial message at the end of the cell, if any.
    incomplete: Option<IncompleteRelayMsgInfo>,
}

impl RelayCellDecoderResult {
    /// Returns a non-empty iterator over commands in relay messages that the
    /// cell producing this result contained *any* part of. i.e. this includes
    /// the command of "head", "middle", and/or "tail" message fragments that
    /// were in the cell.
    pub fn cmds(&self) -> impl Iterator<Item = RelayCmd> + '_ {
        let complete_msg_cmds = self.msgs.iter().map(|m| m.cmd());
        let partial_msg_cmd = self.incomplete.as_ref().map(|c| c.cmd());
        complete_msg_cmds.chain(partial_msg_cmd)
    }
    /// Converts `self` to an iterator over the complete messages, and metadata
    /// about the trailing incomplete message (as for `Self::incomplete_info`),
    /// if any.
    pub fn into_parts(
        self,
    ) -> (
        impl Iterator<Item = UnparsedRelayMsg>,
        Option<IncompleteRelayMsgInfo>,
    ) {
        (self.msgs.into_iter(), self.incomplete)
    }
    /// Returns the `IncompleteRelayMsgInfo` describing the incomplete
    /// relay message that this cell contained a fragment of, if any.
    ///
    /// Note that:
    /// * This does not describe a fragment that includes the end of the relay
    ///   message, since the message is then complete.
    /// * This *does* include a fragment that continues, but does not complete,
    ///   a message started in an earlier relay cell.
    /// * There is at most one such incomplete relay message, since no current
    ///   relay cell format supports starting a new message before completing the
    ///   previous one.
    pub fn incomplete_info(&self) -> Option<IncompleteRelayMsgInfo> {
        self.incomplete.clone()
    }

    /// Return true if this consists of nothing but padding.
    pub fn is_padding(&self) -> bool {
        // If all the messages we have are padding...
        self.msgs.iter().all(|m| m.cmd() == RelayCmd::DROP) &&
            // ... and any pending incomplete message is either absent or is padding...
            self.incomplete
                .as_ref()
                .is_none_or(|incomplete| incomplete.cmd() == RelayCmd::DROP)
        // ... then this is padding.
    }
}

/// Information about a relay message for which we don't yet have the complete body.
#[derive(Clone, Debug)]
pub struct IncompleteRelayMsgInfo {
    /// The message's command.
    cmd: RelayCmd,
    /// The message's stream ID, if any.
    stream_id: Option<StreamId>,
    /// The total number of bytes in the body of the message.
    total_msg_len: usize,
    /// The number of bytes of the body of the message that we've decoded so
    /// far.
    num_bytes_present: usize,
}

impl IncompleteRelayMsgInfo {
    /// Returns the message's command.
    pub fn cmd(&self) -> RelayCmd {
        self.cmd
    }
    /// Returns the message's `StreamId`, if any.
    pub fn stream_id(&self) -> Option<StreamId> {
        self.stream_id
    }
    /// Returns the total size of the complete message body.
    pub fn total_msg_len(&self) -> usize {
        self.total_msg_len
    }
    /// Returns the number of bytes of the message body that we have so far.
    pub fn num_bytes_present(&self) -> usize {
        self.num_bytes_present
    }
    /// Returns the number of bytes of the message body that we still need.
    pub fn num_bytes_missing(&self) -> usize {
        self.total_msg_len - self.num_bytes_present
    }
}

/// Internal representation of an `UnparsedRelayMsg`.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
enum UnparsedRelayMsgInternal {
    /// For `RelayCellFormat::V0` we can avoid copying data around by just
    /// storing the original cell body here.
    // NOTE: we could also have a separate command and stream ID field here, but
    // we expect to be working with a TON of these, so we will be mildly
    // over-optimized and just peek into the body.
    //
    // It *is* a bit ugly to have to encode so much knowledge about the format in
    // different functions here, but that information shouldn't leak out of this module.
    V0(BoxedCellBody),

    /// For `V1` we can also avoid copies, since there is still exactly one
    /// relay message per cell.
    V1(BoxedCellBody),
}

/// An enveloped relay message that has not yet been fully parsed, but where we
/// have access to the command, stream ID, and payload data length for dispatching
/// and congestion control purposes.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct UnparsedRelayMsg {
    /// The internal representation.
    internal: UnparsedRelayMsgInternal,
}

/// Const helper to find the min between three u16 values.
const fn min(a: u16, b: u16, c: u16) -> u16 {
    const fn min_2(a: u16, b: u16) -> u16 {
        if a < b { a } else { b }
    }
    min_2(a, min_2(b, c))
}

/// Const helper to find the max between three u16 values.
const fn max(a: u16, b: u16, c: u16) -> u16 {
    const fn max_2(a: u16, b: u16) -> u16 {
        if a > b { a } else { b }
    }
    max_2(a, max_2(b, c))
}

/// Position of the stream ID within the V0 cell body.
const STREAM_ID_OFFSET_V0: usize = 3;

/// Position of the stream ID within the V1 cell body, if it is present.
const STREAM_ID_OFFSET_V1: usize = 16 + 1 + 2; // tag, command, length.

/// Position of the payload data length within the V0 cell body.
const LENGTH_OFFSET_V0: usize = 1 + 2 + 2 + 4; // command, recognized, stream_id, digest.

/// Position of the payload data length within the V1 cell body.
const LENGTH_OFFSET_V1: usize = 16 + 1; // tag, command.

/// Position of the payload data within the V0 cell body.
const PAYLOAD_OFFSET_V0: usize = LENGTH_OFFSET_V0 + 2; // (everything before length), length.

/// Position of the payload data within the V1 cell body, when not including a stream ID.
const PAYLOAD_OFFSET_V1_WITHOUT_STREAM_ID: usize = LENGTH_OFFSET_V1 + 2; // (everything before length), length.

/// Position of the payload data within the V1 cell body, when including a stream ID.
const PAYLOAD_OFFSET_V1_WITH_STREAM_ID: usize = LENGTH_OFFSET_V1 + 2 + 2; // (everything before length), length, stream_id.

/// Max amount of payload data that can be stored in a V0 cell body.
const PAYLOAD_MAX_SIZE_V0: u16 = BODY_MAX_LEN_V0 - (PAYLOAD_OFFSET_V0 as u16);

/// Max amount of payload data that can be stored in a V1 cell body, when not including a stream ID.
const PAYLOAD_MAX_SIZE_V1_WITHOUT_STREAM_ID: u16 =
    BODY_MAX_LEN_V1 - (PAYLOAD_OFFSET_V1_WITHOUT_STREAM_ID as u16);

/// Max amount of payload data that can be stored in a V1 cell body, when including a stream ID.
const PAYLOAD_MAX_SIZE_V1_WITH_STREAM_ID: u16 =
    BODY_MAX_LEN_V1 - (PAYLOAD_OFFSET_V1_WITH_STREAM_ID as u16);

/// The maximum length of a V0 cell message body.
const BODY_MAX_LEN_V0: u16 = 509;

/// The maximum length of a V1 cell message body.
const BODY_MAX_LEN_V1: u16 = 509;

/// The maximum amount of payload data that can fit within all cell body types.
pub const PAYLOAD_MAX_SIZE_ALL: u16 = min(
    PAYLOAD_MAX_SIZE_V0,
    PAYLOAD_MAX_SIZE_V1_WITH_STREAM_ID,
    PAYLOAD_MAX_SIZE_V1_WITHOUT_STREAM_ID,
);

/// The maximum amount of payload data that can fit within any cell body type.
pub const PAYLOAD_MAX_SIZE_ANY: u16 = max(
    PAYLOAD_MAX_SIZE_V0,
    PAYLOAD_MAX_SIZE_V1_WITH_STREAM_ID,
    PAYLOAD_MAX_SIZE_V1_WITHOUT_STREAM_ID,
);

impl UnparsedRelayMsg {
    /// Wrap a BoxedCellBody as an UnparsedRelayMsg.
    ///
    /// Fails if the body doesn't correspond to exactly one relay message, but
    /// doesn't parse the message itself.
    ///
    /// Non-test code should generally use `RelayCellDecoder` instead.
    // Ideally we'd make this `#[cfg(test)]`, but then we wouldn't be able
    // to use it in integration tests.
    // https://github.com/rust-lang/rust/issues/84629
    pub fn from_singleton_body(version: RelayCellFormat, body: BoxedCellBody) -> Result<Self> {
        let mut decoder = RelayCellDecoder::new(version);
        let res = decoder.decode(body)?;
        let (mut msgs, incomplete) = res.into_parts();
        let Some(msg) = msgs.next() else {
            // There was no complete message in the cell.
            return Err(Error::MissingData);
        };
        if incomplete.is_some() {
            // There was an incomplete message at the end of the cell.
            return Err(Error::ExtraneousBytes);
        }
        if msgs.next().is_some() {
            // There was more than one message in the cell.
            return Err(Error::ExtraneousBytes);
        }
        Ok(msg)
    }

    /// Return the command for this cell.
    pub fn cmd(&self) -> RelayCmd {
        match &self.internal {
            UnparsedRelayMsgInternal::V0(body) => {
                /// Position of the command within the v0 cell body.
                const CMD_OFFSET: usize = 0;
                body[CMD_OFFSET].into()
            }
            UnparsedRelayMsgInternal::V1(body) => {
                /// Position of the command within the v1 body.
                const CMD_OFFSET: usize = 16;
                body[CMD_OFFSET].into()
            }
        }
    }
    /// Return the stream ID for the stream that this msg corresponds to, if any.
    pub fn stream_id(&self) -> Option<StreamId> {
        match &self.internal {
            UnparsedRelayMsgInternal::V0(body) => StreamId::new(u16::from_be_bytes(
                body[STREAM_ID_OFFSET_V0..STREAM_ID_OFFSET_V0 + 2]
                    .try_into()
                    .expect("two-byte slice was not two bytes long!?"),
            )),
            UnparsedRelayMsgInternal::V1(body) => {
                match self.cmd().expects_streamid(Some(RelayCellFormat::V1)) {
                    StreamIdReq::WantNone => None,
                    StreamIdReq::Unrecognized | StreamIdReq::Any => None,
                    StreamIdReq::WantSome => StreamId::new(u16::from_be_bytes(
                        body[STREAM_ID_OFFSET_V1..STREAM_ID_OFFSET_V1 + 2]
                            .try_into()
                            .expect("two-byte slice was not two bytes long!?"),
                    )),
                }
            }
        }
    }
    /// Return the "length" field of a data cell, or 0 if not a data cell.
    ///
    /// This is the size of the cell data (the "data" field), not the size of the cell.
    ///
    /// If the field value is invalid (for example >509 for V0 cells), an error will be returned.
    pub fn data_len(&self) -> Result<u16> {
        if self.cmd() != RelayCmd::DATA {
            return Ok(0);
        }

        let bytes: [u8; 2] = match &self.internal {
            UnparsedRelayMsgInternal::V0(body) => &body[LENGTH_OFFSET_V0..LENGTH_OFFSET_V0 + 2],
            UnparsedRelayMsgInternal::V1(body) => &body[LENGTH_OFFSET_V1..LENGTH_OFFSET_V1 + 2],
        }
        .try_into()
        .expect("two-byte slice was not two bytes long!?");

        let len = u16::from_be_bytes(bytes);

        let max = match &self.internal {
            UnparsedRelayMsgInternal::V0(_body) => BODY_MAX_LEN_V0,
            UnparsedRelayMsgInternal::V1(_body) => BODY_MAX_LEN_V1,
        };

        if len > max {
            // TODO: This error value isn't quite right as it has the error message "object length
            // too large to represent as usize", which isn't what we're checking here.
            // But it wouldn't make sense to add a different but similar variant to `Error`.
            return Err(Error::BadLengthValue);
        }

        Ok(len)
    }
    /// Decode this unparsed cell into a given cell type.
    pub fn decode<M: RelayMsg>(self) -> Result<RelayMsgOuter<M>> {
        match self.internal {
            UnparsedRelayMsgInternal::V0(body) => {
                let mut reader = Reader::from_slice(body.as_ref());
                RelayMsgOuter::decode_v0_from_reader(&mut reader)
            }
            UnparsedRelayMsgInternal::V1(body) => {
                let mut reader = Reader::from_slice(body.as_ref());
                RelayMsgOuter::decode_v1_from_reader(&mut reader)
            }
        }
    }
}

/// A decoded and parsed relay message of unrestricted type,
/// with an accompanying optional Stream ID.
pub type AnyRelayMsgOuter = RelayMsgOuter<msg::AnyRelayMsg>;

/// A deprecated name for AnyRelayMsgOuter.
#[deprecated(note = "Use AnyRelayMsgOuter instead.")]
pub type AnyRelayCell = AnyRelayMsgOuter;

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

/// A deprecated name for RelayMsgOuter.
#[deprecated(note = "Use RelayMsgOuter instead.")]
pub type RelayCell<M> = RelayMsgOuter<M>;

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
    //
    // TODO prop340: This API won't work for packed or fragmented messages.
    pub fn encode<R: Rng + CryptoRng>(
        self,
        format: RelayCellFormat,
        rng: &mut R,
    ) -> crate::Result<BoxedCellBody> {
        /// We skip this much space before adding any random padding to the
        /// end of the cell
        const MIN_SPACE_BEFORE_PADDING: usize = 4;

        let (mut body, enc_len) = match format {
            RelayCellFormat::V0 => self.encode_to_cell_v0()?,
            RelayCellFormat::V1 => self.encode_to_cell_v1()?,
        };
        debug_assert!(enc_len <= CELL_DATA_LEN);
        if enc_len < CELL_DATA_LEN - MIN_SPACE_BEFORE_PADDING {
            rng.fill_bytes(&mut body[enc_len + MIN_SPACE_BEFORE_PADDING..]);
        }

        Ok(body)
    }

    /// Consume a relay cell and return its contents, encoded for use
    /// in a RELAY or RELAY_EARLY cell.
    fn encode_to_cell_v0(self) -> EncodeResult<(BoxedCellBody, usize)> {
        // NOTE: This implementation is a bit optimized, since it happens to
        // literally every relay cell that we produce.

        // TODO -NM: Add a specialized implementation for making a DATA cell from
        // a body?

        /// The position of the length field within a relay cell.
        const LEN_POS: usize = 9;
        /// The position of the body a relay cell.
        const BODY_POS: usize = 11;

        let body = BodyWrapper(Box::new([0_u8; BODY_MAX_LEN_V0 as usize]));

        let mut w = crate::slicewriter::SliceWriter::new(body);
        w.write_u8(self.msg.cmd().into());
        w.write_u16(0); // "Recognized"
        w.assert_offset_is(STREAM_ID_OFFSET_V0);
        w.write_u16(StreamId::get_or_zero(self.streamid));
        w.write_u32(0); // Digest
        // (It would be simpler to use NestedWriter at this point, but it uses an internal Vec that we are trying to avoid.)
        w.assert_offset_is(LEN_POS);
        w.write_u16(0); // Length.
        w.assert_offset_is(BODY_POS);
        self.msg.encode_onto(&mut w)?; // body
        let (mut body, written) = w.try_unwrap().map_err(|_| {
            EncodeError::Bug(internal!(
                "Encoding of relay message was too long to fit into a cell!"
            ))
        })?;
        let payload_len = written - BODY_POS;
        debug_assert!(payload_len < u16::MAX as usize);
        *(<&mut [u8; 2]>::try_from(&mut body.0[LEN_POS..LEN_POS + 2])
            .expect("Two-byte slice was not two bytes long!?")) =
            (payload_len as u16).to_be_bytes();
        Ok((body.0, written))
    }

    /// Consume a relay cell and return its contents, encoded for use
    /// in a RELAY or RELAY_EARLY cell.
    fn encode_to_cell_v1(self) -> EncodeResult<(BoxedCellBody, usize)> {
        // NOTE: This implementation is a bit optimized, since it happens to
        // literally every relay cell that we produce.
        // TODO -NM: Add a specialized implementation for making a DATA cell from
        // a body?

        /// Position of the length field within the cell.
        const LEN_POS_V1: usize = 16 + 1; // Skipping tag, command.

        let cmd = self.msg.cmd();
        let body = BodyWrapper(Box::new([0_u8; BODY_MAX_LEN_V1 as usize]));
        let mut w = crate::slicewriter::SliceWriter::new(body);
        w.advance(16); // Tag: 16 bytes
        w.write_u8(cmd.get()); // Command: 1 byte.
        w.assert_offset_is(LEN_POS_V1);
        w.advance(2); //  Length: 2 bytes.
        let mut body_pos = 16 + 1 + 2;
        match (
            cmd.expects_streamid(Some(RelayCellFormat::V1)),
            self.streamid,
        ) {
            (StreamIdReq::WantNone, None) => {}
            (StreamIdReq::WantSome, Some(id)) => {
                w.write_u16(id.into());
                body_pos += 2;
            }
            (_, id) => {
                return Err(EncodeError::Bug(internal!(
                    "Tried to encode invalid stream ID {id:?} for {cmd}"
                )));
            }
        }
        w.assert_offset_is(body_pos);

        self.msg.encode_onto(&mut w)?; // body
        let (mut body, written) = w.try_unwrap().map_err(|_| {
            EncodeError::Bug(internal!(
                "Encoding of relay message was too long to fit into a cell!"
            ))
        })?;
        let payload_len = written - body_pos;
        debug_assert!(payload_len < u16::MAX as usize);
        *(<&mut [u8; 2]>::try_from(&mut body.0[LEN_POS_V1..LEN_POS_V1 + 2])
            .expect("Two-byte slice was not two bytes long!?")) =
            (payload_len as u16).to_be_bytes();
        Ok((body.0, written))
    }

    /// Parse a RELAY or RELAY_EARLY cell body into a RelayMsgOuter.
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    ///
    /// Fails if the cell doesn't contain exactly one message.
    ///
    /// Non-test code should generally use `RelayCellDecoder` instead.
    // Ideally we'd make this `#[cfg(test)]`, but then we wouldn't be able
    // to use it in integration tests.
    // https://github.com/rust-lang/rust/issues/84629
    #[allow(clippy::needless_pass_by_value)] // TODO this will go away soon.
    pub fn decode_singleton(version: RelayCellFormat, body: BoxedCellBody) -> Result<Self> {
        let unparsed_msg = UnparsedRelayMsg::from_singleton_body(version, body)?;
        unparsed_msg.decode()
    }
    /// Parse a `RelayCellFormat::V0` RELAY or RELAY_EARLY cell body into a
    /// RelayMsgOuter from a reader.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed
    fn decode_v0_from_reader(r: &mut Reader<'_>) -> Result<Self> {
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

    /// Parse a `RelayCellFormat::V1` RELAY or RELAY_EARLY cell body into a
    /// RelayMsgOuter from a reader.
    ///
    /// Requires that the cryptographic checks on the message have already been
    /// performed.
    fn decode_v1_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        r.advance(16)?; // Tag
        let cmd: RelayCmd = r.take_u8()?.into();
        let len = r.take_u16()?.into();
        let streamid = match cmd.expects_streamid(Some(RelayCellFormat::V1)) {
            // If no stream ID is expected, then the body begins immediately.
            StreamIdReq::WantNone => None,
            // In this case, a stream ID _is_ expected.
            //
            // (If it happens to be zero, we will reject the message,
            // since zero is never a stream ID.)
            StreamIdReq::WantSome => Some(StreamId::new(r.take_u16()?).ok_or_else(|| {
                Error::InvalidMessage(
                    format!("Zero-valued stream ID with relay command {cmd}").into(),
                )
            })?),
            // We treat an unrecognized command as having no stream ID.
            //
            // (Note: This command is truly unrecognized, and not one that we could parse
            // differently under other circumstances.)
            //
            // Note that this enables a destructive fingerprinting opportunity,
            // where an attacker can learn whether we have a version of Arti that recognizes this
            // command, at the expense of our killing this circuit immediately if they are wrong.
            // This is not a very bad attack.
            //
            // Note that StreamIdReq::Any should be impossible here, since we're using the V1
            // format.
            StreamIdReq::Unrecognized | StreamIdReq::Any => {
                return Err(Error::InvalidMessage(
                    format!("Unrecognized relay command {cmd}").into(),
                ));
            }
        };
        if r.remaining() < len {
            //
            return Err(Error::InvalidMessage(
                "Insufficient data in relay cell".into(),
            ));
        }
        r.truncate(len);
        let msg = M::decode_from_reader(cmd, r)?;
        Ok(Self { streamid, msg })
    }
}

/// Wrap a BoxedCellBody and implement AsMut<[u8]>, so we can use it with `SliceWriter`.
struct BodyWrapper(BoxedCellBody);
impl AsMut<[u8]> for BodyWrapper {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
