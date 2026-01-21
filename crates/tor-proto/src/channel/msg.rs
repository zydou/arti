//! This contains restricted message sets namespaced by link protocol version.
//!
//! In other words, each protocl version define sets of possible messages depending on the channel
//! type as in client or relay and initiator or responder.
//!
//! This module also defines [`MessageFilter`] which can be used to filter messages based on
//! specific details of the message such as direction, command, channel type and channel stage.

use bytes::BytesMut;
use tor_cell::chancell::{AnyChanCell, ChanCell, ChanMsg, codec, msg::AnyChanMsg};

use crate::{Error, channel::ChannelType};

/// Subprotocol LINK version 4.
///
/// Increases circuit ID width to 4 bytes.
pub(super) mod linkv4 {
    use bytes::BytesMut;
    use tor_cell::{
        chancell::{AnyChanCell, codec},
        restricted_msg,
    };

    use super::MessageStage;
    use crate::{
        Error,
        channel::{
            ChannelType,
            msg::{decode_as_any, encode_as_any},
        },
    };

    restricted_msg! {
        /// Handshake messages of a relay that initiates a connection. They are sent by the
        /// initiator and thus received by the responder.
        #[derive(Clone, Debug)]
        pub(super) enum HandshakeRelayInitiatorMsg: ChanMsg {
            Authenticate,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages of a relay that responds to a connection. They are received by the
        /// initiator and thus sent by the responder.
        #[derive(Clone, Debug)]
        pub(super) enum HandshakeRelayResponderMsg: ChanMsg {
            AuthChallenge,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages of a client that initiates a connection to a relay.
        ///
        /// The Versions message is not in this set as it is a special case as the very first cell
        /// being negotiated in order to learn the link protocol version.
        ///
        /// This MUST be a subset of HandshakeRelayResponderMsg because the relay responder doesn't
        /// know what the other side will send depending if it wants to authenticate or not.
        #[derive(Clone, Debug)]
        pub(super) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo,
            Vpadding,
        }
    }

    // From this point on, the C is "Client" and the R is "Relay" and the name indicate the
    // direction of messages. For example, C2R means client -> (to) relay.

    restricted_msg! {
        /// A channel message that we allow to be sent from a Client to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgC2R: ChanMsg {
            // No Create*, it is obsolete (TAP).
            Create2,
            CreateFast,
            Destroy,
            Padding,
            Vpadding,
            // No PaddingNegotiate, it is v5+ only.
            Relay,
            RelayEarly,
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent from a Relay to a Client on
        /// an open channel.
        ///
        /// (An Open channel here is one on which we have received a NETINFO cell.)
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgR2C : ChanMsg {
            // No Create*, we are not a client and it is obsolete (TAP).
            // No Created*, it is obsolete (TAP).
            CreatedFast,
            Created2,
            Relay,
            // No RelayEarly, only for client.
            Destroy,
            Padding,
            Vpadding,
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent (bidirectionally) from a Relay to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgR2R : ChanMsg {
            // No Vpadding, only sent during handshake.
            // No Create/Created, it is obsolete (TAP).
            Create2,
            Created2,
            Destroy,
            Padding,
            Vpadding,
            Relay,
            RelayEarly,
            // No PaddingNegotiate, only client sends this.
            // No Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // No Authorize: it is reserved, but unused.
        }
    }

    /// Decode cell using the given channel type, message stage, codec and byte source.
    pub(super) fn decode_cell(
        chan_type: ChannelType,
        stage: &MessageStage,
        codec: &mut codec::ChannelCodec,
        src: &mut BytesMut,
    ) -> Result<Option<AnyChanCell>, Error> {
        use ChannelType::*;
        use MessageStage::*;

        let decode_fn = match (chan_type, stage) {
            (ClientInitiator, Handshake) => decode_as_any::<HandshakeRelayResponderMsg>,
            (ClientInitiator, Open) => decode_as_any::<OpenChanMsgR2C>,
            (RelayInitiator, Handshake) => decode_as_any::<HandshakeRelayResponderMsg>,
            (RelayInitiator, Open) => decode_as_any::<OpenChanMsgR2R>,
            (RelayResponder { authenticated: _ }, Handshake) => {
                // We don't know if the other side is a client or relay. However, this message set
                // is a superset of the HandshakeClientInitiatorMsg and so we cover the client as
                // well.
                decode_as_any::<HandshakeRelayInitiatorMsg>
            }
            (RelayResponder { authenticated }, Open) => match authenticated {
                false => decode_as_any::<OpenChanMsgC2R>,
                true => decode_as_any::<OpenChanMsgR2R>,
            },
        };

        decode_fn(stage, codec, src)
    }

    /// Encode a given cell which can contains any type of messages. It is filtered through its
    /// restricted message set at encoding time.
    ///
    /// Return an error if encoding fails or if cell is disallowed.
    pub(super) fn encode_cell(
        chan_type: ChannelType,
        stage: &MessageStage,
        cell: AnyChanCell,
        codec: &mut codec::ChannelCodec,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        use ChannelType::*;
        use MessageStage::*;

        let encode_fn = match (chan_type, stage) {
            (ClientInitiator, Handshake) => encode_as_any::<HandshakeClientInitiatorMsg>,
            (ClientInitiator, Open) => encode_as_any::<OpenChanMsgC2R>,
            (RelayInitiator, Handshake) => encode_as_any::<HandshakeRelayInitiatorMsg>,
            (RelayInitiator, Open) => encode_as_any::<OpenChanMsgR2R>,
            (RelayResponder { authenticated: _ }, Handshake) => {
                encode_as_any::<HandshakeRelayResponderMsg>
            }
            (RelayResponder { authenticated }, Open) => match authenticated {
                false => encode_as_any::<OpenChanMsgR2C>,
                true => encode_as_any::<OpenChanMsgR2R>,
            },
        };

        encode_fn(stage, cell, codec, dst)
    }
}

/// Subprotocol LINK version 5.
///
/// Adds support for padding and negotiation.
pub(super) mod linkv5 {
    use bytes::BytesMut;
    use tor_cell::{
        chancell::{AnyChanCell, codec},
        restricted_msg,
    };

    use super::MessageStage;
    use crate::{
        Error,
        channel::{
            ChannelType,
            msg::{decode_as_any, encode_as_any},
        },
    };

    restricted_msg! {
        /// Handshake messages of a relay that initiates a connection. They are sent by the
        /// initiator and thus received by the responder.
        #[derive(Clone,Debug)]
        pub(super) enum HandshakeRelayInitiatorMsg: ChanMsg {
            Authenticate,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages of a relay that responds to a connection. They are received by the
        /// initiator and thus sent by the responder.
        #[derive(Clone,Debug)]
        pub(super) enum HandshakeRelayResponderMsg: ChanMsg {
            AuthChallenge,
            Certs,
            Netinfo,
            Vpadding,
        }
    }

    restricted_msg! {
        /// Handshake messages of a client that initiates a connection to a relay.
        ///
        /// The Versions message is not in this set as it is a special case as the very first cell
        /// being negotiated in order to learn the link protocol version.
        #[derive(Clone,Debug)]
        pub(super) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo,
            Vpadding,
        }
    }

    // From this point on, the C is "Client" and the R is "Relay" and the name indicate the
    // direction of messages. For example, C2R means client -> (to) relay.

    restricted_msg! {
        /// A channel message that we allow to be sent from a Client to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgC2R: ChanMsg {
            // No Create*, it is obsolete (TAP).
            Create2,
            CreateFast,
            Destroy,
            Padding,
            PaddingNegotiate,
            Vpadding,
            Relay,
            RelayEarly,
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent from a Relay to a Client on
        /// an open channel.
        ///
        /// (An Open channel here is one on which we have received a NETINFO cell.)
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgR2C : ChanMsg {
            // No Create/d*, only clients and it is obsolete (TAP).
            CreatedFast,
            Created2,
            Destroy,
            Padding,
            Vpadding,
            Relay,
            // No PaddingNegotiate, only clients.
            // No Versions, Certs, AuthChallenge, Authenticate: they are for handshakes.
            // No Authorize: it is reserved, but unused.
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent (bidirectionally) from a Relay to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(super) enum OpenChanMsgR2R : ChanMsg {
            // No Create/Created, it is obsolete (TAP).
            Create2,
            Created2,
            Destroy,
            Padding,
            Vpadding,
            // No Vpadding, only sent during handshake.
            Relay,
            RelayEarly,
            // No PaddingNegotiate, only client sends this.
            // No Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // No Authorize: it is reserved, but unused.
        }
    }

    /// Decode cell using the given channel type, message stage, codec and byte source.
    pub(super) fn decode_cell(
        chan_type: ChannelType,
        stage: &MessageStage,
        codec: &mut codec::ChannelCodec,
        src: &mut BytesMut,
    ) -> Result<Option<AnyChanCell>, Error> {
        use ChannelType::*;
        use MessageStage::*;

        match (chan_type, stage) {
            (ClientInitiator, Handshake) => {
                decode_as_any::<HandshakeRelayResponderMsg>(stage, codec, src)
            }
            (ClientInitiator, Open) => decode_as_any::<OpenChanMsgR2C>(stage, codec, src),
            (RelayInitiator, Handshake) => {
                decode_as_any::<HandshakeRelayResponderMsg>(stage, codec, src)
            }
            (RelayInitiator, Open) => decode_as_any::<OpenChanMsgR2R>(stage, codec, src),
            (RelayResponder { authenticated: _ }, Handshake) => {
                decode_as_any::<HandshakeRelayInitiatorMsg>(stage, codec, src)
            }
            (
                RelayResponder {
                    authenticated: false,
                },
                Open,
            ) => decode_as_any::<OpenChanMsgC2R>(stage, codec, src),
            (
                RelayResponder {
                    authenticated: true,
                },
                Open,
            ) => decode_as_any::<OpenChanMsgR2R>(stage, codec, src),
        }
    }

    /// Encode a given cell which can contains any type of messages. It is filtered through its
    /// restricted message set at encoding time.
    ///
    /// Return an error if encoding fails or if cell is disallowed.
    pub(super) fn encode_cell(
        chan_type: ChannelType,
        stage: &MessageStage,
        cell: AnyChanCell,
        codec: &mut codec::ChannelCodec,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        use ChannelType::*;
        use MessageStage::*;

        match (chan_type, stage) {
            (ClientInitiator, Handshake) => {
                encode_as_any::<HandshakeClientInitiatorMsg>(stage, cell, codec, dst)
            }
            (ClientInitiator, Open) => encode_as_any::<OpenChanMsgC2R>(stage, cell, codec, dst),
            (RelayInitiator, Handshake) => {
                encode_as_any::<HandshakeRelayInitiatorMsg>(stage, cell, codec, dst)
                // We don't know if the other side is a client or relay. However, this message set
                // is a superset of the HandshakeClientInitiatorMsg and so we cover the client as
                // well.
            }
            (RelayInitiator, Open) => encode_as_any::<OpenChanMsgR2R>(stage, cell, codec, dst),
            (RelayResponder { authenticated: _ }, Handshake) => {
                encode_as_any::<HandshakeRelayResponderMsg>(stage, cell, codec, dst)
            }
            (
                RelayResponder {
                    authenticated: false,
                },
                Open,
            ) => encode_as_any::<OpenChanMsgR2C>(stage, cell, codec, dst),
            (
                RelayResponder {
                    authenticated: true,
                },
                Open,
            ) => encode_as_any::<OpenChanMsgR2R>(stage, cell, codec, dst),
        }
    }
}

/// Helper function to decode a cell within a restricted msg set into an AnyChanCell.
///
/// The given stage is used to know which error to return.
fn decode_as_any<R>(
    stage: &MessageStage,
    codec: &mut codec::ChannelCodec,
    src: &mut BytesMut,
) -> Result<Option<AnyChanCell>, Error>
where
    R: Into<AnyChanMsg> + ChanMsg,
{
    codec
        .decode_cell::<R>(src)
        .map(|opt| {
            opt.map(|cell| {
                let (circid, msg) = cell.into_circid_and_msg();
                ChanCell::new(circid, msg.into())
            })
        })
        .map_err(|e| stage.to_err(format!("Decoding cell error: {e}")))
}

/// Helper function to encode an AnyChanCell cell that is within a restricted msg set R.
///
/// The given stage is used to know which error to return.
fn encode_as_any<R>(
    stage: &MessageStage,
    cell: AnyChanCell,
    codec: &mut codec::ChannelCodec,
    dst: &mut BytesMut,
) -> Result<(), Error>
where
    R: ChanMsg + TryFrom<AnyChanMsg, Error = AnyChanMsg>,
{
    let (circ_id, any_msg) = cell.into_circid_and_msg();

    match R::try_from(any_msg) {
        Ok(rmsg) => {
            let rcell: ChanCell<R> = ChanCell::new(circ_id, rmsg);
            codec
                .write_cell(rcell, dst)
                .map_err(|e| stage.to_err(format!("Encoding cell error: {e}")))
        }
        Err(m) => Err(stage.to_err(format!("Disallowed cell command {}", m.cmd(),))),
    }
}

/// Channel protocol version negotiated.
#[derive(Copy, Clone, Debug)]
pub(super) enum LinkVersion {
    /// Version 4 that need to use linkv4:: messages.
    V4,
    /// Version 5 that need to use linkv5:: messages.
    V5,
}

impl LinkVersion {
    /// Return the value of this link version as a u16. Useful for lower level crates that require
    /// the value for which we can't export this enum.
    pub(super) fn value(&self) -> u16 {
        match self {
            Self::V4 => 4,
            Self::V5 => 5,
        }
    }
}

impl TryFrom<u16> for LinkVersion {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            4 => Self::V4,
            5 => Self::V5,
            _ => {
                return Err(Error::HandshakeProto(format!(
                    "Unknown link version {value}"
                )));
            }
        })
    }
}

/// What stage a channel can be of a negotiation. This is used in order to learn which restricted
/// message set we should be looking at.
///
/// Notice that we don't have the "New" stage and this is because we only learn the link protocol
/// version once we enter the Handshake stage.
pub(super) enum MessageStage {
    /// Handshaking as in the channel is working to become open.
    Handshake,
    /// Open as the channel is now open.
    Open,
}

impl MessageStage {
    /// Return an error using the given message for the right stage.
    ///
    /// Very useful helper that just select the right error type for the stage.
    fn to_err(&self, msg: String) -> Error {
        match self {
            Self::Handshake => Error::HandshakeProto(msg),
            Self::Open => Error::ChanProto(msg),
        }
    }
}

/// A message filter object which is used to learn if a certain message is allowed or not on a
/// channel.
///
/// It is pinned to a link protocol version, a channel type and a channel message stage.
pub(super) struct MessageFilter {
    /// For what link protocol version this filter applies for.
    link_version: LinkVersion,
    /// For which channel type this filter applies for.
    channel_type: ChannelType,
    /// At which stage this filter applies for.
    stage: MessageStage,
}

impl MessageFilter {
    /// Constructor
    pub(super) fn new(
        link_version: LinkVersion,
        channel_type: ChannelType,
        stage: MessageStage,
    ) -> Self {
        Self {
            link_version,
            channel_type,
            stage,
        }
    }

    /// Return the [`ChannelType`] of this filter.
    pub(super) fn channel_type(&self) -> ChannelType {
        self.channel_type
    }

    /// Return the [`ChannelType`] of this filter as a mutable.
    pub(super) fn channel_type_mut(&mut self) -> &mut ChannelType {
        &mut self.channel_type
    }

    /// Decode a cell from the given bytes for the right link version, channel type and message
    /// stage using the codec given.
    pub(super) fn decode_cell(
        &self,
        codec: &mut codec::ChannelCodec,
        src: &mut BytesMut,
    ) -> Result<Option<AnyChanCell>, Error> {
        match self.link_version {
            LinkVersion::V4 => linkv4::decode_cell(self.channel_type, &self.stage, codec, src),
            LinkVersion::V5 => linkv5::decode_cell(self.channel_type, &self.stage, codec, src),
        }
    }

    /// Decode a cell from the given bytes for the right link version, channel type and message
    /// stage using the codec given.
    pub(super) fn encode_cell(
        &self,
        cell: AnyChanCell,
        codec: &mut codec::ChannelCodec,
        dst: &mut BytesMut,
    ) -> Result<(), Error> {
        match self.link_version {
            LinkVersion::V4 => {
                linkv4::encode_cell(self.channel_type, &self.stage, cell, codec, dst)
            }
            LinkVersion::V5 => {
                linkv5::encode_cell(self.channel_type, &self.stage, cell, codec, dst)
            }
        }
    }
}
