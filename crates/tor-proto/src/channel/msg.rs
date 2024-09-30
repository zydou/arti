//! This contains restricted message sets namespaced by link protocol version.
//!
//! In other words, each protocl version define sets of possible messages depending on the channel
//! type as in client or relay and initiator or responder.
//!
//! This module also defines [`MessageFilter`] which can be used to filter messages based on
//! specific details of the message such as direction, command, channel type and channel stage.

/// Subprotocol LINK version 4.
///
/// Increases circuit ID width to 4 bytes.
pub(crate) mod linkv4 {
    use tor_cell::restricted_msg;

    restricted_msg! {
        /// Handshake messages of a relay that initiates a connection. They are sent by the
        /// initiator and thus received by the responder.
        #[derive(Clone, Debug)]
        pub(crate) enum HandshakeRelayInitiatorMsg: ChanMsg {
            Authenticate,
            Certs,
            Netinfo
        }
    }

    restricted_msg! {
        /// Handshake messages of a relay that responds to a connection. They are received by the
        /// initiator and thus sent by the responder.
        #[derive(Clone, Debug)]
        pub(crate) enum HandshakeRelayResponderMsg: ChanMsg {
            AuthChallenge,
            Certs,
            Netinfo
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
        pub(crate) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo
        }
    }

    // From this point on, the C is "Client" and the R is "Relay" and the name indicate the
    // direction of messages. For example, C2R means client -> (to) relay.

    restricted_msg! {
        /// A channel message that we allow to be sent from a Client to a Relay on
        /// an open channel.
        #[allow(unused)] // TODO: Remove once used.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgC2R: ChanMsg {
            // No Create*, it is obsolete (TAP).
            Create2,
            CreateFast,
            Destroy,
            Padding,
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
        pub(crate) enum OpenChanMsgR2C : ChanMsg {
            // No Create*, we are not a client and it is obsolete (TAP).
            // No Created*, it is obsolete (TAP).
            CreatedFast,
            Created2,
            Relay,
            // No RelayEarly, only for client.
            Destroy,
        }
    }

    restricted_msg! {
        /// A channel message that we allow to be sent (bidirectionally) from a Relay to a Relay on
        /// an open channel.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgR2R : ChanMsg {
            // No Vpadding, only sent during handshake.
            // No Create/Created, it is obsolete (TAP).
            Create2,
            Created2,
            Destroy,
            Padding,
            Relay,
            RelayEarly,
            // No PaddingNegotiate, only client sends this.
            // No Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // No Authorize: it is reserved, but unused.
        }
    }
}

/// Subprotocol LINK version 5.
///
/// Adds support for padding and negotiation.
pub(crate) mod linkv5 {
    use tor_cell::restricted_msg;

    restricted_msg! {
        /// Handshake messages of a relay that initiates a connection. They are sent by the
        /// initiator and thus received by the responder.
        #[derive(Clone,Debug)]
        pub(crate) enum HandshakeRelayInitiatorMsg: ChanMsg {
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
        pub(crate) enum HandshakeRelayResponderMsg: ChanMsg {
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
        pub(crate) enum HandshakeClientInitiatorMsg: ChanMsg {
            Netinfo,
            Vpadding,
        }
    }

    // From this point on, the C is "Client" and the R is "Relay" and the name indicate the
    // direction of messages. For example, C2R means client -> (to) relay.

    restricted_msg! {
        /// A channel message that we allow to be sent from a Client to a Relay on
        /// an open channel.
        #[allow(unused)] // TODO: Remove once used.
        #[derive(Clone, Debug)]
        pub(crate) enum OpenChanMsgC2R: ChanMsg {
            // No Create*, it is obsolete (TAP).
            Create2,
            CreateFast,
            Destroy,
            Padding,
            PaddingNegotiate,
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
        pub(crate) enum OpenChanMsgR2C : ChanMsg {
            // No Create/d*, only clients and it is obsolete (TAP).
            CreatedFast,
            Created2,
            Destroy,
            Padding,
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
        pub(crate) enum OpenChanMsgR2R : ChanMsg {
            // No Create/Created, it is obsolete (TAP).
            Create2,
            Created2,
            Destroy,
            Padding,
            // No Vpadding, only sent during handshake.
            Relay,
            RelayEarly,
            // No PaddingNegotiate, only client sends this.
            // No Versions, Certs, AuthChallenge, Authenticate, Netinfo: they are for handshakes.
            // No Authorize: it is reserved, but unused.
        }
    }
}
