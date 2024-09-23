//! Different kinds of messages that can be encoded in channel cells.

use super::{BoxedCellBody, ChanCmd, RawCellBody, CELL_DATA_LEN};
use std::net::{IpAddr, Ipv4Addr};
use tor_basic_utils::skip_fmt;
use tor_bytes::{self, EncodeError, EncodeResult, Error, Readable, Reader, Result, Writer};
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_units::IntegerMilliseconds;

use caret::caret_int;
use derive_deftly::Deftly;
use educe::Educe;

/// Trait for the 'bodies' of channel messages.
pub trait Body: Readable {
    /// Decode a channel cell body from a provided reader.
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        r.extract()
    }
    /// Consume this message and encode its body onto `w`.
    ///
    /// Does not encode anything _but_ the cell body, and does not pad
    /// to the cell length.
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()>;
}

crate::restrict::restricted_msg! {
/// Decoded message from a channel.
///
/// A ChanMsg is an item received on a channel -- a message from
/// another Tor client or relay that we are connected to directly over
/// a TLS connection.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
@omit_from "avoid_conflict_with_a_blanket_implementation"
pub enum AnyChanMsg : ChanMsg {
    /// A Padding message
    Padding,
    /// Variable-length padding message
    Vpadding,
    /// (Deprecated) TAP-based cell to create a new circuit.
    Create,
    /// (Mostly deprecated) HMAC-based cell to create a new circuit.
    CreateFast,
    /// Cell to create a new circuit
    Create2,
    /// (Deprecated) Answer to a Create cell
    Created,
    /// (Mostly Deprecated) Answer to a CreateFast cell
    CreatedFast,
    /// Answer to a Create2 cell
    Created2,
    /// A message sent along a circuit, likely to a more-distant relay.
    Relay,
    /// A message sent along a circuit (limited supply)
    RelayEarly,
    /// Tear down a circuit
    Destroy,
    /// Part of channel negotiation: describes our position on the network
    Netinfo,
    /// Part of channel negotiation: describes what link protocol versions
    /// we support
    Versions,
    /// Negotiates what kind of channel padding to send
    PaddingNegotiate,
    /// Part of channel negotiation: additional certificates not in the
    /// TLS handshake
    Certs,
    /// Part of channel negotiation: additional random material to be used
    /// as part of authentication
    AuthChallenge,
    /// Part of channel negotiation: used to authenticate relays when they
    /// initiate the channel.
    Authenticate,
    /// Not yet used
    Authorize,
    _ =>
    /// Any cell whose command we don't recognize
    Unrecognized,
}
}

/// A Padding message is a fixed-length message on a channel that is
/// ignored.
///
/// Padding message can be used to disguise the true amount of data on a
/// channel, or as a "keep-alive".
///
/// The correct response to a padding cell is to drop it and do nothing.
#[derive(Clone, Debug, Default, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
pub struct Padding {}
impl Padding {
    /// Create a new fixed-length padding cell
    pub fn new() -> Self {
        Padding {}
    }
}
impl Body for Padding {
    fn encode_onto<W: Writer + ?Sized>(self, _w: &mut W) -> EncodeResult<()> {
        Ok(())
    }
}
impl Readable for Padding {
    fn take_from(_b: &mut Reader<'_>) -> Result<Self> {
        Ok(Padding {})
    }
}

/// A VPadding message is a variable-length padding message.
///
/// The correct response to a padding cell is to drop it and do nothing.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Vpadding {
    /// How much padding to send in this cell's body.
    len: u16,
}
impl Vpadding {
    /// Return a new vpadding cell with given length.
    pub fn new(len: u16) -> Self {
        Vpadding { len }
    }
}
impl Body for Vpadding {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_zeros(self.len as usize);
        Ok(())
    }
}
impl Readable for Vpadding {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        if b.remaining() > u16::MAX as usize {
            return Err(Error::InvalidMessage(
                "Too many bytes in VPADDING cell".into(),
            ));
        }
        Ok(Vpadding {
            len: b.remaining() as u16,
        })
    }
}

/// helper -- declare a fixed-width cell for handshake commands, in which
/// a fixed number of bytes matter and the rest are ignored
macro_rules! fixed_len_handshake {
    {
        $(#[$meta:meta])*
        $name:ident , $cmd:ident, $len:ident
    } => {
        $(#[$meta])*
        #[derive(Clone,Debug,Deftly)]
        #[derive_deftly(HasMemoryCost)]
        pub struct $name {
            handshake: Vec<u8>
        }
        impl $name {
            /// Create a new cell from a provided handshake.
            pub fn new<B>(handshake: B) -> Self
                where B: Into<Vec<u8>>
            {
                let handshake = handshake.into();
                $name { handshake }
            }
        }
        impl Body for $name {
            fn encode_onto<W: Writer + ?Sized>(self, w: &mut W)  -> EncodeResult<()> {
                w.write_all(&self.handshake[..]);
                Ok(())
            }
        }
        impl Readable for $name {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                Ok($name {
                    handshake: b.take($len)?.into(),
                })
            }
        }
    }
}

/// Number of bytes used for a TAP handshake by the initiator.
pub(crate) const TAP_C_HANDSHAKE_LEN: usize = 128 + 16 + 42;
/// Number of bytes used for a TAP handshake response
pub(crate) const TAP_S_HANDSHAKE_LEN: usize = 128 + 20;

/// Number of bytes used for a CREATE_FAST handshake by the initiator
const FAST_C_HANDSHAKE_LEN: usize = 20;
/// Number of bytes used for a CREATE_FAST handshake response
const FAST_S_HANDSHAKE_LEN: usize = 20 + 20;

fixed_len_handshake! {
    /// A Create message creates a circuit, using the TAP handshake.
    ///
    /// TAP is an obsolete handshake based on RSA-1024 and DH-1024.
    /// Relays respond to Create message with a Created reply on
    /// success, or a Destroy message on failure.
    ///
    /// In Tor today, Create is only used for the deprecated v2 onion
    /// service protocol.
    Create, CREATE, TAP_C_HANDSHAKE_LEN
}
fixed_len_handshake! {
    /// A Created message responds to a Created message, using the TAP
    /// handshake.
    ///
    /// TAP is an obsolete handshake based on RSA-1024 and DH-1024.
    Created, CREATED, TAP_S_HANDSHAKE_LEN
}
fixed_len_handshake! {
    /// A CreateFast message creates a circuit using no public-key crypto.
    ///
    /// CreateFast is safe only when used on an already-secure TLS
    /// connection.  It can only be used for the first hop of a circuit.
    ///
    /// Relays reply to a CreateFast message with CreatedFast on
    /// success, or a Destroy message on failure.
    ///
    /// This handshake was originally used for the first hop of every
    /// circuit.  Nowadays it is used for creating one-hop circuits
    /// when we don't know any onion key for the first hop.
    CreateFast, CREATE_FAST, FAST_C_HANDSHAKE_LEN
}
impl CreateFast {
    /// Return the content of this handshake
    pub fn handshake(&self) -> &[u8] {
        &self.handshake
    }
}
fixed_len_handshake! {
    /// A CreatedFast message responds to a CreateFast message
    ///
    /// Relays send this message back to indicate that the CrateFast handshake
    /// is complete.
    CreatedFast, CREATED_FAST, FAST_S_HANDSHAKE_LEN
}
impl CreatedFast {
    /// Consume this message and return the content of this handshake
    pub fn into_handshake(self) -> Vec<u8> {
        self.handshake
    }
}

caret_int! {
    /// Handshake type, corresponding to [`HTYPE` in
    /// tor-spec](https://spec.torproject.org/tor-spec/create-created-cells.html).
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct HandshakeType(u16) {
        /// [TAP](https://spec.torproject.org/tor-spec/create-created-cells.html#TAP) -- the original Tor handshake.
        TAP = 0,

        // 1 is reserved

        /// [ntor](https://spec.torproject.org/tor-spec/create-created-cells.html#ntor) -- the ntor+curve25519+sha256 handshake.
        NTOR = 2,
        /// [ntor-v3](https://spec.torproject.org/tor-spec/create-created-cells.html#ntor-v3) -- ntor extended with extra data.
        NTOR_V3 = 3,
    }
}

/// A Create2 message create a circuit on the current channel.
///
/// To create a circuit, the client sends a Create2 cell containing a
/// handshake of a given type; the relay responds with a Created2 cell
/// containing a reply.
///
/// Currently, most Create2 cells contain a client-side instance of the
/// "ntor" handshake.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Create2 {
    /// Identifier for what kind of handshake this is.
    handshake_type: HandshakeType,
    /// Body of the handshake.
    handshake: Vec<u8>,
}
impl Body for Create2 {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u16(self.handshake_type.into());
        let handshake_len = self
            .handshake
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(handshake_len);
        w.write_all(&self.handshake[..]);
        Ok(())
    }
}
impl Readable for Create2 {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let handshake_type = HandshakeType::from(b.take_u16()?);
        let hlen = b.take_u16()?;
        let handshake = b.take(hlen as usize)?.into();
        Ok(Create2 {
            handshake_type,
            handshake,
        })
    }
}
impl Create2 {
    /// Wrap a typed handshake as a Create2 message
    pub fn new<B>(handshake_type: HandshakeType, handshake: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        let handshake = handshake.into();
        Create2 {
            handshake_type,
            handshake,
        }
    }

    /// Return the type of this handshake.
    pub fn handshake_type(&self) -> HandshakeType {
        self.handshake_type
    }

    /// Return the body of this handshake.
    pub fn body(&self) -> &[u8] {
        &self.handshake[..]
    }
}

/// A Created2 message completes a circuit-creation handshake.
///
/// When a relay receives a valid Create2 message that it can handle, it
/// establishes the circuit and replies with a Created2.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Created2 {
    /// Body of the handshake reply
    handshake: Vec<u8>,
}
impl Created2 {
    /// Create a new Created2 to hold a given handshake.
    pub fn new<B>(handshake: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        let handshake = handshake.into();
        Created2 { handshake }
    }
    /// Consume this created2 cell and return its body.
    pub fn into_body(self) -> Vec<u8> {
        self.handshake
    }
}
impl Body for Created2 {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        let handshake_len = self
            .handshake
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(handshake_len);
        w.write_all(&self.handshake[..]);
        Ok(())
    }
}
impl Readable for Created2 {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let hlen = b.take_u16()?;
        let handshake = b.take(hlen as usize)?.into();
        Ok(Created2 { handshake })
    }
}

/// A Relay cell - that is, one transmitted over a circuit.
///
/// Once a circuit has been established, relay cells can be sent over
/// it.  Clients can send relay cells to any relay on the circuit. Any
/// relay on the circuit can send relay cells to the client, either
/// directly (if it is the first hop), or indirectly through the
/// intermediate hops.
///
/// A different protocol is defined over the relay cells; it is implemented
/// in the [crate::relaycell] module.
#[derive(Clone, Educe, derive_more::From, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[educe(Debug)]
pub struct Relay {
    /// The contents of the relay cell as encoded for transfer.
    ///
    /// TODO(nickm): It's nice that this is boxed, since we don't want to copy
    /// cell data all over the place. But unfortunately, there are some other
    /// places where we _don't_ Box things that we should, and more copies than
    /// necessary happen. We should refactor our data handling until we're mostly
    /// moving around pointers rather than copying data;  see ticket #7.
    #[educe(Debug(method = "skip_fmt"))]
    body: BoxedCellBody,
}
impl Relay {
    /// Construct a Relay message from a slice containing its contents.
    pub fn new<P>(body: P) -> Self
    where
        P: AsRef<[u8]>,
    {
        let body = body.as_ref();
        let mut r = [0_u8; CELL_DATA_LEN];
        // TODO: This will panic if body is too long, but that would be a
        // programming error anyway.
        r[..body.len()].copy_from_slice(body);
        Relay { body: Box::new(r) }
    }
    /// Construct a Relay message from its body.
    pub fn from_raw(body: RawCellBody) -> Self {
        Relay {
            body: Box::new(body),
        }
    }
    /// Consume this Relay message and return a BoxedCellBody for
    /// encryption/decryption.
    pub fn into_relay_body(self) -> BoxedCellBody {
        self.body
    }
    /// Wrap this Relay message into a RelayMsg as a RELAY_EARLY cell.
    pub fn into_early(self) -> AnyChanMsg {
        AnyChanMsg::RelayEarly(RelayEarly(self))
    }
}
impl Body for Relay {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.body[..]);
        Ok(())
    }
}
impl Readable for Relay {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let mut body = Box::new([0_u8; CELL_DATA_LEN]);
        body.copy_from_slice(b.take(CELL_DATA_LEN)?);
        Ok(Relay { body })
    }
}

/// A Relay cell that is allowed to contain a CREATE message.
///
/// Only a limited number of these may be sent on each circuit.
#[derive(Clone, Debug, derive_more::Deref, derive_more::From, derive_more::Into, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct RelayEarly(Relay);
impl Readable for RelayEarly {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(RelayEarly(Relay::take_from(r)?))
    }
}
impl Body for RelayEarly {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}
impl RelayEarly {
    /// Consume this RelayEarly message and return a BoxedCellBody for
    /// encryption/decryption.
    //
    // (Since this method takes `self` by value, we can't take advantage of
    // Deref.)
    pub fn into_relay_body(self) -> BoxedCellBody {
        self.0.body
    }
}

/// The Destroy message tears down a circuit.
///
/// On receiving a Destroy message, a Tor implementation should
/// tear down the associated circuit, and pass the destroy message
/// down the circuit to later/earlier hops on the circuit (if any).
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Destroy {
    /// Reason code given for tearing down this circuit
    reason: DestroyReason,
}
impl Destroy {
    /// Create a new destroy cell.
    pub fn new(reason: DestroyReason) -> Self {
        Destroy { reason }
    }
    /// Return the provided reason for destroying the circuit.
    pub fn reason(&self) -> DestroyReason {
        self.reason
    }
}
impl Body for Destroy {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(self.reason.into());
        Ok(())
    }
}
impl Readable for Destroy {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let reason = r.take_u8()?.into();
        Ok(Destroy { reason })
    }
}

caret_int! {
    /// Declared reason for ending a circuit.
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct DestroyReason(u8) {
        /// No reason given.
        ///
        /// This is the only reason that clients send.
        NONE = 0,
        /// Protocol violation
        PROTOCOL = 1,
        /// Internal error.
        INTERNAL = 2,
        /// Client sent a TRUNCATE command.
        REQUESTED = 3,
        /// Relay is hibernating and not accepting requests
        HIBERNATING = 4,
        /// Ran out of memory, sockets, or circuit IDs
        RESOURCELIMIT = 5,
        /// Couldn't connect to relay.
        CONNECTFAILED = 6,
        /// Connected to a relay, but its OR identity wasn't as requested.
        OR_IDENTITY = 7,
        /// One of the OR channels carrying this circuit died.
        CHANNEL_CLOSED = 8,
        /// Circuit expired for being too dirty or old
        FINISHED = 9,
        /// Circuit construction took too long
        TIMEOUT = 10,
        /// Circuit was destroyed w/o client truncate (?)
        DESTROYED = 11,
        /// Request for unknown onion service
        NOSUCHSERVICE = 12
    }
}

impl DestroyReason {
    /// Return a human-readable string for this reason.
    pub fn human_str(&self) -> &'static str {
        match *self {
            DestroyReason::NONE => "No reason",
            DestroyReason::PROTOCOL => "Protocol violation",
            DestroyReason::INTERNAL => "Internal error",
            DestroyReason::REQUESTED => "Client sent a TRUNCATE command",
            DestroyReason::HIBERNATING => "Relay is hibernating and not accepting requests",
            DestroyReason::RESOURCELIMIT => "Relay ran out of resources",
            DestroyReason::CONNECTFAILED => "Couldn't connect to relay",
            DestroyReason::OR_IDENTITY => "Connected to relay with different OR identity",
            DestroyReason::CHANNEL_CLOSED => "The OR channels carrying this circuit died",
            DestroyReason::FINISHED => "Circuit expired for being too dirty or old",
            DestroyReason::TIMEOUT => "Circuit construction took too long",
            DestroyReason::DESTROYED => "Circuit was destroyed without client truncate",
            DestroyReason::NOSUCHSERVICE => "No such onion service",
            _ => "Unrecognized reason",
        }
    }
}

/// The netinfo message ends channel negotiation.
///
/// It tells the other party on the channel our view of the current time,
/// our own list of public addresses, and our view of its address.
///
/// When we get a netinfo cell, we can start creating circuits on a
/// channel and sending data.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Netinfo {
    /// Time when this cell was sent, or 0 if this cell is sent by a client.
    ///
    /// TODO-SPEC(nickm): Y2038 issue here.  Better add a new handshake version
    /// to solve it.  See
    /// [torspec#80](https://gitlab.torproject.org/tpo/core/torspec/-/issues/80).
    timestamp: u32,
    /// Observed address for party that did not send the netinfo cell.
    their_addr: Option<IpAddr>,
    /// Canonical addresses for the party that did send the netinfo cell.
    my_addr: Vec<IpAddr>,
}
/// helper: encode a single address in the form that netinfo messages expect
fn enc_one_netinfo_addr<W: Writer + ?Sized>(w: &mut W, addr: &IpAddr) {
    match addr {
        IpAddr::V4(ipv4) => {
            w.write_u8(0x04); // type.
            w.write_u8(4); // length.
            w.write_all(&ipv4.octets()[..]);
        }
        IpAddr::V6(ipv6) => {
            w.write_u8(0x06); // type.
            w.write_u8(16); // length.
            w.write_all(&ipv6.octets()[..]);
        }
    }
}
/// helper: take an address as encoded in a netinfo message
fn take_one_netinfo_addr(r: &mut Reader<'_>) -> Result<Option<IpAddr>> {
    let atype = r.take_u8()?;
    let alen = r.take_u8()?;
    let abody = r.take(alen as usize)?;
    match (atype, alen) {
        (0x04, 4) => {
            let bytes = [abody[0], abody[1], abody[2], abody[3]];
            Ok(Some(IpAddr::V4(bytes.into())))
        }
        (0x06, 16) => {
            // TODO(nickm) is there a better way?
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(abody);
            Ok(Some(IpAddr::V6(bytes.into())))
        }
        (_, _) => Ok(None),
    }
}
impl Netinfo {
    /// Construct a new Netinfo to be sent by a client.
    pub fn from_client(their_addr: Option<IpAddr>) -> Self {
        Netinfo {
            timestamp: 0, // clients don't report their timestamps.
            their_addr,
            my_addr: Vec::new(), // clients don't report their addrs.
        }
    }
    /// Construct a new Netinfo to be sent by a relay
    pub fn from_relay<V>(timestamp: u32, their_addr: Option<IpAddr>, my_addrs: V) -> Self
    where
        V: Into<Vec<IpAddr>>,
    {
        let my_addr = my_addrs.into();
        Netinfo {
            timestamp,
            their_addr,
            my_addr,
        }
    }
    /// Return the time reported in this NETINFO cell.
    pub fn timestamp(&self) -> Option<std::time::SystemTime> {
        use std::time::{Duration, SystemTime};
        if self.timestamp == 0 {
            None
        } else {
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(self.timestamp.into()))
        }
    }
}
impl Body for Netinfo {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u32(self.timestamp);
        let their_addr = self
            .their_addr
            .unwrap_or_else(|| Ipv4Addr::UNSPECIFIED.into());
        enc_one_netinfo_addr(w, &their_addr);
        let n_addrs: u8 = self
            .my_addr
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u8(n_addrs);
        for addr in &self.my_addr {
            enc_one_netinfo_addr(w, addr);
        }
        Ok(())
    }
}
impl Readable for Netinfo {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let timestamp = r.take_u32()?;
        let their_addr = take_one_netinfo_addr(r)?.filter(|a| !a.is_unspecified());
        let my_n_addrs = r.take_u8()?;
        let mut my_addr = Vec::with_capacity(my_n_addrs as usize);
        for _ in 0..my_n_addrs {
            if let Some(a) = take_one_netinfo_addr(r)? {
                my_addr.push(a);
            }
        }
        Ok(Netinfo {
            timestamp,
            their_addr,
            my_addr,
        })
    }
}

/// A Versions message begins channel negotiation.
///
/// Every channel must begin by sending a Versions message.  This message
/// lists the link protocol versions that this Tor implementation supports.
///
/// Note that we should never actually send Versions cells using the
/// usual channel cell encoding: Versions cells _always_ use two-byte
/// circuit IDs, whereas all the other cell types use four-byte
/// circuit IDs [assuming a non-obsolete version is negotiated].
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Versions {
    /// List of supported link protocol versions
    versions: Vec<u16>,
}
impl Versions {
    /// Construct a new Versions message using a provided list of link
    /// protocols.
    ///
    /// Returns an error if the list of versions is too long.
    pub fn new<B>(vs: B) -> crate::Result<Self>
    where
        B: Into<Vec<u16>>,
    {
        let versions = vs.into();
        if versions.len() < (u16::MAX / 2) as usize {
            Ok(Self { versions })
        } else {
            Err(crate::Error::CantEncode("Too many versions"))
        }
    }
    /// Encode this VERSIONS cell in the manner expected for a handshake.
    ///
    /// (That's different from a standard cell encoding, since we
    /// have not negotiated versions yet, and so our circuit-ID length
    /// is an obsolete 2 bytes).
    pub fn encode_for_handshake(self) -> EncodeResult<Vec<u8>> {
        let mut v = Vec::new();
        v.write_u16(0); // obsolete circuit ID length.
        v.write_u8(ChanCmd::VERSIONS.into());
        v.write_u16((self.versions.len() * 2) as u16); // message length.
        self.encode_onto(&mut v)?;
        Ok(v)
    }
    /// Return the best (numerically highest) link protocol that is
    /// shared by this versions cell and my_protos.
    pub fn best_shared_link_protocol(&self, my_protos: &[u16]) -> Option<u16> {
        // NOTE: this implementation is quadratic, but it shouldn't matter
        // much so long as my_protos is small.
        let p = my_protos
            .iter()
            .filter(|p| self.versions.contains(p))
            .fold(0_u16, |a, b| u16::max(a, *b));
        if p == 0 {
            None
        } else {
            Some(p)
        }
    }
}
impl Body for Versions {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        for v in &self.versions {
            w.write_u16(*v);
        }
        Ok(())
    }
}
impl Readable for Versions {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let mut versions = Vec::new();
        while r.remaining() > 0 {
            versions.push(r.take_u16()?);
        }
        Ok(Versions { versions })
    }
}

caret_int! {
    /// A ChanCmd is the type of a channel cell.  The value of the ChanCmd
    /// indicates the meaning of the cell, and (possibly) its length.
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct PaddingNegotiateCmd(u8) {
        /// Start padding
        START = 2,

        /// Stop padding
        STOP = 1,
    }
}

/// A PaddingNegotiate message is used to negotiate channel padding.
///
/// Sent by a client to its guard node,
/// to instruct the relay to enable/disable channel padding.
/// (Not relevant for channels used only for directory lookups,
/// nor inter-relay channels.)
/// See `padding-spec.txt`, section 2.2.
///
/// This message is constructed in the channel manager and transmitted by the reactor.
///
/// The `Default` impl is the same as [`start_default()`](PaddingNegotiate::start_default`)
#[derive(Clone, Debug, Eq, PartialEq, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct PaddingNegotiate {
    /// Whether to start or stop padding
    command: PaddingNegotiateCmd,
    /// Suggested lower-bound value for inter-packet timeout in msec.
    // TODO(nickm) is that right?
    ito_low_ms: u16,
    /// Suggested upper-bound value for inter-packet timeout in msec.
    // TODO(nickm) is that right?
    ito_high_ms: u16,
}
impl PaddingNegotiate {
    /// Create a new PADDING_NEGOTIATE START message requesting consensus timing parameters.
    ///
    /// This message restores the state to the one which exists at channel startup.
    pub fn start_default() -> Self {
        // Tor Spec section 7.3, padding-spec section 2.5.
        Self {
            command: PaddingNegotiateCmd::START,
            ito_low_ms: 0,
            ito_high_ms: 0,
        }
    }

    /// Create a new PADDING_NEGOTIATE START message.
    pub fn start(ito_low: IntegerMilliseconds<u16>, ito_high: IntegerMilliseconds<u16>) -> Self {
        // Tor Spec section 7.3
        Self {
            command: PaddingNegotiateCmd::START,
            ito_low_ms: ito_low.as_millis(),
            ito_high_ms: ito_high.as_millis(),
        }
    }

    /// Create a new PADDING_NEGOTIATE STOP message.
    pub fn stop() -> Self {
        // Tor Spec section 7.3
        Self {
            command: PaddingNegotiateCmd::STOP,
            ito_low_ms: 0,
            ito_high_ms: 0,
        }
    }

    /// Construct from the three fields: command, low_ms, high_ms, as a tuple
    ///
    /// For testing only
    #[cfg(feature = "testing")]
    pub fn from_raw(command: PaddingNegotiateCmd, ito_low_ms: u16, ito_high_ms: u16) -> Self {
        PaddingNegotiate {
            command,
            ito_low_ms,
            ito_high_ms,
        }
    }
}
impl Default for PaddingNegotiate {
    fn default() -> Self {
        Self::start_default()
    }
}

impl Body for PaddingNegotiate {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(0); // version
        w.write_u8(self.command.get());
        w.write_u16(self.ito_low_ms);
        w.write_u16(self.ito_high_ms);
        Ok(())
    }
}
impl Readable for PaddingNegotiate {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let v = r.take_u8()?;
        if v != 0 {
            return Err(Error::InvalidMessage(
                "Unrecognized padding negotiation version".into(),
            ));
        }
        let command = r.take_u8()?.into();
        let ito_low_ms = r.take_u16()?;
        let ito_high_ms = r.take_u16()?;
        Ok(PaddingNegotiate {
            command,
            ito_low_ms,
            ito_high_ms,
        })
    }
}

/// A single certificate in a Certs cell.
///
/// The formats used here are implemented in tor-cert. Ed25519Cert is the
/// most common.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
struct TorCert {
    /// Type code for this certificate.
    certtype: u8,
    /// Encoded certificate
    cert: Vec<u8>,
}
/// encode a single TorCert `c` onto a Writer `w`.
fn enc_one_tor_cert<W: Writer + ?Sized>(w: &mut W, c: &TorCert) -> EncodeResult<()> {
    w.write_u8(c.certtype);
    let cert_len: u16 = c
        .cert
        .len()
        .try_into()
        .map_err(|_| EncodeError::BadLengthValue)?;
    w.write_u16(cert_len);
    w.write_all(&c.cert[..]);
    Ok(())
}
/// Try to extract a TorCert from the reader `r`.
fn take_one_tor_cert(r: &mut Reader<'_>) -> Result<TorCert> {
    let certtype = r.take_u8()?;
    let certlen = r.take_u16()?;
    let cert = r.take(certlen as usize)?;
    Ok(TorCert {
        certtype,
        cert: cert.into(),
    })
}
/// A Certs message is used as part of the channel handshake to send
/// additional certificates.
///
/// These certificates are not presented as part of the TLS handshake.
/// Originally this was meant to make Tor TLS handshakes look "normal", but
/// nowadays it serves less purpose, especially now that we have TLS 1.3.
///
/// Every relay sends this message as part of channel negotiation;
/// clients do not send them.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Certs {
    /// The certificates in this cell
    certs: Vec<TorCert>,
}
impl Certs {
    /// Return a new empty certs cell.
    pub fn new_empty() -> Self {
        Certs { certs: Vec::new() }
    }
    /// Add a new encoded certificate to this cell.
    ///
    /// Does not check anything about the well-formedness of the certificate.
    pub fn push_cert_body<B>(&mut self, certtype: tor_cert::CertType, cert: B)
    where
        B: Into<Vec<u8>>,
    {
        let certtype = certtype.into();
        let cert = cert.into();
        self.certs.push(TorCert { certtype, cert });
    }

    /// Return the body of the certificate tagged with 'tp', if any.
    pub fn cert_body(&self, tp: tor_cert::CertType) -> Option<&[u8]> {
        let tp: u8 = tp.into();
        self.certs
            .iter()
            .find(|c| c.certtype == tp)
            .map(|c| &c.cert[..])
    }

    /// Look for a certificate of type 'tp' in this cell; return it if
    /// there is one.
    pub fn parse_ed_cert(&self, tp: tor_cert::CertType) -> crate::Result<tor_cert::KeyUnknownCert> {
        let body = self
            .cert_body(tp)
            .ok_or_else(|| crate::Error::ChanProto(format!("Missing {} certificate", tp)))?;

        let cert = tor_cert::Ed25519Cert::decode(body).map_err(|be| crate::Error::BytesErr {
            err: be,
            parsed: "ed25519 certificate",
        })?;
        if cert.peek_cert_type() != tp {
            return Err(crate::Error::ChanProto(format!(
                "Found a {} certificate labeled as {}",
                cert.peek_cert_type(),
                tp
            )));
        }

        Ok(cert)
    }
}

impl Body for Certs {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        let n_certs: u8 = self
            .certs
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u8(n_certs);
        for c in &self.certs {
            enc_one_tor_cert(w, c)?;
        }
        Ok(())
    }
}
impl Readable for Certs {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let mut certs = Vec::new();
        for _ in 0..n {
            certs.push(take_one_tor_cert(r)?);
        }
        Ok(Certs { certs })
    }
}

/// Length of the body for an authentication challenge
const CHALLENGE_LEN: usize = 32;

/// An AuthChallenge message is part of negotiation, sent by
/// responders to initiators.
///
/// The AuthChallenge cell is used to ensure that some unpredictable material
/// has been sent on the channel, and to tell the initiator what
/// authentication methods will be accepted.
///
/// Clients can safely ignore this message: they don't need to authenticate.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct AuthChallenge {
    /// Random challenge to be used in generating response
    challenge: [u8; CHALLENGE_LEN],
    /// List of permitted authentication methods
    methods: Vec<u16>,
}
impl AuthChallenge {
    /// Construct a new AuthChallenge cell with a given challenge
    /// value (chosen randomly) and a set of acceptable authentication methods.
    pub fn new<B, M>(challenge: B, methods: M) -> Self
    where
        B: Into<[u8; CHALLENGE_LEN]>,
        M: Into<Vec<u16>>,
    {
        AuthChallenge {
            challenge: challenge.into(),
            methods: methods.into(),
        }
    }
}

impl Body for AuthChallenge {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.challenge[..]);
        let n_methods = self
            .methods
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(n_methods);
        for m in self.methods {
            w.write_u16(m);
        }
        Ok(())
    }
}
impl Readable for AuthChallenge {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        //let challenge = r.take(CHALLENGE_LEN)?.into();
        let challenge = r.extract()?;
        let n_methods = r.take_u16()?;
        let mut methods = Vec::new();
        for _ in 0..n_methods {
            methods.push(r.take_u16()?);
        }
        Ok(AuthChallenge { challenge, methods })
    }
}

/// Part of negotiation: sent by initiators to responders.
///
/// The Authenticate cell proves the initiator's identity to the
/// responder, even if TLS client authentication was not used.
///
/// Clients do not use this.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Authenticate {
    /// Authentication method in use
    authtype: u16,
    /// Encoded authentication object
    auth: Vec<u8>,
}
impl Authenticate {
    /// Create a new Authenticate message from a given type and body.
    pub fn new<B>(authtype: u16, body: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Authenticate {
            authtype,
            auth: body.into(),
        }
    }
}
impl Body for Authenticate {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u16(self.authtype);
        let authlen = self
            .auth
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(authlen);
        w.write_all(&self.auth[..]);
        Ok(())
    }
}
impl Readable for Authenticate {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let authtype = r.take_u16()?;
        let authlen = r.take_u16()?;
        let auth = r.take(authlen as usize)?.into();
        Ok(Authenticate { authtype, auth })
    }
}

/// The Authorize message type is not yet used.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Authorize {
    /// The cell's content, which isn't really specified yet.
    content: Vec<u8>,
}
impl Authorize {
    /// Construct a new Authorize cell.
    pub fn new<B>(content: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        let content = content.into();
        Authorize { content }
    }
}
impl Body for Authorize {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.content[..]);
        Ok(())
    }
}
impl Readable for Authorize {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Authorize {
            content: r.take(r.remaining())?.into(),
        })
    }
}

/// Holds any message whose command we don't recognize.
///
/// Well-behaved Tor implementations are required to ignore commands
/// like this.
///
/// TODO: I believe that this is not a risky case of Postel's law,
/// since it is only for channels, but we should be careful here.
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Unrecognized {
    /// The channel command that we got with this cell
    cmd: ChanCmd,
    /// The contents of the cell
    content: Vec<u8>,
}
impl Unrecognized {
    /// Construct a new cell of arbitrary or unrecognized type.
    pub fn new<B>(cmd: ChanCmd, content: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        let content = content.into();
        Unrecognized { cmd, content }
    }
    /// Return the command from this cell.
    pub fn cmd(&self) -> ChanCmd {
        self.cmd
    }
    /// Take an unrecognized cell's body from a reader `r`, and apply
    /// the given command to it.
    pub fn decode_with_cmd(cmd: ChanCmd, r: &mut Reader<'_>) -> Result<Unrecognized> {
        let mut u = Unrecognized::take_from(r)?;
        u.cmd = cmd;
        Ok(u)
    }
}
impl Body for Unrecognized {
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.content[..]);
        Ok(())
    }
}
impl Readable for Unrecognized {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Unrecognized {
            cmd: 0.into(),
            content: r.take(r.remaining())?.into(),
        })
    }
}

/// Helper: declare a From<> implementation from message types for
/// cells that don't take a circid.
macro_rules! msg_into_cell {
    ($body:ident) => {
        impl From<$body> for super::AnyChanCell {
            fn from(body: $body) -> super::AnyChanCell {
                super::AnyChanCell {
                    circid: None,
                    msg: body.into(),
                }
            }
        }
    };
}

msg_into_cell!(Padding);
msg_into_cell!(Vpadding);
msg_into_cell!(Netinfo);
msg_into_cell!(Versions);
msg_into_cell!(PaddingNegotiate);
msg_into_cell!(Certs);
msg_into_cell!(AuthChallenge);
msg_into_cell!(Authenticate);
msg_into_cell!(Authorize);

/// Helper: declare a ChanMsg implementation for a message type that has a
/// fixed command.
//
// TODO: It might be better to merge Body with ChanMsg, but that is complex,
// since their needs are _slightly_ different.
//
// TODO: If we *do* make the change above, then perhaps we should also implement
// our restricted enums in terms of this, so that there is only one instance of
// [<$body:snake:upper>]
macro_rules! msg_impl_chanmsg {
    ($($body:ident,)*) =>
    {paste::paste!{
       $(impl crate::chancell::ChanMsg for $body {
            fn cmd(&self) -> crate::chancell::ChanCmd { crate::chancell::ChanCmd::[< $body:snake:upper >] }
            fn encode_onto<W: tor_bytes::Writer + ?Sized>(self, w: &mut W) -> tor_bytes::EncodeResult<()> {
                crate::chancell::msg::Body::encode_onto(self, w)
            }
            fn decode_from_reader(cmd: ChanCmd, r: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
                if cmd != crate::chancell::ChanCmd::[< $body:snake:upper >] {
                    return Err(tor_bytes::Error::InvalidMessage(
                        format!("Expected {} command; got {cmd}", stringify!([< $body:snake:upper >])).into()
                    ));
                }
                crate::chancell::msg::Body::decode_from_reader(r)
            }
        })*
    }}
}

// We implement ChanMsg for every body type, so that you can write code that does
// e.g. ChanCell<Relay>.
msg_impl_chanmsg!(
    Padding,
    Vpadding,
    Create,
    CreateFast,
    Create2,
    Created,
    CreatedFast,
    Created2,
    Relay,
    RelayEarly,
    Destroy,
    Netinfo,
    Versions,
    PaddingNegotiate,
    Certs,
    AuthChallenge,
    Authenticate,
    Authorize,
);

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    #[test]
    fn destroy_reason() {
        let r1 = DestroyReason::CONNECTFAILED;

        assert_eq!(r1.human_str(), "Couldn't connect to relay");

        let r2 = DestroyReason::from(200); // not a specified number.
        assert_eq!(r2.human_str(), "Unrecognized reason");
    }
}
