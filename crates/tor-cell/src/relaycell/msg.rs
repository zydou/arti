//! Encoding and decoding for relay messages
//!
//! Relay messages are sent along circuits, inside RELAY or RELAY_EARLY
//! cells.

use super::RelayCmd;
use crate::chancell::msg::{
    DestroyReason, HandshakeType, TAP_C_HANDSHAKE_LEN, TAP_S_HANDSHAKE_LEN,
};
use crate::chancell::CELL_DATA_LEN;
use caret::caret_int;
use derive_deftly::Deftly;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use tor_bytes::{EncodeError, EncodeResult, Error, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_linkspec::EncodedLinkSpec;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::{derive_deftly_template_HasMemoryCost, memory_cost_structural_copy};

use bitflags::bitflags;

#[cfg(feature = "hs")]
#[cfg_attr(docsrs, doc(cfg(feature = "hs")))]
pub use super::hs::{
    est_intro::EstablishIntro, EstablishRendezvous, IntroEstablished, Introduce1, Introduce2,
    IntroduceAck, Rendezvous1, Rendezvous2, RendezvousEstablished,
};
#[cfg(feature = "experimental-udp")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental-udp")))]
pub use super::udp::{ConnectUdp, ConnectedUdp, Datagram};

crate::restrict::restricted_msg! {
/// A single parsed relay message, sent or received along a circuit
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
@omit_from "avoid_conflict_with_a_blanket_implementation"
pub enum AnyRelayMsg : RelayMsg {
    /// Create a stream
    Begin,
    /// Send data on a stream
    Data,
    /// Close a stream
    End,
    /// Successful response to a Begin message
    Connected,
    /// For flow control
    Sendme,
    /// Extend a circuit to a new hop (deprecated)
    Extend,
    /// Successful response to an Extend message (deprecated)
    Extended,
    /// Extend a circuit to a new hop
    Extend2,
    /// Successful response to an Extend2 message
    Extended2,
    /// Partially close a circuit
    Truncate,
    /// Tell the client that a circuit has been partially closed
    Truncated,
    /// Used for padding
    Drop,
    /// Launch a DNS request
    Resolve,
    /// Response to a Resolve message
    Resolved,
    /// Start a directory stream
    BeginDir,
    /// Start a UDP stream.
    [feature = "experimental-udp"]
    ConnectUdp,
    /// Successful response to a ConnectUdp message
    [feature = "experimental-udp"]
    ConnectedUdp,
    /// UDP stream data
    [feature = "experimental-udp"]
    Datagram,
    /// Establish Introduction
    [feature = "hs"]
    EstablishIntro,
    /// Establish Rendezvous
    [feature = "hs"]
    EstablishRendezvous,
    /// Introduce1 (client to introduction point)
    [feature = "hs"]
    Introduce1,
    /// Introduce2 (introduction point to service)
    [feature = "hs"]
    Introduce2,
    /// Rendezvous1 (service to rendezvous point)
    [feature = "hs"]
    Rendezvous1,
    /// Rendezvous2 (rendezvous point to client)
    [feature = "hs"]
    Rendezvous2,
    /// Acknowledgement for EstablishIntro.
    [feature = "hs"]
    IntroEstablished,
    /// Acknowledgment for EstablishRendezvous.
    [feature = "hs"]
    RendezvousEstablished,
    /// Acknowledgement for Introduce1.
    [feature = "hs"]
    IntroduceAck,

    _ =>
    /// An unrecognized command.
    Unrecognized,
    }
}

/// Internal: traits in common different cell bodies.
pub trait Body: Sized {
    /// Decode a relay cell body from a provided reader.
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self>;
    /// Encode the body of this cell into the end of a writer.
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()>;
}

bitflags! {
    /// A set of recognized flags that can be attached to a begin cell.
    ///
    /// For historical reasons, these flags are constructed so that 0
    /// is a reasonable default for all of them.
    #[derive(Clone, Copy, Debug)]
    pub struct BeginFlags : u32 {
        /// The client would accept a connection to an IPv6 address.
        const IPV6_OKAY = (1<<0);
        /// The client would not accept a connection to an IPv4 address.
        const IPV4_NOT_OKAY = (1<<1);
        /// The client would rather have a connection to an IPv6 address.
        const IPV6_PREFERRED = (1<<2);
    }
}
memory_cost_structural_copy!(BeginFlags);
impl From<u32> for BeginFlags {
    fn from(v: u32) -> Self {
        BeginFlags::from_bits_truncate(v)
    }
}

/// A preference for IPv4 vs IPv6 addresses; usable as a nicer frontend for
/// BeginFlags.
#[derive(Clone, Default, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IpVersionPreference {
    /// Only IPv4 is allowed.
    Ipv4Only,
    /// IPv4 and IPv6 are both allowed, and IPv4 is preferred.
    #[default]
    Ipv4Preferred,
    /// IPv4 and IPv6 are both allowed, and IPv6 is preferred.
    Ipv6Preferred,
    /// Only IPv6 is allowed.
    Ipv6Only,
}
impl From<IpVersionPreference> for BeginFlags {
    fn from(v: IpVersionPreference) -> Self {
        use IpVersionPreference::*;
        match v {
            Ipv4Only => 0.into(),
            Ipv4Preferred => BeginFlags::IPV6_OKAY,
            Ipv6Preferred => BeginFlags::IPV6_OKAY | BeginFlags::IPV6_PREFERRED,
            Ipv6Only => BeginFlags::IPV4_NOT_OKAY,
        }
    }
}

/// A Begin message creates a new data stream.
///
/// Upon receiving a Begin message, relays should try to open a new stream
/// for the client, if their exit policy permits, and associate it with a
/// new TCP connection to the target address.
///
/// If the exit decides to reject the Begin message, or if the TCP
/// connection fails, the exit should send an End message.
///
/// Clients should reject these messages.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Begin {
    /// Ascii string describing target address
    addr: Vec<u8>,
    /// Target port
    port: u16,
    /// Flags that describe how to resolve the address
    flags: BeginFlags,
}

impl Begin {
    /// Construct a new Begin cell
    pub fn new<F>(addr: &str, port: u16, flags: F) -> crate::Result<Self>
    where
        F: Into<BeginFlags>,
    {
        if !addr.is_ascii() {
            return Err(crate::Error::BadStreamAddress);
        }
        let mut addr = addr.to_string();
        addr.make_ascii_lowercase();
        Ok(Begin {
            addr: addr.into_bytes(),
            port,
            flags: flags.into(),
        })
    }

    /// Return the address requested in this message.
    pub fn addr(&self) -> &[u8] {
        &self.addr[..]
    }

    /// Return the port requested by this message.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return the set of flags provided in this message.
    pub fn flags(&self) -> BeginFlags {
        self.flags
    }
}

impl Body for Begin {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = {
            if r.peek(1)? == b"[" {
                // IPv6 address
                r.advance(1)?;
                let a = r.take_until(b']')?;
                let colon = r.take_u8()?;
                if colon != b':' {
                    return Err(Error::InvalidMessage("missing port in begin cell".into()));
                }
                a
            } else {
                // IPv4 address, or hostname.
                r.take_until(b':')?
            }
        };
        let port = r.take_until(0)?;
        let flags = if r.remaining() >= 4 { r.take_u32()? } else { 0 };

        if !addr.is_ascii() {
            return Err(Error::InvalidMessage(
                "target address in begin cell not ascii".into(),
            ));
        }

        let port = std::str::from_utf8(port)
            .map_err(|_| Error::InvalidMessage("port in begin cell not utf8".into()))?;

        let port = port
            .parse()
            .map_err(|_| Error::InvalidMessage("port in begin cell not a valid port".into()))?;

        Ok(Begin {
            addr: addr.into(),
            port,
            flags: flags.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        if self.addr.contains(&b':') {
            w.write_u8(b'[');
            w.write_all(&self.addr[..]);
            w.write_u8(b']');
        } else {
            w.write_all(&self.addr[..]);
        }
        w.write_u8(b':');
        w.write_all(self.port.to_string().as_bytes());
        w.write_u8(0);
        if self.flags.bits() != 0 {
            w.write_u32(self.flags.bits());
        }
        Ok(())
    }
}

/// A Data message represents data sent along a stream.
///
/// Upon receiving a Data message for a live stream, the client or
/// exit sends that data onto the associated TCP connection.
///
/// These messages hold between 1 and [Data::MAXLEN] bytes of data each;
/// they are the most numerous messages on the Tor network.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Data {
    /// Contents of the cell, to be sent on a specific stream
    ///
    /// INVARIANT: Holds between 1 and [`Data::MAXLEN`] bytes, inclusive.
    //
    // TODO: There's a good case to be made that this should be a BoxedCellBody
    // instead, to avoid allocations and copies.  But first probably we should
    // figure out how proposal 340 will work with this.  Possibly, we will wind
    // up using `bytes` or something.
    body: Vec<u8>,
}
impl Data {
    /// The longest allowable body length for a single data cell.
    /// Relay command (1) + 'Recognized' (2) + StreamID (2) + Digest (4) + Length (2) = 11
    pub const MAXLEN: usize = CELL_DATA_LEN - 11;

    /// Construct a new data cell.
    ///
    /// Returns an error if `inp` is longer than [`Data::MAXLEN`] bytes.
    pub fn new(inp: &[u8]) -> crate::Result<Self> {
        if inp.len() > Data::MAXLEN {
            return Err(crate::Error::CantEncode("Data message too long"));
        }
        if inp.is_empty() {
            return Err(crate::Error::CantEncode("Empty data message"));
        }
        Ok(Self::new_unchecked(inp.into()))
    }

    /// Construct a new data cell, taking as many bytes from `inp`
    /// as possible.
    ///
    /// Return the data cell, and a slice holding any bytes that
    /// wouldn't fit (if any).
    ///
    /// # Panics
    ///
    /// Panics if `inp` is empty.
    #[deprecated(since = "0.16.1", note = "Use try_split_from instead.")]
    pub fn split_from(inp: &[u8]) -> (Self, &[u8]) {
        Self::try_split_from(inp).expect("Tried to split a Data message from an empty input.")
    }

    /// Construct a new data cell, taking as many bytes from `inp`
    /// as possible.
    ///
    /// Return the data cell, and a slice holding any bytes that
    /// wouldn't fit (if any).
    ///
    /// Returns None if the input was empty.
    pub fn try_split_from(inp: &[u8]) -> Option<(Self, &[u8])> {
        if inp.is_empty() {
            return None;
        }
        let len = std::cmp::min(inp.len(), Data::MAXLEN);
        let (data, remainder) = inp.split_at(len);
        Some((Self::new_unchecked(data.into()), remainder))
    }

    /// Construct a new data cell from a provided vector of bytes.
    ///
    /// The vector _must_ not have more than [`Data::MAXLEN`] bytes, and must
    /// not be empty.
    fn new_unchecked(body: Vec<u8>) -> Self {
        debug_assert!((1..=Data::MAXLEN).contains(&body.len()));
        Data { body }
    }
}
impl From<Data> for Vec<u8> {
    fn from(data: Data) -> Vec<u8> {
        data.body
    }
}
impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.body[..]
    }
}

impl Body for Data {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Err(Error::InvalidMessage("Empty DATA message".into()));
        }
        Ok(Data {
            body: r.take(r.remaining())?.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.body);
        Ok(())
    }
}

/// An End message tells the other end of the circuit to close a stream.
///
/// Note that End messages do not implement a true half-closed state,
/// so after sending an End message each party needs to wait a while
/// to be sure that the stream is completely dead.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct End {
    /// Reason for closing the stream
    reason: EndReason,
    /// If the reason is EXITPOLICY, this holds the resolved address an
    /// associated TTL.  The TTL is set to MAX if none was given.
    addr: Option<(IpAddr, u32)>,
}

caret_int! {
    /// A declared reason for closing a stream
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct EndReason(u8) {
        /// Closing a stream because of an unspecified reason.
        ///
        /// This is the only END reason that clients send.
        MISC = 1,
        /// Couldn't look up hostname.
        RESOLVEFAILED = 2,
        /// Remote host refused connection.
        CONNECTREFUSED = 3,
        /// Closing a stream because of an exit-policy violation.
        EXITPOLICY = 4,
        /// Circuit destroyed
        DESTROY = 5,
        /// Anonymized TCP connection was closed
        DONE = 6,
        /// Connection timed out, or OR timed out while connecting
        TIMEOUT = 7,
        /// No route to target destination.
        NOROUTE = 8,
        /// OR is entering hibernation and not handling requests
        HIBERNATING = 9,
        /// Internal error at the OR
        INTERNAL = 10,
        /// Ran out of resources to fulfill requests
        RESOURCELIMIT = 11,
        /// Connection unexpectedly reset
        CONNRESET = 12,
        /// Tor protocol violation
        TORPROTOCOL = 13,
        /// BEGIN_DIR cell at a non-directory-cache.
        NOTDIRECTORY = 14,
    }
}

impl tor_error::HasKind for EndReason {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use EndReason as E;
        match *self {
            E::MISC => EK::RemoteStreamError,
            E::RESOLVEFAILED => EK::RemoteHostResolutionFailed,
            E::CONNECTREFUSED => EK::RemoteConnectionRefused,
            E::EXITPOLICY => EK::ExitPolicyRejected,
            E::DESTROY => EK::CircuitCollapse,
            E::DONE => EK::RemoteStreamClosed,
            E::TIMEOUT => EK::ExitTimeout,
            E::NOROUTE => EK::RemoteNetworkFailed,
            E::RESOURCELIMIT | E::HIBERNATING => EK::RelayTooBusy,
            E::INTERNAL | E::TORPROTOCOL | E::NOTDIRECTORY => EK::TorProtocolViolation,
            E::CONNRESET => EK::RemoteStreamReset,
            _ => EK::RemoteStreamError,
        }
    }
}

impl End {
    /// Make a new END_REASON_MISC message.
    ///
    /// Clients send this every time they decide to close a stream.
    pub fn new_misc() -> Self {
        End {
            reason: EndReason::MISC,
            addr: None,
        }
    }
    /// Make a new END message with the provided end reason.
    pub fn new_with_reason(reason: EndReason) -> Self {
        End { reason, addr: None }
    }
    /// Make a new END message with END_REASON_EXITPOLICY, and the
    /// provided address and ttl.
    pub fn new_exitpolicy(addr: IpAddr, ttl: u32) -> Self {
        End {
            reason: EndReason::EXITPOLICY,
            addr: Some((addr, ttl)),
        }
    }
    /// Return the provided EndReason for this End cell.
    pub fn reason(&self) -> EndReason {
        self.reason
    }
}
impl Body for End {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(End {
                reason: EndReason::MISC,
                addr: None,
            });
        }
        let reason = r.take_u8()?.into();
        if reason == EndReason::EXITPOLICY {
            let addr = match r.remaining() {
                4 | 8 => IpAddr::V4(r.extract()?),
                16 | 20 => IpAddr::V6(r.extract()?),
                _ => {
                    // Ignores other message lengths.
                    return Ok(End { reason, addr: None });
                }
            };
            let ttl = if r.remaining() == 4 {
                r.take_u32()?
            } else {
                u32::MAX
            };
            Ok(End {
                reason,
                addr: Some((addr, ttl)),
            })
        } else {
            Ok(End { reason, addr: None })
        }
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(self.reason.into());
        if let (EndReason::EXITPOLICY, Some((addr, ttl))) = (self.reason, self.addr) {
            match addr {
                IpAddr::V4(v4) => w.write(&v4)?,
                IpAddr::V6(v6) => w.write(&v6)?,
            }
            w.write_u32(ttl);
        }
        Ok(())
    }
}

impl From<EndReason> for std::io::ErrorKind {
    fn from(e: EndReason) -> Self {
        use std::io::ErrorKind::*;
        match e {
            EndReason::RESOLVEFAILED => NotFound,
            EndReason::CONNECTREFUSED => ConnectionRefused,
            EndReason::EXITPOLICY => ConnectionRefused,
            EndReason::DESTROY => ConnectionAborted,
            EndReason::DONE => UnexpectedEof,
            EndReason::TIMEOUT => TimedOut,
            EndReason::HIBERNATING => ConnectionRefused,
            EndReason::RESOURCELIMIT => ConnectionRefused,
            EndReason::CONNRESET => ConnectionReset,
            EndReason::TORPROTOCOL => InvalidData,
            EndReason::NOTDIRECTORY => ConnectionRefused,
            EndReason::INTERNAL | EndReason::NOROUTE | EndReason::MISC => Other,
            _ => Other,
        }
    }
}

/// A Connected message is a successful response to a Begin message
///
/// When an outgoing connection succeeds, the exit sends a Connected
/// back to the client.
///
/// Clients never send Connected messages.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Connected {
    /// Resolved address and TTL (time to live) in seconds
    addr: Option<(IpAddr, u32)>,
}
impl Connected {
    /// Construct a new empty connected cell.
    pub fn new_empty() -> Self {
        Connected { addr: None }
    }
    /// Construct a connected cell with an address and a time-to-live value.
    pub fn new_with_addr(addr: IpAddr, ttl: u32) -> Self {
        Connected {
            addr: Some((addr, ttl)),
        }
    }
}
impl Body for Connected {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        if r.remaining() == 0 {
            return Ok(Connected { addr: None });
        }
        let ipv4 = r.take_u32()?;
        let addr = if ipv4 == 0 {
            if r.take_u8()? != 6 {
                return Err(Error::InvalidMessage(
                    "Invalid address type in CONNECTED cell".into(),
                ));
            }
            IpAddr::V6(r.extract()?)
        } else {
            IpAddr::V4(ipv4.into())
        };
        let ttl = r.take_u32()?;

        Ok(Connected {
            addr: Some((addr, ttl)),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        if let Some((addr, ttl)) = self.addr {
            match addr {
                IpAddr::V4(v4) => w.write(&v4)?,
                IpAddr::V6(v6) => {
                    w.write_u32(0);
                    w.write_u8(6);
                    w.write(&v6)?;
                }
            }
            w.write_u32(ttl);
        }
        Ok(())
    }
}

/// A Sendme message is used to increase flow-control windows.
///
/// To avoid congestion, each Tor circuit and stream keeps track of a
/// number of data cells that it is willing to send.  It decrements
/// these numbers every time it sends a cell.  If these numbers reach
/// zero, then no more cells can be sent on the stream or circuit.
///
/// The only way to re-increment these numbers is by receiving a
/// Sendme cell from the other end of the circuit or stream.
///
/// For security, current circuit-level Sendme cells include an
/// authentication tag that proves knowledge of the cells that they are
/// acking.
///
/// See [tor-spec.txt](https://spec.torproject.org/tor-spec) for more
/// information; also see the source for `tor_proto::circuit::sendme`.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Sendme {
    /// A tag value authenticating the previously received data.
    digest: Option<Vec<u8>>,
}
impl Sendme {
    /// Return a new empty sendme cell
    ///
    /// This format is used on streams, and on circuits without sendme
    /// authentication.
    pub fn new_empty() -> Self {
        Sendme { digest: None }
    }
    /// This format is used on circuits with sendme authentication.
    pub fn new_tag(x: [u8; 20]) -> Self {
        Sendme {
            digest: Some(x.into()),
        }
    }
    /// Consume this cell and return its authentication tag, if any
    pub fn into_tag(self) -> Option<Vec<u8>> {
        self.digest
    }
}
impl Body for Sendme {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let digest = if r.remaining() == 0 {
            None
        } else {
            let ver = r.take_u8()?;
            match ver {
                0 => None,
                1 => {
                    let dlen = r.take_u16()?;
                    Some(r.take(dlen as usize)?.into())
                }
                _ => {
                    return Err(Error::InvalidMessage("Unrecognized SENDME version.".into()));
                }
            }
        };
        Ok(Sendme { digest })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        match self.digest {
            None => (),
            Some(x) => {
                w.write_u8(1);
                let bodylen: u16 = x
                    .len()
                    .try_into()
                    .map_err(|_| EncodeError::BadLengthValue)?;
                w.write_u16(bodylen);
                w.write_all(&x);
            }
        }
        Ok(())
    }
}

/// Extend was an obsolete circuit extension message format.
///
/// This format only handled IPv4 addresses, RSA identities, and the
/// TAP handshake.  Modern Tor clients use Extend2 instead.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Extend {
    /// Where to extend to (address)
    addr: Ipv4Addr,
    /// Where to extend to (port)
    port: u16,
    /// A TAP handshake to send
    handshake: Vec<u8>,
    /// The RSA identity of the target relay
    rsaid: RsaIdentity,
}
impl Extend {
    /// Construct a new (deprecated) extend cell
    pub fn new(addr: Ipv4Addr, port: u16, handshake: Vec<u8>, rsaid: RsaIdentity) -> Self {
        Extend {
            addr,
            port,
            handshake,
            rsaid,
        }
    }
}
impl Body for Extend {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let addr = r.extract()?;
        let port = r.take_u16()?;
        let handshake = r.take(TAP_C_HANDSHAKE_LEN)?.into();
        let rsaid = r.extract()?;
        Ok(Extend {
            addr,
            port,
            handshake,
            rsaid,
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.addr)?;
        w.write_u16(self.port);
        w.write_all(&self.handshake[..]);
        w.write(&self.rsaid)?;
        Ok(())
    }
}

/// Extended was an obsolete circuit extension message, sent in reply to
/// an Extend message.
///
/// Like Extend, the Extended message was only designed for the TAP
/// handshake.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Extended {
    /// Contents of the handshake sent in response to the EXTEND
    handshake: Vec<u8>,
}
impl Extended {
    /// Construct a new Extended message with the provided handshake
    pub fn new(handshake: Vec<u8>) -> Self {
        Extended { handshake }
    }
}
impl Body for Extended {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let handshake = r.take(TAP_S_HANDSHAKE_LEN)?.into();
        Ok(Extended { handshake })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.handshake);
        Ok(())
    }
}

/// An Extend2 message tells the last relay in a circuit to extend to a new
/// hop.
///
/// When a relay (call it R) receives an Extend2 message, it tries to
/// find (or make) a channel to the other relay (R') described in the
/// list of link specifiers. (A link specifier can be an IP addresses
/// or a cryptographic identity).  Once R has such a channel, the
/// it packages the client's handshake data as a new Create2 message
/// R'.  If R' replies with a Created2 (success) message, R packages
/// that message's contents in an Extended message.
//
/// Unlike Extend messages, Extend2 messages can encode any handshake
/// type, and can describe relays in ways other than IPv4 addresses
/// and RSA identities.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Extend2 {
    /// A vector of "link specifiers"
    ///
    /// These link specifiers describe where to find the target relay
    /// that the recipient should extend to.  They include things like
    /// IP addresses and identity keys.
    linkspec: Vec<EncodedLinkSpec>,
    /// Type of handshake to be sent in a CREATE2 cell
    handshake_type: HandshakeType,
    /// Body of the handshake to be sent in a CREATE2 cell
    handshake: Vec<u8>,
}
impl Extend2 {
    /// Create a new Extend2 cell.
    pub fn new(
        linkspec: Vec<EncodedLinkSpec>,
        handshake_type: HandshakeType,
        handshake: Vec<u8>,
    ) -> Self {
        Extend2 {
            linkspec,
            handshake_type,
            handshake,
        }
    }

    /// Return the type of this handshake.
    pub fn handshake_type(&self) -> HandshakeType {
        self.handshake_type
    }

    /// Return the inner handshake for this Extend2 cell.
    pub fn handshake(&self) -> &[u8] {
        &self.handshake[..]
    }
}

impl Body for Extend2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let n = r.take_u8()?;
        let linkspec = r.extract_n(n as usize)?;
        let handshake_type = r.take_u16()?.into();
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?.into();
        Ok(Extend2 {
            linkspec,
            handshake_type,
            handshake,
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        let n_linkspecs: u8 = self
            .linkspec
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u8(n_linkspecs);
        for ls in &self.linkspec {
            w.write(ls)?;
        }
        w.write_u16(self.handshake_type.into());
        let handshake_len: u16 = self
            .handshake
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(handshake_len);
        w.write_all(&self.handshake[..]);
        Ok(())
    }
}

/// Extended2 is a successful reply to an Extend2 message.
///
/// Extended2 messages are generated by the former last hop of a
/// circuit, to tell the client that they have successfully completed
/// a handshake on the client's behalf.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Extended2 {
    /// Contents of the CREATED2 cell that the new final hop sent in
    /// response
    handshake: Vec<u8>,
}
impl Extended2 {
    /// Construct a new Extended2 message with the provided handshake
    pub fn new(handshake: Vec<u8>) -> Self {
        Extended2 { handshake }
    }
    /// Consume this extended2 cell and return its body.
    pub fn into_body(self) -> Vec<u8> {
        self.handshake
    }
}
impl Body for Extended2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let hlen = r.take_u16()?;
        let handshake = r.take(hlen as usize)?;
        Ok(Extended2 {
            handshake: handshake.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        let handshake_len: u16 = self
            .handshake
            .len()
            .try_into()
            .map_err(|_| EncodeError::BadLengthValue)?;
        w.write_u16(handshake_len);
        w.write_all(&self.handshake[..]);
        Ok(())
    }
}

/// A Truncated message is sent to the client when the remaining hops
/// of a circuit have gone away.
///
/// NOTE: Current Tor implementations often treat Truncated messages and
/// Destroy messages interchangeably.  Truncated was intended to be a
/// "soft" Destroy, that would leave the unaffected parts of a circuit
/// still usable.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Truncated {
    /// Reason for which this circuit was truncated.
    reason: DestroyReason,
}
impl Truncated {
    /// Construct a new truncated message.
    pub fn new(reason: DestroyReason) -> Self {
        Truncated { reason }
    }
    /// Get the provided reason to truncate the circuit.
    pub fn reason(self) -> DestroyReason {
        self.reason
    }
}
impl Body for Truncated {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Truncated {
            reason: r.take_u8()?.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u8(self.reason.into());
        Ok(())
    }
}

/// A Resolve message launches a DNS lookup stream.
///
/// A client sends a Resolve message when it wants to perform a DNS
/// lookup _without_ connecting to the resulting address.  On success
/// the exit responds with a Resolved message; on failure it responds
/// with an End message.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Resolve {
    /// Ascii-encoded address to resolve
    query: Vec<u8>,
}
impl Resolve {
    /// Construct a new resolve message to look up a hostname.
    pub fn new(s: &str) -> Self {
        Resolve {
            query: s.as_bytes().into(),
        }
    }
    /// Construct a new resolve message to do a reverse lookup on an address
    pub fn new_reverse(addr: &IpAddr) -> Self {
        let query = match addr {
            IpAddr::V4(v4) => {
                let [a, b, c, d] = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", d, c, b, a)
            }
            IpAddr::V6(v6) => {
                let mut s = String::with_capacity(72);
                for o in v6.octets().iter().rev() {
                    let high_nybble = o >> 4;
                    let low_nybble = o & 15;
                    write!(s, "{:x}.{:x}.", low_nybble, high_nybble).unwrap();
                }
                write!(s, "ip6.arpa").unwrap();
                s
            }
        };
        Resolve {
            query: query.into_bytes(),
        }
    }
}
impl Body for Resolve {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let query = r.take_until(0)?;
        Ok(Resolve {
            query: query.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.query[..]);
        w.write_u8(0);
        Ok(())
    }
}

/// Possible response to a DNS lookup
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
pub enum ResolvedVal {
    /// We found an IP address
    Ip(IpAddr),
    /// We found a hostname
    Hostname(Vec<u8>),
    /// Error; try again
    TransientError,
    /// Error; don't try again
    NontransientError,
    /// A DNS lookup response that we didn't recognize
    Unrecognized(u8, Vec<u8>),
}

/// Indicates a hostname response
const RES_HOSTNAME: u8 = 0;
/// Indicates an IPv4 response
const RES_IPV4: u8 = 4;
/// Indicates an IPv6 response
const RES_IPV6: u8 = 6;
/// Transient error (okay to try again)
const RES_ERR_TRANSIENT: u8 = 0xF0;
/// Non-transient error (don't try again)
const RES_ERR_NONTRANSIENT: u8 = 0xF1;

impl Readable for ResolvedVal {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        /// Helper: return the expected length of a resolved answer with
        /// a given type, if there is a particular expected length.
        fn res_len(tp: u8) -> Option<usize> {
            match tp {
                RES_IPV4 => Some(4),
                RES_IPV6 => Some(16),
                _ => None,
            }
        }
        let tp = r.take_u8()?;
        let len = r.take_u8()? as usize;
        if let Some(expected_len) = res_len(tp) {
            if len != expected_len {
                return Err(Error::InvalidMessage(
                    "Wrong length for RESOLVED answer".into(),
                ));
            }
        }
        Ok(match tp {
            RES_HOSTNAME => Self::Hostname(r.take(len)?.into()),
            RES_IPV4 => Self::Ip(IpAddr::V4(r.extract()?)),
            RES_IPV6 => Self::Ip(IpAddr::V6(r.extract()?)),
            RES_ERR_TRANSIENT => {
                r.advance(len)?;
                Self::TransientError
            }
            RES_ERR_NONTRANSIENT => {
                r.advance(len)?;
                Self::NontransientError
            }
            _ => Self::Unrecognized(tp, r.take(len)?.into()),
        })
    }
}

impl Writeable for ResolvedVal {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        match self {
            Self::Hostname(h) => {
                w.write_u8(RES_HOSTNAME);
                let h_len: u8 = h
                    .len()
                    .try_into()
                    .map_err(|_| EncodeError::BadLengthValue)?;
                w.write_u8(h_len);
                w.write_all(&h[..]);
            }
            Self::Ip(IpAddr::V4(a)) => {
                w.write_u8(RES_IPV4);
                w.write_u8(4); // length
                w.write(a)?;
            }
            Self::Ip(IpAddr::V6(a)) => {
                w.write_u8(RES_IPV6);
                w.write_u8(16); // length
                w.write(a)?;
            }
            Self::TransientError => {
                w.write_u8(RES_ERR_TRANSIENT);
                w.write_u8(0); // length
            }
            Self::NontransientError => {
                w.write_u8(RES_ERR_NONTRANSIENT);
                w.write_u8(0); // length
            }
            Self::Unrecognized(tp, v) => {
                w.write_u8(*tp);
                let v_len: u8 = v
                    .len()
                    .try_into()
                    .map_err(|_| EncodeError::BadLengthValue)?;
                w.write_u8(v_len);
                w.write_all(&v[..]);
            }
        }
        Ok(())
    }
}

/// A Resolved message is a successful reply to a Resolve message.
///
/// The Resolved message contains a list of zero or more addresses,
/// and their associated times-to-live in seconds.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Resolved {
    /// List of addresses and their associated time-to-live values.
    answers: Vec<(ResolvedVal, u32)>,
}
impl Resolved {
    /// Return a new empty Resolved object with no answers.
    pub fn new_empty() -> Self {
        Resolved {
            answers: Vec::new(),
        }
    }
    /// Return a new Resolved object reporting a name lookup error.
    ///
    /// TODO: Is getting no answer an error; or it is represented by
    /// a list of no answers?
    pub fn new_err(transient: bool, ttl: u32) -> Self {
        let mut res = Self::new_empty();
        let err = if transient {
            ResolvedVal::TransientError
        } else {
            ResolvedVal::NontransientError
        };
        res.add_answer(err, ttl);
        res
    }
    /// Add a single answer to this Resolved message
    pub fn add_answer(&mut self, answer: ResolvedVal, ttl: u32) {
        self.answers.push((answer, ttl));
    }

    /// Consume this Resolved message, returning a vector of the
    /// answers and TTL values that it contains.
    ///
    /// Note that actually relying on these TTL values can be
    /// dangerous in practice, since the relay that sent the cell
    /// could be lying in order to cause more lookups, or to get a
    /// false answer cached for longer.
    pub fn into_answers(self) -> Vec<(ResolvedVal, u32)> {
        self.answers
    }
}
impl Body for Resolved {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let mut answers = Vec::new();
        while r.remaining() > 0 {
            let rv = r.extract()?;
            let ttl = r.take_u32()?;
            answers.push((rv, ttl));
        }
        Ok(Resolved { answers })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        for (rv, ttl) in &self.answers {
            w.write(rv)?;
            w.write_u32(*ttl);
        }
        Ok(())
    }
}

/// A relay message that we didn't recognize
///
/// NOTE: Clients should generally reject these.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Unrecognized {
    /// Command that we didn't recognize
    cmd: RelayCmd,
    /// Body associated with that command
    body: Vec<u8>,
}

impl Unrecognized {
    /// Create a new 'unrecognized' cell.
    pub fn new<B>(cmd: RelayCmd, body: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        let body = body.into();
        Unrecognized { cmd, body }
    }

    /// Return the command associated with this message
    pub fn cmd(&self) -> RelayCmd {
        self.cmd
    }
    /// Decode this message, using a provided command.
    pub fn decode_with_cmd(cmd: RelayCmd, r: &mut Reader<'_>) -> Result<Self> {
        let mut r = Unrecognized::decode_from_reader(r)?;
        r.cmd = cmd;
        Ok(r)
    }
}

impl Body for Unrecognized {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Unrecognized {
            cmd: 0.into(),
            body: r.take(r.remaining())?.into(),
        })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.body[..]);
        Ok(())
    }
}

/// Declare a message type for a message with an empty body.
macro_rules! empty_body {
   {
       $(#[$meta:meta])*
       pub struct $name:ident {}
   } => {
       $(#[$meta])*
       #[derive(Clone,Debug,Default,derive_deftly::Deftly)]
       #[derive_deftly(tor_memquota::HasMemoryCost)]
       #[non_exhaustive]
       pub struct $name {}
       impl $crate::relaycell::msg::Body for $name {
           fn decode_from_reader(_r: &mut Reader<'_>) -> Result<Self> {
               Ok(Self::default())
           }
           fn encode_onto<W: Writer + ?Sized>(self, _w: &mut W) -> EncodeResult<()> {
               Ok(())
           }
       }
   }
}
pub(crate) use empty_body;

empty_body! {
    /// A padding message, which is always ignored.
    pub struct Drop {}
}
empty_body! {
    /// Tells a circuit to close all downstream hops on the circuit.
    pub struct Truncate {}
}
empty_body! {
    /// Opens a new stream on a directory cache.
    pub struct BeginDir {}
}

/// Helper: declare a RelayMsg implementation for a message type that has a
/// fixed command.
//
// TODO: It might be better to merge Body with RelayMsg, but that is complex,
// since their needs are _slightly_ different.
//
// TODO: If we *do* make the change above, then perhaps we should also implement
// our restricted enums in terms of this, so that there is only one instance of
// [<$body:snake:upper>]
macro_rules! msg_impl_relaymsg {
    ($($body:ident),* $(,)?) =>
    {paste::paste!{
       $(impl crate::relaycell::RelayMsg for $body {
            fn cmd(&self) -> crate::relaycell::RelayCmd { crate::relaycell::RelayCmd::[< $body:snake:upper >] }
            fn encode_onto<W: tor_bytes::Writer + ?Sized>(self, w: &mut W) -> tor_bytes::EncodeResult<()> {
                crate::relaycell::msg::Body::encode_onto(self, w)
            }
            fn decode_from_reader(cmd: RelayCmd, r: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
                if cmd != crate::relaycell::RelayCmd::[< $body:snake:upper >] {
                    return Err(tor_bytes::Error::InvalidMessage(
                        format!("Expected {} command; got {cmd}", stringify!([< $body:snake:upper >])).into()
                    ));
                }
                crate::relaycell::msg::Body::decode_from_reader(r)
            }
        }

        impl TryFrom<AnyRelayMsg> for $body {
            type Error = crate::Error;
            fn try_from(msg: AnyRelayMsg) -> crate::Result<$body> {
                use crate::relaycell::RelayMsg;
                match msg {
                    AnyRelayMsg::$body(b) => Ok(b),
                    _ => Err(crate::Error::CircProto(format!("Expected {}; got {}" ,
                                                     stringify!([<$body:snake:upper>]),
                                                     msg.cmd())) ),
                }
            }
        }
        )*
    }}
}

msg_impl_relaymsg!(
    Begin, Data, End, Connected, Sendme, Extend, Extended, Extend2, Extended2, Truncate, Truncated,
    Drop, Resolve, Resolved, BeginDir,
);

#[cfg(feature = "experimental-udp")]
msg_impl_relaymsg!(ConnectUdp, ConnectedUdp, Datagram);

#[cfg(feature = "hs")]
msg_impl_relaymsg!(
    EstablishIntro,
    EstablishRendezvous,
    Introduce1,
    Introduce2,
    Rendezvous1,
    Rendezvous2,
    IntroEstablished,
    RendezvousEstablished,
    IntroduceAck,
);
