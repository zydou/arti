//! Encoding and decoding for relay messages
//!
//! Relay messages are sent along circuits, inside RELAY or RELAY_EARLY
//! cells.

use super::msg;
use crate::chancell::CELL_DATA_LEN;
use derive_deftly::Deftly;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use tor_bytes::{EncodeResult, Error, Result};
use tor_bytes::{Readable, Reader, Writeable, Writer};
use tor_memquota::derive_deftly_template_HasMemoryCost;

/// Indicates the payload is a hostname.
const T_HOSTNAME: u8 = 0x01;
/// Indicates the payload is an IPv4.
const T_IPV4: u8 = 0x04;
/// Indicates the payload is an IPv6.
const T_IPV6: u8 = 0x06;

/// Maximum length of an Address::Hostname set at 255.
const MAX_HOSTNAME_LEN: usize = u8::MAX as usize;

/// Address contained in a ConnectUdp and ConnectedUdp cell which can
/// represent a hostname, IPv4 or IPv6 along a port number.
#[derive(Clone, Debug, Eq, PartialEq, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct AddressPort {
    /// Address.
    addr: Address,
    /// Port.
    port: u16,
}

impl Readable for AddressPort {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            addr: r.extract()?,
            port: r.take_u16()?,
        })
    }
}

impl Writeable for AddressPort {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        w.write(&self.addr)?;
        w.write_u16(self.port);
        Ok(())
    }
}

impl TryFrom<(&str, u16)> for AddressPort {
    type Error = Error;

    fn try_from(value: (&str, u16)) -> Result<Self> {
        let addr = Address::from_str(value.0)?;
        Ok(Self {
            addr,
            port: value.1,
        })
    }
}

/// Address representing either a hostname, IPv4 or IPv6.
#[derive(Clone, Debug, Eq, PartialEq, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[non_exhaustive]
pub enum Address {
    /// Hostname
    Hostname(Vec<u8>),
    /// IP version 4 address
    Ipv4(Ipv4Addr),
    /// IP version 6 address
    Ipv6(Ipv6Addr),
}

impl Address {
    /// Return true iff this is a Hostname.
    pub fn is_hostname(&self) -> bool {
        matches!(self, Address::Hostname(_))
    }

    /// Return the cell wire format address type value.
    fn wire_addr_type(&self) -> u8 {
        match self {
            Address::Hostname(_) => T_HOSTNAME,
            Address::Ipv4(_) => T_IPV4,
            Address::Ipv6(_) => T_IPV6,
        }
    }
}

impl Readable for Address {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let addr_type = r.take_u8()?;
        r.read_nested_u8len(|r| {
            Ok(match addr_type {
                T_HOSTNAME => {
                    let h = r.take_rest();
                    Self::Hostname(h.into())
                }
                T_IPV4 => Self::Ipv4(r.extract()?),
                T_IPV6 => Self::Ipv6(r.extract()?),
                _ => return Err(Error::InvalidMessage("Invalid address type".into())),
            })
        })
    }
}

impl Writeable for Address {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        // Address type.
        w.write_u8(self.wire_addr_type());
        // Address length and data.
        let mut w = w.write_nested_u8len();

        match self {
            Address::Hostname(h) => {
                w.write_all(&h[..]);
            }
            Address::Ipv4(ip) => w.write(ip)?,
            Address::Ipv6(ip) => w.write(ip)?,
        }

        w.finish()
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(ipv4) = Ipv4Addr::from_str(s) {
            Ok(Self::Ipv4(ipv4))
        } else if let Ok(ipv6) = Ipv6Addr::from_str(s) {
            Ok(Self::Ipv6(ipv6))
        } else {
            if s.len() > MAX_HOSTNAME_LEN {
                return Err(Error::InvalidMessage("Hostname too long".into()));
            }
            if s.contains('\0') {
                return Err(Error::InvalidMessage("Nul byte not permitted".into()));
            }

            let mut addr = s.to_string();
            addr.make_ascii_lowercase();
            Ok(Self::Hostname(addr.into_bytes()))
        }
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Address::Ipv4(ip),
            IpAddr::V6(ip) => Address::Ipv6(ip),
        }
    }
}

/// A ConnectUdp message creates a new UDP data stream.
///
/// Upon receiving a ConnectUdp message, a relay tries to connect to the given address with the UDP
/// protocol if the exit policy permits.
///
/// If the exit decides to reject the message, or if the UDP connection fails, the exit should send
/// an End message.
///
/// Clients should reject these messages.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct ConnectUdp {
    /// Same as Begin flags.
    flags: msg::BeginFlags,
    /// Address to connect to. Can be Hostname, IPv4 or IPv6.
    addr: AddressPort,
}

impl ConnectUdp {
    /// Construct a new ConnectUdp cell
    pub fn new<F>(addr: &str, port: u16, flags: F) -> crate::Result<Self>
    where
        F: Into<msg::BeginFlags>,
    {
        Ok(Self {
            addr: (addr, port)
                .try_into()
                .map_err(|_| crate::Error::BadStreamAddress)?,
            flags: flags.into(),
        })
    }
}

impl msg::Body for ConnectUdp {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let flags = r.take_u32()?;
        let addr = r.extract()?;

        Ok(Self {
            flags: flags.into(),
            addr,
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_u32(self.flags.bits());
        w.write(&self.addr)?;
        Ok(())
    }
}

/// A ConnectedUdp cell sent in response to a ConnectUdp.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct ConnectedUdp {
    /// The address that the relay has bound locally of a ConnectUdp. Note
    /// that this might not be the relay address from the descriptor.
    our_address: AddressPort,
    /// The address that the stream is connected to.
    their_address: AddressPort,
}

impl ConnectedUdp {
    /// Construct a new ConnectedUdp cell.
    pub fn new(our_address: AddressPort, their_address: AddressPort) -> Result<Self> {
        Ok(Self {
            our_address,
            their_address,
        })
    }
}

impl msg::Body for ConnectedUdp {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let our_address: AddressPort = r.extract()?;
        if our_address.addr.is_hostname() {
            return Err(Error::InvalidMessage("Our address is a Hostname".into()));
        }
        let their_address: AddressPort = r.extract()?;
        if their_address.addr.is_hostname() {
            return Err(Error::InvalidMessage("Their address is a Hostname".into()));
        }

        Ok(Self {
            our_address,
            their_address,
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.our_address)?;
        w.write(&self.their_address)?;
        Ok(())
    }
}

/// A Datagram message represents data sent along a UDP stream.
///
/// Upon receiving a Datagram message for a live stream, the client or
/// exit sends that data onto the associated UDP connection.
///
/// These messages hold between 1 and [Datagram::MAXLEN] bytes of data each.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct Datagram {
    /// Contents of the cell, to be sent on a specific stream
    body: Vec<u8>,
}

impl Datagram {
    /// NOTE: Proposal 340, fragmented relay message, might change this value reality.
    /// The longest allowable body length for a single data cell.
    pub const MAXLEN: usize = CELL_DATA_LEN - 11;

    /// Construct a new data cell.
    ///
    /// Returns an error if `inp` is longer than [`Datagram::MAXLEN`] bytes.
    pub fn new(inp: &[u8]) -> crate::Result<Self> {
        if inp.len() > msg::Data::MAXLEN {
            return Err(crate::Error::CantEncode("Datagram too long"));
        }
        Ok(Self::new_unchecked(inp.into()))
    }

    /// Construct a new cell from a provided vector of bytes.
    ///
    /// The vector _must_ have fewer than [`Datagram::MAXLEN`] bytes.
    fn new_unchecked(body: Vec<u8>) -> Self {
        Self { body }
    }
}

impl From<Datagram> for Vec<u8> {
    fn from(data: Datagram) -> Vec<u8> {
        data.body
    }
}

impl AsRef<[u8]> for Datagram {
    fn as_ref(&self) -> &[u8] {
        &self.body[..]
    }
}

impl msg::Body for Datagram {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Datagram {
            body: r.take(r.remaining())?.into(),
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&self.body);
        Ok(())
    }
}
