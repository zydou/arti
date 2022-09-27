//! Implement the socks handshakes.

#[cfg(feature = "client-handshake")]
pub(crate) mod client;
#[cfg(feature = "proxy-handshake")]
pub(crate) mod proxy;

use crate::msg::SocksAddr;
use std::net::IpAddr;
use tor_bytes::Result as BytesResult;
use tor_bytes::{EncodeResult, Error as BytesError, Readable, Reader, Writeable, Writer};

/// Constant for Username/Password-style authentication.
/// (See RFC 1929)
const USERNAME_PASSWORD: u8 = 0x02;
/// Constant for "no authentication".
const NO_AUTHENTICATION: u8 = 0x00;

/// An action to take in response to a SOCKS handshake message.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Action {
    /// If nonzero, this many bytes should be drained from the
    /// client's inputs.
    pub drain: usize,
    /// If nonempty, this reply should be sent to the other party.
    pub reply: Vec<u8>,
    /// If true, then this handshake is over, either successfully or not.
    pub finished: bool,
}

impl Readable for SocksAddr {
    fn take_from(r: &mut Reader<'_>) -> BytesResult<SocksAddr> {
        let atype = r.take_u8()?;
        match atype {
            1 => {
                let ip4: std::net::Ipv4Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip4.into()))
            }
            3 => {
                let hlen = r.take_u8()?;
                let hostname = r.take(hlen as usize)?;
                let hostname = std::str::from_utf8(hostname)
                    .map_err(|_| BytesError::BadMessage("bad utf8 on hostname"))?
                    .to_string();
                let hostname = hostname
                    .try_into()
                    .map_err(|_| BytesError::BadMessage("hostname too long"))?;
                Ok(SocksAddr::Hostname(hostname))
            }
            4 => {
                let ip6: std::net::Ipv6Addr = r.extract()?;
                Ok(SocksAddr::Ip(ip6.into()))
            }
            _ => Err(BytesError::BadMessage("unrecognized address type.")),
        }
    }
}

impl Writeable for SocksAddr {
    fn write_onto<W: Writer + ?Sized>(&self, w: &mut W) -> EncodeResult<()> {
        match self {
            SocksAddr::Ip(IpAddr::V4(ip)) => {
                w.write_u8(1);
                w.write(ip)?;
            }
            SocksAddr::Ip(IpAddr::V6(ip)) => {
                w.write_u8(4);
                w.write(ip)?;
            }
            SocksAddr::Hostname(h) => {
                let h = h.as_ref();
                assert!(h.len() < 256);
                let hlen = h.len() as u8;
                w.write_u8(3);
                w.write_u8(hlen);
                w.write(h.as_bytes())?;
            }
        }
        Ok(())
    }
}
