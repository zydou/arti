//! Types and traits for converting objects to addresses which
//! Tor can connect to.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use thiserror::Error;

// ----------------------------------------------------------------------

/// An object that can be converted to a [`TorAddr`] with a minimum
/// of risk.
pub trait IntoTorAddr {
    /// Try to make a [`TorAddr`] to represent connecting to this
    /// address.
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError>;
}

/// An object that can be converted to a [`TorAddr`], but which it
/// might be risky to get in the first place if you're hoping for
/// anonymity.
///
/// For example, you can use this trait to convert a [`SocketAddr`]
/// into a [`TorAddr`], and it's safe to do that conversion.  But
/// where did you get the [`SocketAddr`] in the first place?  If it
/// comes from a local DNS lookup, then you have leaked the address
/// you were resolving to your DNS resolver, and probably your ISP.
pub trait DangerouslyIntoTorAddr {
    /// Try to make a [`TorAddr`] to represent connecting to this
    /// address.
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError>;
}

/// An address object that you can connect to over the Tor network.
///
/// When you're making a connection with Tor, you shouldn't do your DNS
/// lookups locally: that would leak your target address to your DNS server.
/// Instead, it's better to use a combination of a hostname and a port
/// directly.
///
/// The preferred way to create a `TorAddr` is via the [`IntoTorAddr`] trait,
/// using a hostname and a port (or a string containing a hostname and a
/// port).  It's also okay to use an IP and Port there, but only if they come
/// from some source _other than_ a local DNS lookup.
///
/// In order to discourage local hostname lookups, the functions that
/// construct a [`TorAddr`] from [`IpAddr`], [`SocketAddr`], and so
/// forth are labeled as "dangerous".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TorAddr {
    /// The target host.
    host: Host,
    /// The target port number.
    // TODO: reject port 0.
    port: u16,
}

impl TorAddr {
    /// Construct a `TorAddr` from any object that implements
    /// [`IntoTorAddr`].
    pub fn from<A: IntoTorAddr>(addr: A) -> Result<Self, TorAddrError> {
        addr.into_tor_addr()
    }
    /// Construct a `TorAddr` from any object that implements
    /// [`DangerouslyIntoTorAddr`].
    ///
    /// See [`DangerouslyIntoTorAddr`] for an explanation of why the
    /// style of programming supported by this function is dangerous
    /// to use.
    pub fn dangerously_from<A: DangerouslyIntoTorAddr>(addr: A) -> Result<Self, TorAddrError> {
        addr.into_tor_addr_dangerously()
    }

    /// Return true if this is an IP address (rather than a hostname).
    pub fn is_ip_address(&self) -> bool {
        matches!(&self.host, Host::Ip(_))
    }

    /// Extract a `String`-based hostname and a `u16` port from this
    /// address.
    pub(crate) fn into_string_and_port(self) -> (String, u16) {
        let host = self.host.to_string();
        let port = self.port;
        (host, port)
    }
}

impl std::fmt::Display for TorAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.host {
            Host::Ip(IpAddr::V6(addr)) => write!(f, "[{}]:{}", addr, self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// An error created while making or using a [`TorAddr`].
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum TorAddrError {
    /// Tried to parse a string that can never be interpreted as a valid host.
    #[error("String can never be a valid hostname")]
    InvalidHostname,
    /// Tried to parse a string as an `address:port`, but it had no port.
    #[error("No port found in string")]
    NoPort,
    /// Tried to parse a port that wasn't a valid `u16`.
    #[error("Could not parse port")]
    BadPort,
}

/// A host that Tor can connect to: either a hostname or an IP address.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Host {
    /// A hostname.  This variant should never be used if the `Ip`
    /// variant could be used instead.
    Hostname(String),
    /// An IP address.
    Ip(IpAddr),
}

impl FromStr for Host {
    type Err = TorAddrError;
    fn from_str(s: &str) -> Result<Host, TorAddrError> {
        if let Ok(ip_addr) = s.parse() {
            Ok(Host::Ip(ip_addr))
        } else {
            // XXXX: reject bad hostnames.
            Ok(Host::Hostname(s.to_owned()))
        }
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Host::Hostname(s) => write!(f, "{}", s),
            Host::Ip(ip) => write!(f, "{}", ip),
        }
    }
}

impl IntoTorAddr for TorAddr {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        Ok(self)
    }
}

impl<A: IntoTorAddr + Clone> IntoTorAddr for &A {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        self.clone().into_tor_addr()
    }
}

impl IntoTorAddr for &str {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        if let Ok(sa) = SocketAddr::from_str(self) {
            Ok(TorAddr {
                host: Host::Ip(sa.ip()),
                port: sa.port(),
            })
        } else {
            let (host, port) = self.rsplit_once(':').ok_or(TorAddrError::NoPort)?;
            let host = host.parse()?;
            let port = port.parse().map_err(|_| TorAddrError::BadPort)?;
            Ok(TorAddr { host, port })
        }
    }
}

impl IntoTorAddr for String {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        self[..].into_tor_addr()
    }
}

impl IntoTorAddr for (&str, u16) {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        let (host, port) = self;
        let host = host.parse()?;
        Ok(TorAddr { host, port })
    }
}

impl IntoTorAddr for (String, u16) {
    fn into_tor_addr(self) -> Result<TorAddr, TorAddrError> {
        let (host, port) = self;
        (&host[..], port).into_tor_addr()
    }
}

impl<T: DangerouslyIntoTorAddr + Clone> DangerouslyIntoTorAddr for &T {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        self.clone().into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for (IpAddr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        Ok(TorAddr {
            host: Host::Ip(addr),
            port,
        })
    }
}

impl DangerouslyIntoTorAddr for (Ipv4Addr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        Ok(TorAddr {
            host: Host::Ip(addr.into()),
            port,
        })
    }
}

impl DangerouslyIntoTorAddr for (Ipv6Addr, u16) {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = self;
        Ok(TorAddr {
            host: Host::Ip(addr.into()),
            port,
        })
    }
}

impl DangerouslyIntoTorAddr for SocketAddr {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (addr, port).into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for SocketAddrV4 {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (*addr, port).into_tor_addr_dangerously()
    }
}

impl DangerouslyIntoTorAddr for SocketAddrV6 {
    fn into_tor_addr_dangerously(self) -> Result<TorAddr, TorAddrError> {
        let (addr, port) = (self.ip(), self.port());
        (*addr, port).into_tor_addr_dangerously()
    }
}
