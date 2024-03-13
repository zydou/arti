//! Structures that represent SOCKS messages

use crate::{Error, Result};

use caret::caret_int;
use std::fmt;
use std::net::IpAddr;

#[cfg(feature = "arbitrary")]
use std::net::Ipv6Addr;

use tor_error::bad_api_usage;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};

/// A supported SOCKS version.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[non_exhaustive]
pub enum SocksVersion {
    /// Socks v4.
    V4,
    /// Socks v5.
    V5,
}

impl TryFrom<u8> for SocksVersion {
    type Error = Error;
    fn try_from(v: u8) -> Result<SocksVersion> {
        match v {
            4 => Ok(SocksVersion::V4),
            5 => Ok(SocksVersion::V5),
            _ => Err(Error::BadProtocol(v)),
        }
    }
}

/// A completed SOCKS request, as negotiated on a SOCKS connection.
///
/// Once this request is done, we know where to connect.  Don't
/// discard this object immediately: Use it to report success or
/// failure.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct SocksRequest {
    /// Negotiated SOCKS protocol version.
    version: SocksVersion,
    /// The command requested by the SOCKS client.
    cmd: SocksCmd,
    /// The target address.
    addr: SocksAddr,
    /// The target port.
    port: u16,
    /// Authentication information.
    ///
    /// (Tor doesn't believe in SOCKS authentication, since it cannot
    /// possibly secure.  Instead, we use it for circuit isolation.)
    auth: SocksAuth,
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SocksRequest {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let version = SocksVersion::arbitrary(u)?;
        let cmd = SocksCmd::arbitrary(u)?;
        let addr = SocksAddr::arbitrary(u)?;
        let port = u16::arbitrary(u)?;
        let auth = SocksAuth::arbitrary(u)?;

        SocksRequest::new(version, cmd, addr, port, auth)
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

/// An address sent or received as part of a SOCKS handshake
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum SocksAddr {
    /// A regular DNS hostname.
    Hostname(SocksHostname),
    /// An IP address.  (Tor doesn't like to receive these during SOCKS
    /// handshakes, since they usually indicate that the hostname lookup
    /// happened somewhere else.)
    Ip(IpAddr),
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SocksAddr {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        use std::net::Ipv4Addr;
        let b = u8::arbitrary(u)?;
        Ok(match b % 3 {
            0 => SocksAddr::Hostname(SocksHostname::arbitrary(u)?),
            1 => SocksAddr::Ip(IpAddr::V4(Ipv4Addr::arbitrary(u)?)),
            _ => SocksAddr::Ip(IpAddr::V6(Ipv6Addr::arbitrary(u)?)),
        })
    }
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (1, Some(256))
    }
}

/// A hostname for use with SOCKS.  It is limited in length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksHostname(String);

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for SocksHostname {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        String::arbitrary(u)?
            .try_into()
            .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
    fn size_hint(_depth: usize) -> (usize, Option<usize>) {
        (0, Some(255))
    }
}

/// Provided authentication from a SOCKS handshake
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[non_exhaustive]
pub enum SocksAuth {
    /// No authentication was provided
    NoAuth,
    /// Socks4 authentication (a string) was provided.
    Socks4(Vec<u8>),
    /// Socks5 username/password authentication was provided.
    Username(Vec<u8>, Vec<u8>),
}

caret_int! {
    /// Command from the socks client telling us what to do.
    #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
    pub struct SocksCmd(u8) {
        /// Connect to a remote TCP address:port.
        CONNECT = 1,
        /// Not supported in Tor.
        BIND = 2,
        /// Not supported in Tor.
        UDP_ASSOCIATE = 3,

        /// Lookup a hostname, return an IP address. (Tor only.)
        RESOLVE = 0xF0,
        /// Lookup an IP address, return a hostname. (Tor only.)
        RESOLVE_PTR = 0xF1,
    }
}

caret_int! {
    /// Possible reply status values from a SOCKS5 handshake.
    ///
    /// Note that the documentation for these values is kind of scant,
    /// and is limited to what the RFC says.  Note also that SOCKS4
    /// only represents success and failure.
    #[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
    pub struct SocksStatus(u8) {
        /// RFC 1928: "succeeded"
        SUCCEEDED = 0x00,
        /// RFC 1928: "general SOCKS server failure"
        GENERAL_FAILURE = 0x01,
        /// RFC 1928: "connection not allowable by ruleset"
        ///
        /// (This is the only occurrence of 'ruleset' or even 'rule'
        /// in RFC 1928.)
        NOT_ALLOWED = 0x02,
        /// RFC 1928: "Network unreachable"
        NETWORK_UNREACHABLE = 0x03,
        /// RFC 1928: "Host unreachable"
        HOST_UNREACHABLE = 0x04,
        /// RFC 1928: "Connection refused"
        CONNECTION_REFUSED = 0x05,
        /// RFC 1928: "TTL expired"
        ///
        /// (This is the only occurrence of 'TTL' in RFC 1928.)
        TTL_EXPIRED = 0x06,
        /// RFC 1929: "Command not supported"
        COMMAND_NOT_SUPPORTED = 0x07,
        /// RFC 1929: "Address type not supported"
        ADDRTYPE_NOT_SUPPORTED = 0x08,
        /// Prop304: "Onion Service Descriptor Can Not be Found"
        HS_DESC_NOT_FOUND = 0xF0,
        /// Prop304: "Onion Service Descriptor Is Invalid"
        HS_DESC_INVALID = 0xF1,
        /// Prop304: "Onion Service Introduction Failed"
        HS_INTRO_FAILED = 0xF2,
        /// Prop304: "Onion Service Rendezvous Failed"
        HS_REND_FAILED = 0xF3,
        /// Prop304: "Onion Service Missing Client Authorization"
        HS_MISSING_CLIENT_AUTH = 0xF4,
        /// Prop304: "Onion Service Wrong Client Authorization"
        HS_WRONG_CLIENT_AUTH = 0xF5,
        /// "Onion service address is invalid"
        ///
        /// (Documented in `tor.1` but not yet specified.)
        HS_BAD_ADDRESS = 0xF6,
        /// "Onion Service Introduction Timed Out"
        ///
        /// (Documented in `tor.1` but not yet specified.)
        HS_INTRO_TIMEOUT = 0xF7
    }
}

impl SocksCmd {
    /// Return true if this is a supported command.
    fn recognized(self) -> bool {
        matches!(
            self,
            SocksCmd::CONNECT | SocksCmd::RESOLVE | SocksCmd::RESOLVE_PTR
        )
    }

    /// Return true if this is a command for which we require a port.
    fn requires_port(self) -> bool {
        matches!(
            self,
            SocksCmd::CONNECT | SocksCmd::BIND | SocksCmd::UDP_ASSOCIATE
        )
    }
}

impl SocksStatus {
    /// Convert this status into a value for use with SOCKS4 or SOCKS4a.
    #[cfg(feature = "proxy-handshake")]
    pub(crate) fn into_socks4_status(self) -> u8 {
        match self {
            SocksStatus::SUCCEEDED => 0x5A,
            _ => 0x5B,
        }
    }
    /// Create a status from a SOCKS4 or SOCKS4a reply code.
    #[cfg(feature = "client-handshake")]
    pub(crate) fn from_socks4_status(status: u8) -> Self {
        match status {
            0x5A => SocksStatus::SUCCEEDED,
            0x5B => SocksStatus::GENERAL_FAILURE,
            0x5C | 0x5D => SocksStatus::NOT_ALLOWED,
            _ => SocksStatus::GENERAL_FAILURE,
        }
    }
}

impl TryFrom<String> for SocksHostname {
    type Error = Error;
    fn try_from(s: String) -> Result<SocksHostname> {
        if s.len() > 255 {
            // This is only a limitation for Socks 5, but we enforce it in both
            // cases, for simplicity.
            Err(bad_api_usage!("hostname too long").into())
        } else if contains_zeros(s.as_bytes()) {
            // This is only a limitation for Socks 4, but we enforce it in both
            // cases, for simplicity.
            Err(Error::Syntax)
        } else {
            Ok(SocksHostname(s))
        }
    }
}

impl AsRef<str> for SocksHostname {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl SocksAuth {
    /// Check whether this authentication is well-formed and compatible with the
    /// provided SOCKS version.
    ///
    /// Return an error if not.
    fn validate(&self, version: SocksVersion) -> Result<()> {
        match self {
            SocksAuth::NoAuth => {}
            SocksAuth::Socks4(data) => {
                if version != SocksVersion::V4 || contains_zeros(data) {
                    return Err(Error::Syntax);
                }
            }
            SocksAuth::Username(user, pass) => {
                if version != SocksVersion::V5
                    || user.len() > u8::MAX as usize
                    || pass.len() > u8::MAX as usize
                {
                    return Err(Error::Syntax);
                }
            }
        }
        Ok(())
    }
}

/// Return true if b contains at least one zero.
///
/// Try to run in constant time.
fn contains_zeros(b: &[u8]) -> bool {
    use subtle::{Choice, ConstantTimeEq};
    let c: Choice = b
        .iter()
        .fold(Choice::from(0), |seen_any, byte| seen_any | byte.ct_eq(&0));
    c.unwrap_u8() != 0
}

impl SocksRequest {
    /// Create a SocksRequest with a given set of fields.
    ///
    /// Return an error if the inputs aren't supported or valid.
    pub fn new(
        version: SocksVersion,
        cmd: SocksCmd,
        addr: SocksAddr,
        port: u16,
        auth: SocksAuth,
    ) -> Result<Self> {
        if !cmd.recognized() {
            return Err(Error::NotImplemented(
                format!("SOCKS command {}", cmd).into(),
            ));
        }
        if port == 0 && cmd.requires_port() {
            return Err(Error::Syntax);
        }
        auth.validate(version)?;

        Ok(SocksRequest {
            version,
            cmd,
            addr,
            port,
            auth,
        })
    }

    /// Return the negotiated version (4 or 5).
    pub fn version(&self) -> SocksVersion {
        self.version
    }

    /// Return the command that the client requested.
    pub fn command(&self) -> SocksCmd {
        self.cmd
    }

    /// Return the 'authentication' information from this request.
    pub fn auth(&self) -> &SocksAuth {
        &self.auth
    }

    /// Return the requested port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return the requested address.
    pub fn addr(&self) -> &SocksAddr {
        &self.addr
    }
}

impl fmt::Display for SocksAddr {
    /// Format a string (a hostname or IP address) corresponding to this
    /// SocksAddr.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocksAddr::Ip(a) => write!(f, "{}", a),
            SocksAddr::Hostname(h) => write!(f, "{}", h.0),
        }
    }
}

/// The reply from a SOCKS proxy.
#[derive(Debug, Clone)]
pub struct SocksReply {
    /// The provided status code
    status: SocksStatus,
    /// The provided address, if any.
    addr: SocksAddr,
    /// The provided port.
    port: u16,
}

impl SocksReply {
    /// Create a new SocksReply.
    #[cfg(feature = "client-handshake")]
    pub(crate) fn new(status: SocksStatus, addr: SocksAddr, port: u16) -> Self {
        Self { status, addr, port }
    }

    /// Return the status code from this socks reply.
    pub fn status(&self) -> SocksStatus {
        self.status
    }

    /// Return the address from this socks reply.
    ///
    /// The semantics of this address depend on the original socks command
    /// provided; see the SOCKS specification for more information.
    ///
    /// Note that some implementations (including Tor) will return `0.0.0.0` or
    /// `[::]` to indicate "no address given".
    pub fn addr(&self) -> &SocksAddr {
        &self.addr
    }

    /// Return the address from this socks reply.
    ///
    /// The semantics of this port depend on the original socks command
    /// provided; see the SOCKS specification for more information.
    pub fn port(&self) -> u16 {
        self.port
    }
}

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
    fn display_sa() {
        let a = SocksAddr::Ip(IpAddr::V4("127.0.0.1".parse().unwrap()));
        assert_eq!(a.to_string(), "127.0.0.1");

        let a = SocksAddr::Ip(IpAddr::V6("f00::9999".parse().unwrap()));
        assert_eq!(a.to_string(), "f00::9999");

        let a = SocksAddr::Hostname("www.torproject.org".to_string().try_into().unwrap());
        assert_eq!(a.to_string(), "www.torproject.org");
    }

    #[test]
    fn ok_request() {
        let localhost_v4 = SocksAddr::Ip(IpAddr::V4("127.0.0.1".parse().unwrap()));
        let r = SocksRequest::new(
            SocksVersion::V4,
            SocksCmd::CONNECT,
            localhost_v4.clone(),
            1024,
            SocksAuth::NoAuth,
        )
        .unwrap();
        assert_eq!(r.version(), SocksVersion::V4);
        assert_eq!(r.command(), SocksCmd::CONNECT);
        assert_eq!(r.addr(), &localhost_v4);
        assert_eq!(r.auth(), &SocksAuth::NoAuth);
    }

    #[test]
    fn bad_request() {
        let localhost_v4 = SocksAddr::Ip(IpAddr::V4("127.0.0.1".parse().unwrap()));

        let e = SocksRequest::new(
            SocksVersion::V4,
            SocksCmd::BIND,
            localhost_v4.clone(),
            1024,
            SocksAuth::NoAuth,
        );
        assert!(matches!(e, Err(Error::NotImplemented(_))));

        let e = SocksRequest::new(
            SocksVersion::V4,
            SocksCmd::CONNECT,
            localhost_v4,
            0,
            SocksAuth::NoAuth,
        );
        assert!(matches!(e, Err(Error::Syntax)));
    }

    #[test]
    fn test_contains_zeros() {
        assert!(contains_zeros(b"Hello\0world"));
        assert!(!contains_zeros(b"Hello world"));
    }
}
