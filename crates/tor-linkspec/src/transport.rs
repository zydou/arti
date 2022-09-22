//! Support for identifying a particular transport.
//!
//! A "transport" is a mechanism to connect to a relay on the Tor network and
//! make a `Channel`. Currently, two types of transports exist: the "built-in"
//! transport, which uses TLS over TCP, and various anti-censorship transports,
//! which use TLS over other protocols to avoid detection by censors.

/// Identify a type of Transport.
///
/// If this crate is compiled with the `pt-client` feature, this type can
/// support pluggable transports; otherwise, only the built-in transport type is
/// supported.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct TransportId(Inner);

/// Helper type to implement [`TransportId`].
///
/// This is a separate type so that TransportId can be opaque.
#[derive(Debug, Clone, Eq, PartialEq, Hash, educe::Educe)]
#[educe(Default)]
enum Inner {
    /// The built-in transport type.
    #[educe(Default)]
    BuiltIn,

    /// A pluggable transport type, specified by its name.
    #[cfg(feature = "pt-client")]
    Pluggable(String),
}

/// This identifier is used to indicate the built-in transport.
const BUILT_IN_ID: &str = "<none>";

impl std::str::FromStr for TransportId {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == BUILT_IN_ID {
            return Ok(TransportId(Inner::BuiltIn));
        };

        #[cfg(feature = "pt-client")]
        if is_well_formed_id(s) {
            Ok(TransportId(Inner::Pluggable(s.to_string())))
        } else {
            Err(TransportIdError::BadId(s.to_string()))
        }

        #[cfg(not(feature = "pt-client"))]
        Err(TransportIdError::NoSupport)
    }
}

impl std::fmt::Display for TransportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Inner::BuiltIn => write!(f, "{}", BUILT_IN_ID),
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(name) => write!(f, "{}", name),
        }
    }
}

/// Return true if `s` is a well-formed transport ID.
///
/// According to the specification, a well-formed transport ID follows the same
/// rules as a C99 identifier: It must follow the regular expression
/// `[a-zA-Z_][a-zA-Z0-9_]*`.
#[cfg(feature = "pt-client")]
fn is_well_formed_id(s: &str) -> bool {
    // It's okay to use a bytes iterator, since non-ascii strings are not
    // allowed.
    let mut bytes = s.bytes();

    if let Some(first) = bytes.next() {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    }
}

/// An error related to parsing a TransportId.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportIdError {
    /// Arti was compiled without client-side pluggable transport support, and
    /// we tried to use a pluggable transport.
    #[error("Not compiled with pluggable transport support")]
    NoSupport,

    /// Tried to parse a pluggable transport whose name was not well-formed.
    #[error("{0:?} is not a valid pluggable transport ID.")]
    BadId(String),
}

impl TransportId {
    /// Return true if this is the built-in transport.
    pub fn is_builtin(&self) -> bool {
        self.0 == Inner::BuiltIn
    }
}

/// This identifier is used to indicate no transport address.
const NONE_ADDR: &str = "<none>";

/// An address that an be passed to a transport to tell it where to
/// connect (typically, to a bridge).
///
/// Not every transport accepts all kinds of addresses.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportTargetAddr {
    /// An IP address and port for a Tor relay.
    ///
    /// This is the only address type supported by the BuiltIn transport.
    IpPort(std::net::SocketAddr),
    /// A hostname-and-port target address.  Some transports may support this.
    #[cfg(feature = "pt-client")]
    HostPort(String, u16),
    /// A completely absent target address.  Some transports support this.
    #[cfg(feature = "pt-client")]
    None,
}

/// An error from parsing a [`TransportTargetAddr`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportAddrError {
    /// We were compiled without support for addresses of this type.
    #[error("Not compiled with pluggable transport support.")]
    NoSupport,
    /// We cannot parse this address.
    #[error("Cannot parse {0:?} as an address.")]
    BadAddress(String),
}

#[allow(clippy::unnecessary_wraps)]
impl TransportTargetAddr {
    /// Helper: Construct a `HostPort` instance or return a `NoSupport` error.
    #[cfg(feature = "pt-client")]
    fn host_port(host: &str, port: u16) -> Result<Self, TransportAddrError> {
        Ok(TransportTargetAddr::HostPort(host.to_string(), port))
    }

    /// Helper: Construct a `None` instance or return a `NoSupport` error.
    #[cfg(feature = "pt-client")]
    fn none() -> Result<Self, TransportAddrError> {
        Ok(TransportTargetAddr::None)
    }

    /// Helper: Construct a `HostPort` instance or return a `NoSupport` error.
    #[cfg(not(feature = "pt-client"))]
    fn host_port(_host: &str, _port: u16) -> Result<Self, TransportAddrError> {
        Err(TransportAddrError::NoSupport)
    }

    /// Helper: Construct a `None` instance or return a `NoSupport` error.
    #[cfg(not(feature = "pt-client"))]
    fn none() -> Result<Self, TransportAddrError> {
        Err(TransportAddrError::NoSupport)
    }
}

impl std::str::FromStr for TransportTargetAddr {
    type Err = TransportAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse() {
            Ok(TransportTargetAddr::IpPort(addr))
        } else if let Some((name, port)) = s.rsplit_once(':') {
            let port = port
                .parse()
                .map_err(|_| TransportAddrError::BadAddress(s.to_string()))?;

            Self::host_port(name, port)
        } else if s == NONE_ADDR {
            Self::none()
        } else {
            Err(TransportAddrError::BadAddress(s.to_string()))
        }
    }
}

impl std::fmt::Display for TransportTargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportTargetAddr::IpPort(addr) => write!(f, "{}", addr),
            #[cfg(feature = "pt-client")]
            TransportTargetAddr::HostPort(host, port) => write!(f, "{}:{}", host, port),
            #[cfg(feature = "pt-client")]
            TransportTargetAddr::None => write!(f, "{}", NONE_ADDR),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::str::FromStr;

    #[test]
    fn builtin() {
        assert!(TransportId::default().is_builtin());
        assert_eq!(
            TransportId::default(),
            "<none>".parse().expect("Couldn't parse default ID")
        );
    }

    #[test]
    #[cfg(not(feature = "pt-client"))]
    fn nosupport() {
        // We should get this error whenever we parse a non-default PT and we have no PT support.
        assert!(matches!(
            TransportId::from_str("obfs4"),
            Err(TransportIdError::NoSupport)
        ));
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn wellformed() {
        for id in &["snowflake", "obfs4", "_ohai", "Z", "future_WORK2"] {
            assert!(is_well_formed_id(id));
        }

        for id in &[" ", "Mölm", "12345", ""] {
            assert!(!is_well_formed_id(id));
        }
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn parsing() {
        let obfs = TransportId::from_str("obfs4").unwrap();
        let dflt = TransportId::default();
        let dflt2 = TransportId::from_str("<none>").unwrap();
        let snow = TransportId::from_str("snowflake").unwrap();
        let obfs_again = TransportId::from_str("obfs4").unwrap();

        assert_eq!(obfs, obfs_again);
        assert_eq!(dflt, dflt2);
        assert_ne!(snow, obfs);
        assert_ne!(snow, dflt);

        assert!(matches!(
            TransportId::from_str("12345"),
            Err(TransportIdError::BadId(_))
        ));
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn addr() {
        for addr in &["1.2.3.4:555", "[::1]:9999"] {
            let a: TransportTargetAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);
        }

        for addr in &["www.example.com:9100", "<none>"] {
            if cfg!(feature = "pt-client") {
                let a: TransportTargetAddr = addr.parse().unwrap();
                assert_eq!(&a.to_string(), addr);
            } else {
                let e = TransportTargetAddr::from_str(addr).unwrap_err();
                assert!(matches!(e, TransportAddrError::NoSupport));
            }
        }

        for addr in &["foobar", "<<<>>>"] {
            let e = TransportTargetAddr::from_str(addr).unwrap_err();
            assert!(matches!(e, TransportAddrError::BadAddress(_)));
        }
    }
}
