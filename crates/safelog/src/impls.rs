//! Implement `Redactable` for various types.

use super::Redactable;
use std::fmt::{self, Formatter};

// Network types.

impl Redactable for std::net::Ipv4Addr {
    fn display_redacted(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.x.x.x", self.octets()[0])
    }
}

impl Redactable for std::net::Ipv6Addr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}:x:x:…", self.segments()[0])
    }
}

impl Redactable for std::net::IpAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            std::net::IpAddr::V4(v4) => v4.display_redacted(f),
            std::net::IpAddr::V6(v6) => v6.display_redacted(f),
        }
    }
}

impl Redactable for std::net::SocketAddrV4 {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip().redacted(), self.port())
    }
}

impl Redactable for std::net::SocketAddrV6 {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]:{}", self.ip().redacted(), self.port())
    }
}

impl Redactable for std::net::SocketAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            std::net::SocketAddr::V4(v4) => v4.display_redacted(f),
            std::net::SocketAddr::V6(v6) => v6.display_redacted(f),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use std::{
        net::{IpAddr, SocketAddr},
        str::FromStr,
    };

    use crate::Redactable;
    use serial_test::serial;

    #[test]
    #[serial]
    fn ip() {
        let r = |s| IpAddr::from_str(s).unwrap().redacted().to_string();

        assert_eq!(&r("127.0.0.1"), "127.x.x.x");
        assert_eq!(&r("::1"), "0:x:x:…");
        assert_eq!(&r("192.0.2.55"), "192.x.x.x");
        assert_eq!(&r("2001:db8::f00d"), "2001:x:x:…");
    }

    #[test]
    #[serial]
    fn sockaddr() {
        let r = |s| SocketAddr::from_str(s).unwrap().redacted().to_string();

        assert_eq!(&r("127.0.0.1:55"), "127.x.x.x:55");
        assert_eq!(&r("[::1]:443"), "[0:x:x:…]:443");
        assert_eq!(&r("192.0.2.55:80"), "192.x.x.x:80");
        assert_eq!(&r("[2001:db8::f00d]:9001"), "[2001:x:x:…]:9001");
    }
}
