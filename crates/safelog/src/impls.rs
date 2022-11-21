//! Implement `Redactable` for various types.

use super::Redactable;
use std::fmt::{self, Formatter};

// Network types.

impl Redactable for std::net::Ipv4Addr {
    fn display_redacted(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.x.x.x", self.octets()[0])
    }

    fn debug_redacted(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.display_redacted(f)
    }
}

impl Redactable for std::net::Ipv6Addr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}:x:x:…", self.segments()[0])
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
}

impl Redactable for std::net::IpAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            std::net::IpAddr::V4(v4) => v4.display_redacted(f),
            std::net::IpAddr::V6(v6) => v6.display_redacted(f),
        }
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
}

impl Redactable for std::net::SocketAddrV4 {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip().redacted(), self.port())
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
}

impl Redactable for std::net::SocketAddrV6 {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]:{}", self.ip().redacted(), self.port())
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
}

impl Redactable for std::net::SocketAddr {
    fn display_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            std::net::SocketAddr::V4(v4) => v4.display_redacted(f),
            std::net::SocketAddr::V6(v6) => v6.display_redacted(f),
        }
    }

    fn debug_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display_redacted(f)
    }
}
