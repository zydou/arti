//! Configuration logic for onion service reverse proxy.

use std::{net::SocketAddr, path::PathBuf};

/// Configuration for a reverse proxy running for a single onion service.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// A list of rules to apply to incoming requests.  If no rule
    /// matches, we take the DestroyCircuit action.
    proxy_ports: Vec<ProxyRule>,
}

/// A single rule in a `ProxyConfig`.
///
/// Rules take the form of, "When this pattern matches, take this action."
#[derive(Clone, Debug)]
pub struct ProxyRule {
    /// Any connections to a port matching this pattern match this rule.
    source: ProxyPattern,
    /// When this rule matches, we take this action.
    target: ProxyTarget,
}

/// A set of ports to use when checking how to handle a port.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ProxyPattern {
    /// Match a single port.
    Port(u16),
    /// Match an inclusive range of ports.
    PortRange(u16, u16),
    /// Match all ports.
    AllPorts,
}

/// An action to take upon receiving an incoming request.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ProxyTarget {
    /// Close the circuit immediately with an error.
    DestroyCircuit,
    /// Open a TCP connection to a given address and port.
    Tcp(SocketAddr),
    /// Open an AF_UNIX connection to a given address.
    Unix(PathBuf),
    /// Close the stream immediately with an error.
    RejectStream,
    /// Ignore the stream request.
    DropStream,
}
