//! Declare the TargetPort type.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A port that we want to connect to as a client.
///
/// Ordinarily, this is a TCP port, plus a flag to indicate whether we
/// must support IPv4 or IPv6.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Default,
)]
#[non_exhaustive]
pub struct TargetPort {
    /// True if this is a request to connect to an IPv6 address
    pub ipv6: bool,
    /// The port that the client wants to connect to
    pub port: u16,
}

impl TargetPort {
    /// Create a request to make sure that a circuit supports a given
    /// ipv4 exit port.
    pub fn ipv4(port: u16) -> TargetPort {
        TargetPort { ipv6: false, port }
    }

    /// Create a request to make sure that a circuit supports a given
    /// ipv6 exit port.
    pub fn ipv6(port: u16) -> TargetPort {
        TargetPort { ipv6: true, port }
    }

    /// Return true if this port is supported by the provided Relay.
    pub fn is_supported_by(&self, r: &tor_netdir::Relay<'_>) -> bool {
        if self.ipv6 {
            r.supports_exit_port_ipv6(self.port)
        } else {
            r.supports_exit_port_ipv4(self.port)
        }
    }
}

impl fmt::Display for TargetPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.port, if self.ipv6 { "v6" } else { "v4" })
    }
}
