//! Configuration for a channel manager (and, therefore, channels)
//!
//! # Semver note
//!
//! Most types in this module are re-exported by `arti-client`.

use std::net::SocketAddr;

use tor_config::impl_standard_builder;
use tor_config::{ConfigBuildError, PaddingLevel};
use tor_socksproto::SocksAuth;
use tor_socksproto::SocksVersion;

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

/// Error parsing a proxy URI string
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyProtocolParseError {
    #[error("unsupported or missing proxy scheme: {0}")]
    UnsupportedScheme(String),
    #[error("invalid proxy address: {0}")]
    InvalidAddress(String),
    #[error("missing or invalid port")]
    InvalidPort,
    #[error("invalid proxy URI format: {0}")]
    InvalidFormat(String),
}

/// Information about what proxy protocol to use, and how to use it.
///
/// This type can be parsed from a URI-like string:
/// - `socks4://host:port` - SOCKS4 proxy
/// - `socks4a://host:port` - SOCKS4a proxy (same as socks4)
/// - `socks5://host:port` - SOCKS5 proxy without auth
/// - `socks5://user:pass@host:port` - SOCKS5 proxy with username/password auth
#[derive(
    Debug, Clone, Eq, PartialEq, serde_with::DeserializeFromStr, serde_with::SerializeDisplay,
)]
#[non_exhaustive]
pub enum ProxyProtocol {
    /// Connect via SOCKS 4, SOCKS 4a, or SOCKS 5.
    Socks {
        /// The SOCKS version to use
        version: SocksVersion,
        /// The authentication method to use
        auth: SocksAuth,
        /// The proxy server address
        addr: SocketAddr,
    },
}

impl std::str::FromStr for ProxyProtocol {
    type Err = ProxyProtocolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse URI: scheme://[user:pass@]host:port
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| ProxyProtocolParseError::InvalidFormat(s.to_string()))?;

        let scheme_lower = scheme.to_ascii_lowercase();
        let version = match scheme_lower.as_str() {
            "socks4" | "socks4a" => SocksVersion::V4,
            "socks5" => SocksVersion::V5,
            _ => {
                return Err(ProxyProtocolParseError::UnsupportedScheme(
                    scheme.to_string(),
                ));
            }
        };

        // Check for authentication credentials (user:pass@host:port)
        let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
            let creds = &rest[..at_pos];
            let addr_part = &rest[at_pos + 1..];

            let (user, pass) = creds.split_once(':').ok_or_else(|| {
                ProxyProtocolParseError::InvalidFormat(
                    "credentials must be in user:pass format".to_string(),
                )
            })?;

            // SOCKS4 uses Socks4 auth with user ID, SOCKS5 uses Username auth
            let auth = match version {
                SocksVersion::V4 => SocksAuth::Socks4(user.as_bytes().to_vec()),
                SocksVersion::V5 => {
                    SocksAuth::Username(user.as_bytes().to_vec(), pass.as_bytes().to_vec())
                }
                // Handle potential future SOCKS versions
                _ => SocksAuth::NoAuth,
            };
            (auth, addr_part)
        } else {
            (SocksAuth::NoAuth, rest)
        };

        // Parse the address. Handle IPv6 addresses in brackets: [::1]:port
        let addr = if host_port.starts_with('[') {
            // IPv6 address in brackets
            host_port
                .parse::<SocketAddr>()
                .map_err(|_| ProxyProtocolParseError::InvalidAddress(host_port.to_string()))?
        } else {
            // IPv4 or hostname:port - try direct parse first
            host_port
                .parse::<SocketAddr>()
                .map_err(|_| ProxyProtocolParseError::InvalidAddress(host_port.to_string()))?
        };

        Ok(ProxyProtocol::Socks {
            version,
            auth,
            addr,
        })
    }
}

impl std::fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                let scheme = match version {
                    SocksVersion::V4 => "socks4",
                    SocksVersion::V5 => "socks5",
                    // Handle potential future SOCKS versions
                    _ => "socks5",
                };

                match auth {
                    SocksAuth::NoAuth => write!(f, "{}://{}", scheme, addr),
                    SocksAuth::Socks4(user_id) => {
                        // Best effort: try to display user ID as UTF-8
                        let user = String::from_utf8_lossy(user_id);
                        write!(f, "{}://{}@{}", scheme, user, addr)
                    }
                    SocksAuth::Username(user, pass) => {
                        let user = String::from_utf8_lossy(user);
                        let pass = String::from_utf8_lossy(pass);
                        write!(f, "{}://{}:{}@{}", scheme, user, pass, addr)
                    }
                    // Handle potential future auth types
                    _ => write!(f, "{}://{}", scheme, addr),
                }
            }
        }
    }
}

impl ProxyProtocol {
    /// Create a new SOCKS proxy configuration with no authentication
    pub fn socks_no_auth(version: SocksVersion, addr: SocketAddr) -> Self {
        ProxyProtocol::Socks {
            version,
            auth: SocksAuth::NoAuth,
            addr,
        }
    }
}

/// Channel configuration
///
/// This type is immutable once constructed.  To build one, use
/// [`ChannelConfigBuilder`], or deserialize it from a string.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ChannelConfig {
    /// Control of channel padding
    #[builder(default)]
    pub(crate) padding: PaddingLevel,
    /// Outbound proxy to use for all direct connections
    #[builder(default)]
    pub(crate) outbound_proxy: Option<ProxyProtocol>,
}
impl_standard_builder! { ChannelConfig }

#[cfg(feature = "testing")]
impl ChannelConfig {
    /// The padding level (accessor for testing)
    pub fn padding(&self) -> PaddingLevel {
        self.padding
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn channel_config() {
        let config = ChannelConfig::default();

        assert_eq!(PaddingLevel::Normal, config.padding);
    }

    #[test]
    fn proxy_protocol_parse_socks5_basic() {
        let p: ProxyProtocol = "socks5://127.0.0.1:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                assert_eq!(version, SocksVersion::V5);
                assert_eq!(auth, SocksAuth::NoAuth);
                assert_eq!(addr, "127.0.0.1:1080".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_socks5_with_auth() {
        let p: ProxyProtocol = "socks5://myuser:mypass@192.168.1.1:9050".parse().unwrap();
        match p {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                assert_eq!(version, SocksVersion::V5);
                assert_eq!(
                    auth,
                    SocksAuth::Username(b"myuser".to_vec(), b"mypass".to_vec())
                );
                assert_eq!(addr, "192.168.1.1:9050".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_socks4() {
        let p: ProxyProtocol = "socks4://10.0.0.1:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                assert_eq!(version, SocksVersion::V4);
                assert_eq!(auth, SocksAuth::NoAuth);
                assert_eq!(addr, "10.0.0.1:1080".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_socks4a() {
        let p: ProxyProtocol = "socks4a://10.0.0.1:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks { version, auth, .. } => {
                assert_eq!(version, SocksVersion::V4);
                assert_eq!(auth, SocksAuth::NoAuth);
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_ipv6() {
        let p: ProxyProtocol = "socks5://[::1]:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks { addr, .. } => {
                assert_eq!(addr, "[::1]:1080".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_display_roundtrip() {
        for uri in [
            "socks5://127.0.0.1:1080",
            "socks4://10.0.0.1:9050",
            "socks5://user:pass@192.168.1.1:1080",
            "socks5://[::1]:1080",
        ] {
            let p: ProxyProtocol = uri.parse().unwrap();
            let s = p.to_string();
            let p2: ProxyProtocol = s.parse().unwrap();
            assert_eq!(p, p2, "Round-trip failed for: {}", uri);
        }
    }

    #[test]
    fn proxy_protocol_parse_errors() {
        // Missing scheme
        assert!("127.0.0.1:1080".parse::<ProxyProtocol>().is_err());

        // Invalid scheme
        assert!("invalid://127.0.0.1:1080".parse::<ProxyProtocol>().is_err());

        // Missing port
        assert!("socks5://127.0.0.1".parse::<ProxyProtocol>().is_err());

        // Invalid address
        assert!("socks5://not-an-ip:1080".parse::<ProxyProtocol>().is_err());
    }

    #[test]
    fn proxy_protocol_case_insensitive() {
        // Scheme parsing should be case-insensitive
        let p1: ProxyProtocol = "SOCKS5://127.0.0.1:1080".parse().unwrap();
        let p2: ProxyProtocol = "socks5://127.0.0.1:1080".parse().unwrap();
        let p3: ProxyProtocol = "SoCkS5://127.0.0.1:1080".parse().unwrap();

        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }
}
