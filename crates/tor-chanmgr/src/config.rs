//! Configuration for a channel manager (and, therefore, channels)
//!
//! # Semver note
//!
//! Most types in this module are re-exported by `arti-client`.

use std::net::SocketAddr;

use derive_builder::Builder;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

/// Characters that must be percent-encoded in URI userinfo (user:pass)
/// Based on RFC 3986 section 3.2.1
const USERINFO_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b':')
    .add(b'@')
    .add(b'[')
    .add(b']')
    .add(b'\\');
use serde::{Deserialize, Serialize};
use tor_config::impl_standard_builder;
use tor_config::{ConfigBuildError, PaddingLevel};
use tor_socksproto::SocksAuth;
use tor_socksproto::SocksVersion;

/// Error parsing a proxy URI string
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyProtocolParseError {
    /// Proxy URI has an unsupported or missing scheme.
    #[error("unsupported or missing proxy scheme: {0}")]
    UnsupportedScheme(String),
    /// Proxy URI had an invalid or unparsable address.
    #[error("invalid proxy address: {0}")]
    InvalidAddress(String),
    /// Proxy URI is missing a port or has an invalid port.
    #[error("missing or invalid port")]
    InvalidPort,
    /// Proxy URI does not match the expected format.
    #[error("invalid proxy URI format: {0}")]
    InvalidFormat(String),
}

/// Information about what proxy protocol to use, and how to use it.
///
/// This type can be parsed from a URI string using the same format as curl's
/// proxy URL syntax (see <https://curl.se/docs/url-syntax.html>).
///
/// Supported formats:
///
/// - `socks4://ip:port` - SOCKS4 proxy
/// - `socks4://user@ip:port` - SOCKS4 proxy with user ID
/// - `socks4a://ip:port` - SOCKS4a proxy (treated same as socks4)
/// - `socks5://ip:port` - SOCKS5 proxy without auth
/// - `socks5://user:pass@ip:port` - SOCKS5 proxy with username/password auth
/// - `socks5://user@ip:port` - SOCKS5 proxy with username only (empty password)
/// - `socks5h://ip:port` - SOCKS5 with remote hostname resolution (treated same as socks5)
///
/// - Hostnames for the proxy server itself are not supported.
/// - Credentials must be embedded in the URI; curl's `-U user:pass` style is not supported.
/// - For `socks4://`, any password component is silently ignored (SOCKS4 only supports user ID).
/// - Special characters in credentials are percent-encoded per RFC 3986 section 3.2.1.
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
            "socks5" | "socks5h" => SocksVersion::V5,
            _ => {
                return Err(ProxyProtocolParseError::UnsupportedScheme(
                    scheme.to_string(),
                ));
            }
        };

        // Check for authentication credentials (user:pass@host:port or user@host:port)
        let (auth, host_port) = if let Some(at_pos) = rest.rfind('@') {
            let creds = &rest[..at_pos];
            let addr_part = &rest[at_pos + 1..];

            // Parse user:pass or just user.
            // Password is optional; for SOCKS4 any password is silently ignored.
            // Percent-decode credentials per RFC 3986 (e.g., %40 -> @)
            let (user_encoded, pass_encoded) = match creds.split_once(':') {
                Some((u, p)) => (u, Some(p)),
                None => (creds, None),
            };

            // Decode percent-encoded characters in user/pass
            let user_decoded = percent_decode_str(user_encoded).decode_utf8_lossy();
            let pass_decoded = pass_encoded.map(|p| percent_decode_str(p).decode_utf8_lossy());

            // SOCKS4 only supports user ID (password ignored if provided).
            // SOCKS5 supports username/password authentication.
            let auth = match version {
                SocksVersion::V4 => {
                    // Note: password is silently discarded for SOCKS4
                    SocksAuth::Socks4(user_decoded.as_bytes().to_vec())
                }
                SocksVersion::V5 => {
                    let pass = pass_decoded.as_deref().unwrap_or("");
                    SocksAuth::Username(user_decoded.as_bytes().to_vec(), pass.as_bytes().to_vec())
                }
                // Handle potential future SOCKS versions
                _ => SocksAuth::NoAuth,
            };
            (auth, addr_part)
        } else {
            (SocksAuth::NoAuth, rest)
        };

        // Parse the proxy address. Only IP addresses are supported, not hostnames.
        // SocketAddr::parse handles both IPv4 (1.2.3.4:port) and IPv6 ([::1]:port).
        let addr = host_port
            .parse::<SocketAddr>()
            .map_err(|_| ProxyProtocolParseError::InvalidAddress(host_port.to_string()))?;

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
                // Use SocksVersion's Display impl for the scheme (e.g., "socks5")
                match auth {
                    SocksAuth::NoAuth => write!(f, "{}://{}", version, addr),
                    SocksAuth::Socks4(user_id) => {
                        // SOCKS4: user@host format (no password in SOCKS4)
                        // Percent-encode special characters per RFC 3986 section 3.2.1
                        let user = String::from_utf8_lossy(user_id);
                        let user_encoded = utf8_percent_encode(&user, USERINFO_ENCODE_SET);
                        write!(f, "{}://{}@{}", version, user_encoded, addr)
                    }
                    SocksAuth::Username(user, pass) => {
                        // SOCKS5: user:pass@host format
                        // Percent-encode special characters per RFC 3986 section 3.2.1
                        let user = String::from_utf8_lossy(user);
                        let pass = String::from_utf8_lossy(pass);
                        let user_encoded = utf8_percent_encode(&user, USERINFO_ENCODE_SET);
                        let pass_encoded = utf8_percent_encode(&pass, USERINFO_ENCODE_SET);
                        write!(
                            f,
                            "{}://{}:{}@{}",
                            version, user_encoded, pass_encoded, addr
                        )
                    }
                    // Handle potential future auth types
                    _ => write!(f, "{}://{}", version, addr),
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

/// Deserialize an outbound proxy, treating empty strings as unset.
#[allow(clippy::option_option)]
fn deserialize_outbound_proxy<'de, D>(
    deserializer: D,
) -> Result<Option<Option<ProxyProtocol>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(s) => {
            if s.trim().is_empty() {
                return Ok(Some(None));
            }
            let parsed = s.parse().map_err(serde::de::Error::custom)?;
            Ok(Some(Some(parsed)))
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
    #[builder_field_attr(serde(default, deserialize_with = "deserialize_outbound_proxy"))]
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

    #[test]
    fn proxy_protocol_parse_socks5h() {
        // socks5h:// should be treated as socks5
        let p: ProxyProtocol = "socks5h://127.0.0.1:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks { version, auth, .. } => {
                assert_eq!(version, SocksVersion::V5);
                assert_eq!(auth, SocksAuth::NoAuth);
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_socks4_user_only() {
        // SOCKS4 with user only (no password)
        let p: ProxyProtocol = "socks4://myuser@10.0.0.1:1080".parse().unwrap();
        match p {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                assert_eq!(version, SocksVersion::V4);
                assert_eq!(auth, SocksAuth::Socks4(b"myuser".to_vec()));
                assert_eq!(addr, "10.0.0.1:1080".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_parse_socks5_user_only() {
        // SOCKS5 with user only (empty password)
        let p: ProxyProtocol = "socks5://myuser@192.168.1.1:9050".parse().unwrap();
        match p {
            ProxyProtocol::Socks {
                version,
                auth,
                addr,
            } => {
                assert_eq!(version, SocksVersion::V5);
                assert_eq!(auth, SocksAuth::Username(b"myuser".to_vec(), b"".to_vec()));
                assert_eq!(addr, "192.168.1.1:9050".parse().unwrap());
            }
        }
    }

    #[test]
    fn proxy_protocol_percent_encoding_roundtrip() {
        // Test percent-encoding round-trip for special characters
        // User with @ and : characters that need encoding
        let p = ProxyProtocol::Socks {
            version: SocksVersion::V5,
            auth: SocksAuth::Username(b"user@domain".to_vec(), b"pass:word".to_vec()),
            addr: "127.0.0.1:1080".parse().unwrap(),
        };
        let s = p.to_string();
        // Should contain percent-encoded characters
        assert!(s.contains("%40"), "@ should be encoded as %40");
        assert!(
            s.contains("%3A") || s.contains("%3a"),
            ": in password should be encoded"
        );

        // Parse it back
        let p2: ProxyProtocol = s.parse().unwrap();
        assert_eq!(p, p2, "Round-trip failed for percent-encoded URI");
    }

    #[test]
    fn proxy_protocol_socks4_user_roundtrip() {
        // SOCKS4 user-only format should round-trip
        let uri = "socks4://testuser@10.0.0.1:1080";
        let p: ProxyProtocol = uri.parse().unwrap();
        let s = p.to_string();
        let p2: ProxyProtocol = s.parse().unwrap();
        assert_eq!(p, p2, "SOCKS4 user-only round-trip failed");
    }
}
