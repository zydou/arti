//! Configuration logic for onion service reverse proxy.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};
use tor_config::{define_list_builder_accessors, define_list_builder_helper, ConfigBuildError};

/// Configuration for a reverse proxy running for a single onion service.
#[derive(Clone, Debug, Builder)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ProxyConfig {
    /// A list of rules to apply to incoming requests.  If no rule
    /// matches, we take the DestroyCircuit action.
    #[builder(sub_builder, setter(custom))]
    pub(crate) proxy_ports: ProxyRuleList,
}

define_list_builder_accessors! {
   struct ProxyConfigBuilder {
       pub proxy_ports: [ProxyRule],
   }
}

/// Helper to define builder for ProxyConfig.
type ProxyRuleList = Vec<ProxyRule>;

define_list_builder_helper! {
   pub struct ProxyRuleListBuilder {
       pub(crate) values: [ProxyRule],
   }
   built: ProxyRuleList = values;
   default = vec![];
   item_build: |value| Ok(value.clone());
}

/// A single rule in a `ProxyConfig`.
///
/// Rules take the form of, "When this pattern matches, take this action."
#[derive(Clone, Debug, Serialize, Deserialize)]
// TODO HSS: we might someday want to accept structs here as well, so that
// we can add per-rule fields if we need to.  We can make that an option if/when
// it comes up, however.
#[serde(from = "ProxyRuleAsTuple", into = "ProxyRuleAsTuple")]
pub struct ProxyRule {
    /// Any connections to a port matching this pattern match this rule.
    source: ProxyPattern,
    /// When this rule matches, we take this action.
    target: ProxyTarget,
}

/// Helper type used to (de)serialize ProxyRule.
type ProxyRuleAsTuple = (ProxyPattern, ProxyTarget);
impl From<ProxyRuleAsTuple> for ProxyRule {
    fn from(value: ProxyRuleAsTuple) -> Self {
        Self {
            source: value.0,
            target: value.1,
        }
    }
}
impl From<ProxyRule> for ProxyRuleAsTuple {
    fn from(value: ProxyRule) -> Self {
        (value.source, value.target)
    }
}
impl ProxyRule {
    /// Create a new ProxyRule mapping `source` to `target`.
    pub fn new(source: ProxyPattern, target: ProxyTarget) -> Self {
        Self { source, target }
    }
}

/// A set of ports to use when checking how to handle a port.
#[derive(Clone, Debug, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
pub struct ProxyPattern(ProxyPatternInner);

/// Implementation type for `ProxyPattern`.
///
/// (This is a separate type so that we can enforce well-formedness)
#[derive(Clone, Debug)]
enum ProxyPatternInner {
    /// Match a single port.
    Port(u16),
    /// Match an inclusive range of ports.
    PortRange(u16, u16),
    /// Match all ports.
    AllPorts,
}

impl FromStr for ProxyPattern {
    type Err = ProxyConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProxyConfigError as PCE;
        if s == "*" {
            Ok(Self::all_ports())
        } else if let Some((left, right)) = s.split_once('-') {
            let left: u16 = left.parse().map_err(PCE::InvalidPort)?;
            let right: u16 = right.parse().map_err(PCE::InvalidPort)?;
            Self::port_range(left, right)
        } else {
            let port = s.parse().map_err(PCE::InvalidPort)?;
            Self::one_port(port)
        }
    }
}
impl std::fmt::Display for ProxyPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ProxyPatternInner as PPI;
        match &self.0 {
            PPI::Port(p) => write!(f, "{}", p),
            PPI::PortRange(low, high) => write!(f, "{}-{}", low, high),
            PPI::AllPorts => write!(f, "*"),
        }
    }
}

impl ProxyPattern {
    /// Return a pattern matching all ports.
    pub fn all_ports() -> Self {
        ProxyPatternInner::AllPorts
            .check()
            .expect("Somehow, AllPorts was not a valid pattern")
    }
    /// Return a pattern matching a single port.
    ///
    /// Gives an error if the port is zero.
    pub fn one_port(port: u16) -> Result<Self, ProxyConfigError> {
        ProxyPatternInner::Port(port).check()
    }
    /// Return a pattern matching all ports between `low` and `high` inclusive.
    ///
    /// Gives an error unless `0 < low <= high`.
    pub fn port_range(low: u16, high: u16) -> Result<Self, ProxyConfigError> {
        ProxyPatternInner::PortRange(low, high).check()
    }

    /// Return true if this pattern includes `port`.
    pub(crate) fn matches_port(&self, port: u16) -> bool {
        use ProxyPatternInner as PPI;
        match &self.0 {
            PPI::Port(p) => *p == port,
            PPI::PortRange(low, high) => *low <= port && port <= *high,
            PPI::AllPorts => true,
        }
    }
}

impl ProxyPatternInner {
    /// If this is a valid pattern, wrap it as a ProxyPattern. Otherwise return
    /// an error.
    fn check(self) -> Result<ProxyPattern, ProxyConfigError> {
        use ProxyConfigError as PCE;
        use ProxyPatternInner as PPI;
        match self {
            PPI::Port(0) | PPI::PortRange(0, _) | PPI::PortRange(_, 0) => Err(PCE::ZeroPort),
            PPI::PortRange(low, high) if low > high => Err(PCE::EmptyPortRange),
            other => Ok(ProxyPattern(other)),
        }
    }
}

/// An action to take upon receiving an incoming request.
#[derive(Clone, Debug, Default, serde_with::DeserializeFromStr, serde_with::SerializeDisplay)]
#[non_exhaustive]
pub enum ProxyTarget {
    /// Close the circuit immediately with an error.
    #[default]
    DestroyCircuit,
    /// Open a TCP connection to a given address and port.
    Tcp(SocketAddr),
    /// Open an AF_UNIX connection to a given address.
    Unix(PathBuf),
    /// Close the stream immediately with an error.
    RejectStream,
    /// Ignore the stream request.
    IgnoreStream,
}

impl FromStr for ProxyTarget {
    type Err = ProxyConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ProxyConfigError as PCE;

        /// Return true if 's' looks like an attempted IPv4 or IPv6 socketaddr.
        fn looks_like_attempted_addr(s: &str) -> bool {
            s.starts_with(|c: char| c.is_ascii_digit())
                || s.strip_prefix('[')
                    .map(|rhs| rhs.starts_with(|c: char| c.is_ascii_hexdigit() || c == ':'))
                    .unwrap_or(false)
        }

        if s == "destroy" {
            Ok(Self::DestroyCircuit)
        } else if s == "reject" {
            Ok(Self::RejectStream)
        } else if s == "ignore" {
            Ok(Self::IgnoreStream)
        } else if let Some(path) = s.strip_prefix("unix:") {
            Ok(Self::Unix(PathBuf::from(path)))
        } else if let Some(addr) = s.strip_prefix("tcp:") {
            Ok(Self::Tcp(addr.parse().map_err(PCE::InvalidTargetAddr)?))
        } else if looks_like_attempted_addr(s) {
            // We check 'looks_like_attempted_addr' before parsing this.
            Ok(Self::Tcp(s.parse().map_err(PCE::InvalidTargetAddr)?))
        } else {
            Err(PCE::UnrecognizedTargetType)
        }
    }
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyTarget::DestroyCircuit => write!(f, "destroy"),
            ProxyTarget::Tcp(addr) => write!(f, "tcp:{}", addr),
            ProxyTarget::Unix(path) => write!(f, "unix:{}", path.display()),
            ProxyTarget::RejectStream => write!(f, "reject"),
            ProxyTarget::IgnoreStream => write!(f, "ignore"),
        }
    }
}

/// An error encountered while parsing or applying a proxy configuration.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyConfigError {
    /// We encountered a proxy target with an unrecognized type keyword.
    #[error("Could not parse proxy target type.")]
    UnrecognizedTargetType,

    /// A socket address could not be parsed to be invalid.
    #[error("Could not parse proxy target address.")]
    InvalidTargetAddr(#[source] std::net::AddrParseError),

    /// A socket rule had an source port that couldn't be parsed as a `u16`.
    #[error("Could not parse proxy source port.")]
    InvalidPort(#[source] std::num::ParseIntError),

    /// A socket rule had a zero source port.
    #[error("Zero is not a valid port.")]
    ZeroPort,

    /// A socket rule specified an empty port range.
    #[error("Port range is empty.")]
    EmptyPortRange,
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
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
    fn pattern_ok() {
        use ProxyPattern as P;
        use ProxyPatternInner as I;
        assert!(matches!(P::from_str("*"), Ok(P(I::AllPorts))));
        assert!(matches!(P::from_str("100"), Ok(P(I::Port(100)))));
        assert!(matches!(
            P::from_str("100-200"),
            Ok(P(I::PortRange(100, 200)))
        ));
    }

    #[test]
    fn pattern_display() {
        use ProxyPattern as P;
        assert_eq!(P::all_ports().to_string(), "*");
        assert_eq!(P::one_port(100).unwrap().to_string(), "100");
        assert_eq!(P::port_range(100, 200).unwrap().to_string(), "100-200");
    }

    #[test]
    fn pattern_err() {
        use ProxyConfigError as PCE;
        use ProxyPattern as P;
        assert!(matches!(P::from_str("fred"), Err(PCE::InvalidPort(_))));
        assert!(matches!(P::from_str("100-fred"), Err(PCE::InvalidPort(_))));
    }

    #[test]
    fn target_ok() {
        use ProxyTarget as T;
        assert!(matches!(T::from_str("reject"), Ok(T::RejectStream)));
        assert!(matches!(T::from_str("ignore"), Ok(T::IgnoreStream)));
        assert!(matches!(T::from_str("destroy"), Ok(T::DestroyCircuit)));
        let sa: SocketAddr = "192.168.1.1:50".parse().unwrap();
        assert!(matches!(T::from_str("192.168.1.1:50"), Ok(T::Tcp(a)) if a == sa));
        assert!(matches!(T::from_str("tcp:192.168.1.1:50"), Ok(T::Tcp(a)) if a == sa));
        let sa: SocketAddr = "[::1]:999".parse().unwrap();
        assert!(matches!(T::from_str("[::1]:999"), Ok(T::Tcp(a)) if a == sa));
        assert!(matches!(T::from_str("tcp:[::1]:999"), Ok(T::Tcp(a)) if a == sa));
        let pb = PathBuf::from("/var/run/hs/socket");
        assert!(matches!(T::from_str("unix:/var/run/hs/socket"), Ok(T::Unix(p)) if p == pb));
    }

    #[test]
    fn target_display() {
        use ProxyTarget as T;
        assert_eq!(T::RejectStream.to_string(), "reject");
        assert_eq!(T::IgnoreStream.to_string(), "ignore");
        assert_eq!(T::DestroyCircuit.to_string(), "destroy");
        assert_eq!(
            T::Tcp("192.168.1.1:50".parse().unwrap()).to_string(),
            "tcp:192.168.1.1:50"
        );
        assert_eq!(
            T::Tcp("[::1]:999".parse().unwrap()).to_string(),
            "tcp:[::1]:999"
        );
        assert_eq!(
            T::Unix("/var/run/hs/socket".into()).to_string(),
            "unix:/var/run/hs/socket"
        );
    }

    #[test]
    fn target_err() {
        use ProxyConfigError as PCE;
        use ProxyTarget as T;

        assert!(matches!(
            T::from_str("sdakljf"),
            Err(PCE::UnrecognizedTargetType)
        ));

        assert!(matches!(
            T::from_str("tcp:hello"),
            Err(PCE::InvalidTargetAddr(_))
        ));

        assert!(matches!(
            T::from_str("128.256.cats.and.dogs"),
            Err(PCE::InvalidTargetAddr(_))
        ));
    }

    #[test]
    fn deserialize() {
        let ex = r#"{
            "proxy_ports": [
                [ "443", "127.0.0.1:11443" ],
                [ "80", "ignore" ],
                [ "*", "destroy" ]
            ]
        }"#;
        let bld: ProxyConfigBuilder = serde_json::from_str(ex).unwrap();
        let cfg = bld.build().unwrap();
        assert_eq!(cfg.proxy_ports.len(), 3);
        // TODO HSS: test actual values.
    }
}
