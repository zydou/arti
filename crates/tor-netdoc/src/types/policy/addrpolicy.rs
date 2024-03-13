//! Implements address policies, based on a series of accept/reject
//! rules.

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use super::{PolicyError, PortRange};

/// A sequence of rules that are applied to an address:port until one
/// matches.
///
/// Each rule is of the form "accept PATTERN" or "reject PATTERN",
/// where every pattern describes a set of addresses and ports.
/// Address sets are given as a prefix of 0-128 bits that the address
/// must have; port sets are given as a low-bound and high-bound that
/// the target port might lie between.
///
/// Relays use this type for defining their own policies, and for
/// publishing their IPv4 policies.  Clients instead use
/// [super::portpolicy::PortPolicy] objects to view a summary of the
/// relays' declared policies.
///
/// An example IPv4 policy might be:
///
/// ```ignore
///  reject *:25
///  reject 127.0.0.0/8:*
///  reject 192.168.0.0/16:*
///  accept *:80
///  accept *:443
///  accept *:9000-65535
///  reject *:*
/// ```
#[derive(Clone, Debug, Default)]
pub struct AddrPolicy {
    /// A list of rules to apply to find out whether an address is
    /// contained by this policy.
    ///
    /// The rules apply in order; the first one to match determines
    /// whether the address is accepted or rejected.
    rules: Vec<AddrPolicyRule>,
}

/// A kind of policy rule: either accepts or rejects addresses
/// matching a pattern.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)]
pub enum RuleKind {
    /// A rule that accepts matching address:port combinations.
    Accept,
    /// A rule that rejects matching address:port combinations.
    Reject,
}

impl AddrPolicy {
    /// Apply this policy to an address:port combination
    ///
    /// We do this by applying each rule in sequence, until one
    /// matches.
    ///
    /// Returns None if no rule matches.
    pub fn allows(&self, addr: &IpAddr, port: u16) -> Option<RuleKind> {
        self.rules
            .iter()
            .find(|rule| rule.pattern.matches(addr, port))
            .map(|AddrPolicyRule { kind, .. }| *kind)
    }

    /// As allows, but accept a SocketAddr.
    pub fn allows_sockaddr(&self, addr: &SocketAddr) -> Option<RuleKind> {
        self.allows(&addr.ip(), addr.port())
    }

    /// Create a new AddrPolicy that matches nothing.
    pub fn new() -> Self {
        AddrPolicy::default()
    }

    /// Add a new rule to this policy.
    ///
    /// The newly added rule is applied _after_ all previous rules.
    /// It matches all addresses and ports covered by AddrPortPattern.
    ///
    /// If accept is true, the rule is to accept addresses that match;
    /// if accept is false, the rule rejects such addresses.
    pub fn push(&mut self, kind: RuleKind, pattern: AddrPortPattern) {
        self.rules.push(AddrPolicyRule { kind, pattern });
    }
}

/// A single rule in an address policy.
///
/// Contains a pattern and what to do with things that match it.
#[derive(Clone, Debug)]
struct AddrPolicyRule {
    /// What do we do with items that match the pattern?
    kind: RuleKind,
    /// What pattern are we trying to match?
    pattern: AddrPortPattern,
}

/*
impl Display for AddrPolicyRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmd = match self.kind {
            RuleKind::Accept => "accept",
            RuleKind::Reject => "reject",
        };
        write!(f, "{} {}", cmd, self.pattern)
    }
}
*/

/// A pattern that may or may not match an address and port.
///
/// Each AddrPortPattern has an IP pattern, which matches a set of
/// addresses by prefix, and a port pattern, which matches a range of
/// ports.
///
/// # Example
///
/// ```
/// use tor_netdoc::types::policy::AddrPortPattern;
/// use std::net::{IpAddr,Ipv4Addr};
/// let localhost = IpAddr::V4(Ipv4Addr::new(127,3,4,5));
/// let not_localhost = IpAddr::V4(Ipv4Addr::new(192,0,2,16));
/// let pat: AddrPortPattern = "127.0.0.0/8:*".parse().unwrap();
///
/// assert!(pat.matches(&localhost, 22));
/// assert!(! pat.matches(&not_localhost, 22));
/// ```
#[derive(
    Clone, Debug, Eq, PartialEq, serde_with::SerializeDisplay, serde_with::DeserializeFromStr,
)]
pub struct AddrPortPattern {
    /// A pattern to match somewhere between zero and all IP addresses.
    pattern: IpPattern,
    /// A pattern to match a range of ports.
    ports: PortRange,
}

impl AddrPortPattern {
    /// Return an AddrPortPattern matching all targets.
    pub fn new_all() -> Self {
        Self {
            pattern: IpPattern::Star,
            ports: PortRange::new_all(),
        }
    }

    /// Return true iff this pattern matches a given address and port.
    pub fn matches(&self, addr: &IpAddr, port: u16) -> bool {
        self.pattern.matches(addr) && self.ports.contains(port)
    }
    /// As matches, but accept a SocketAddr.
    pub fn matches_sockaddr(&self, addr: &SocketAddr) -> bool {
        self.matches(&addr.ip(), addr.port())
    }
}

impl Display for AddrPortPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ports.is_all() {
            write!(f, "{}:*", self.pattern)
        } else {
            write!(f, "{}:{}", self.pattern, self.ports)
        }
    }
}

impl FromStr for AddrPortPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let last_colon = s.rfind(':').ok_or(PolicyError::InvalidPolicy)?;
        let pattern: IpPattern = s[..last_colon].parse()?;
        let ports_s = &s[last_colon + 1..];
        let ports: PortRange = if ports_s == "*" {
            PortRange::new_all()
        } else {
            ports_s.parse()?
        };

        Ok(AddrPortPattern { pattern, ports })
    }
}

/// A pattern that matches one or more IP addresses.
//
// TODO(nickm): At present there is no way for Display or FromStr to distinguish
// V4Star, V6Star, and Star.  If we decide it's important to have a syntax for
// "all IPv4 addresses" that isn't "0.0.0.0/0", we'll need to revisit that.
// At present, C tor allows '*', '*4', and '*6'.
#[derive(Clone, Debug, Eq, PartialEq)]
enum IpPattern {
    /// Match all addresses.
    Star,
    /// Match all IPv4 addresses.
    V4Star,
    /// Match all IPv6 addresses.
    V6Star,
    /// Match all IPv4 addresses beginning with a given prefix.
    V4(Ipv4Addr, u8),
    /// Match all IPv6 addresses beginning with a given prefix.
    V6(Ipv6Addr, u8),
}

impl IpPattern {
    /// Construct an IpPattern that matches the first `mask` bits of `addr`.
    fn from_addr_and_mask(addr: IpAddr, mask: u8) -> Result<Self, PolicyError> {
        match (addr, mask) {
            (IpAddr::V4(_), 0) => Ok(IpPattern::V4Star),
            (IpAddr::V6(_), 0) => Ok(IpPattern::V6Star),
            (IpAddr::V4(a), m) if m <= 32 => Ok(IpPattern::V4(a, m)),
            (IpAddr::V6(a), m) if m <= 128 => Ok(IpPattern::V6(a, m)),
            (_, _) => Err(PolicyError::InvalidMask),
        }
    }
    /// Return true iff `addr` is matched by this pattern.
    fn matches(&self, addr: &IpAddr) -> bool {
        match (self, addr) {
            (IpPattern::Star, _) => true,
            (IpPattern::V4Star, IpAddr::V4(_)) => true,
            (IpPattern::V6Star, IpAddr::V6(_)) => true,
            (IpPattern::V4(pat, mask), IpAddr::V4(addr)) => {
                let p1 = u32::from_be_bytes(pat.octets());
                let p2 = u32::from_be_bytes(addr.octets());
                let shift = 32 - mask;
                (p1 >> shift) == (p2 >> shift)
            }
            (IpPattern::V6(pat, mask), IpAddr::V6(addr)) => {
                let p1 = u128::from_be_bytes(pat.octets());
                let p2 = u128::from_be_bytes(addr.octets());
                let shift = 128 - mask;
                (p1 >> shift) == (p2 >> shift)
            }
            (_, _) => false,
        }
    }
}

impl Display for IpPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IpPattern::*;
        match self {
            Star | V4Star | V6Star => write!(f, "*"),
            V4(a, 32) => write!(f, "{}", a),
            V4(a, m) => write!(f, "{}/{}", a, m),
            V6(a, 128) => write!(f, "[{}]", a),
            V6(a, m) => write!(f, "[{}]/{}", a, m),
        }
    }
}

/// Helper: try to parse a plain ipv4 address, or an IPv6 address
/// wrapped in brackets.
fn parse_addr(mut s: &str) -> Result<IpAddr, PolicyError> {
    let bracketed = s.starts_with('[') && s.ends_with(']');
    if bracketed {
        s = &s[1..s.len() - 1];
    }
    let addr: IpAddr = s.parse().map_err(|_| PolicyError::InvalidAddress)?;
    if addr.is_ipv6() != bracketed {
        return Err(PolicyError::InvalidAddress);
    }
    Ok(addr)
}

impl FromStr for IpPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let (ip_s, mask_s) = match s.find('/') {
            Some(slash_idx) => (&s[..slash_idx], Some(&s[slash_idx + 1..])),
            None => (s, None),
        };
        match (ip_s, mask_s) {
            ("*", Some(_)) => Err(PolicyError::MaskWithStar),
            ("*", None) => Ok(IpPattern::Star),
            (s, Some(m)) => {
                let a: IpAddr = parse_addr(s)?;
                let m: u8 = m.parse().map_err(|_| PolicyError::InvalidMask)?;
                IpPattern::from_addr_and_mask(a, m)
            }
            (s, None) => {
                let a: IpAddr = parse_addr(s)?;
                let m = if a.is_ipv4() { 32 } else { 128 };
                IpPattern::from_addr_and_mask(a, m)
            }
        }
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
    fn test_roundtrip_rules() {
        fn check(inp: &str, outp: &str) {
            let policy = inp.parse::<AddrPortPattern>().unwrap();
            assert_eq!(format!("{}", policy), outp);
        }

        check("127.0.0.2/32:77-10000", "127.0.0.2:77-10000");
        check("127.0.0.2/32:*", "127.0.0.2:*");
        check("127.0.0.0/16:9-100", "127.0.0.0/16:9-100");
        check("127.0.0.0/0:443", "*:443");
        check("*:443", "*:443");
        check("[::1]:443", "[::1]:443");
        check("[ffaa::]/16:80", "[ffaa::]/16:80");
        check("[ffaa::77]/128:80", "[ffaa::77]:80");
    }

    #[test]
    fn test_bad_rules() {
        fn check(s: &str) {
            assert!(s.parse::<AddrPortPattern>().is_err());
        }

        check("marzipan:80");
        check("1.2.3.4:90-80");
        check("1.2.3.4/100:8888");
        check("[1.2.3.4]/16:80");
        check("[::1]/130:8888");
    }

    #[test]
    fn test_rule_matches() {
        fn check(addr: &str, yes: &[&str], no: &[&str]) {
            use std::net::SocketAddr;
            let policy = addr.parse::<AddrPortPattern>().unwrap();
            for s in yes {
                let sa = s.parse::<SocketAddr>().unwrap();
                assert!(policy.matches_sockaddr(&sa));
            }
            for s in no {
                let sa = s.parse::<SocketAddr>().unwrap();
                assert!(!policy.matches_sockaddr(&sa));
            }
        }

        check(
            "1.2.3.4/16:80",
            &["1.2.3.4:80", "1.2.44.55:80"],
            &["9.9.9.9:80", "1.3.3.4:80", "1.2.3.4:81"],
        );
        check(
            "*:443-8000",
            &["1.2.3.4:443", "[::1]:500"],
            &["9.0.0.0:80", "[::1]:80"],
        );
        check(
            "[face::]/8:80",
            &["[fab0::7]:80"],
            &["[dd00::]:80", "[face::7]:443"],
        );

        check("0.0.0.0/0:*", &["127.0.0.1:80"], &["[f00b::]:80"]);
        check("[::]/0:*", &["[f00b::]:80"], &["127.0.0.1:80"]);
    }

    #[test]
    fn test_policy_matches() -> Result<(), PolicyError> {
        let mut policy = AddrPolicy::default();
        policy.push(RuleKind::Accept, "*:443".parse()?);
        policy.push(RuleKind::Accept, "[::1]:80".parse()?);
        policy.push(RuleKind::Reject, "*:80".parse()?);

        let policy = policy; // drop mut
        assert_eq!(
            policy.allows_sockaddr(&"[::6]:443".parse().unwrap()),
            Some(RuleKind::Accept)
        );
        assert_eq!(
            policy.allows_sockaddr(&"127.0.0.1:443".parse().unwrap()),
            Some(RuleKind::Accept)
        );
        assert_eq!(
            policy.allows_sockaddr(&"[::1]:80".parse().unwrap()),
            Some(RuleKind::Accept)
        );
        assert_eq!(
            policy.allows_sockaddr(&"[::2]:80".parse().unwrap()),
            Some(RuleKind::Reject)
        );
        assert_eq!(
            policy.allows_sockaddr(&"127.0.0.1:80".parse().unwrap()),
            Some(RuleKind::Reject)
        );
        assert_eq!(
            policy.allows_sockaddr(&"127.0.0.1:66".parse().unwrap()),
            None
        );
        Ok(())
    }

    #[test]
    fn serde() {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
        struct X {
            p1: AddrPortPattern,
            p2: AddrPortPattern,
        }

        let x = X {
            p1: "127.0.0.1/8:9-10".parse().unwrap(),
            p2: "*:80".parse().unwrap(),
        };

        let encoded = serde_json::to_string(&x).unwrap();
        let expected = r#"{"p1":"127.0.0.1/8:9-10","p2":"*:80"}"#;
        let x2: X = serde_json::from_str(&encoded).unwrap();
        let x3: X = serde_json::from_str(expected).unwrap();
        assert_eq!(&x2, &x3);
        assert_eq!(&x2, &x);
    }
}
