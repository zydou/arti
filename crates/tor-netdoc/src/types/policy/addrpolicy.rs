//! Implements address policies, based on a series of accept/reject
//! rules.

use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use itertools::chain;

use crate::NormalItemArgument;
use crate::encode::NetdocEncodableFields;
use crate::parse2::{
    ErrorProblem as EP, ItemArgumentParseable, ItemStream, KeywordRef, NetdocParseableFields,
    UnparsedItem,
};

use ipnet::IpNet;

use super::{PolicyError, PortRange, RuleKind};

/// Sequence of `accept` and `reject` rules
///
/// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:accept>
///
/// Encodable in netdocs, and parseable as [`NetdocParseableFields`].
///
/// A specific address:port is tested against them in order;
/// first match wins.
//
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
///
/// `Default` is the all-reject policy, also constructible with [`AddrPolicy::new`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddrPolicy {
    /// A list of rules to apply to find out whether an address is
    /// contained by this policy.
    ///
    /// The rules apply in order; the first one to match determines
    /// whether the address is accepted or rejected.
    rules: Vec<AddrPolicyRule>,
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

    /// List the rules in this pattern
    pub fn rules(&self) -> impl DoubleEndedIterator<Item = (RuleKind, AddrPortPattern)> + '_ {
        self.rules
            .iter()
            .map(|rule| (rule.kind, rule.pattern.clone()))
    }
}

impl NetdocParseableFields for AddrPolicy {
    type Accumulator = AddrPolicy;

    fn is_item_keyword(kw: KeywordRef<'_>) -> bool {
        matches!(kw.as_str(), "accept" | "reject")
    }

    fn accumulate_item(acc: &mut Self::Accumulator, mut item: UnparsedItem<'_>) -> Result<(), EP> {
        // We must use `FromStr`, not argument parsing, because
        // RuleKind is the keyword and not an argument.
        let rule = RuleKind::from_str(item.keyword().as_str())
            .map_err(|_| EP::Internal("accept/reject not a RuleKind?"))?;
        let args = item.args_mut();
        let pattern =
            AddrPortPattern::from_args(args).map_err(args.error_handler("accept/reject"))?;
        acc.push(rule, pattern);
        Ok(())
    }

    fn finish(acc: Self::Accumulator, _: &ItemStream) -> Result<Self, EP> {
        Ok(acc)
    }
}

impl NetdocEncodableFields for AddrPolicy {
    fn encode_fields(&self, out: &mut crate::encode::NetdocEncoder) -> Result<(), tor_error::Bug> {
        // The order of this field is significant, meaning we have to emit the
        // values as they are.  The spec also strongly recommends a trailing
        // `accept *:*` or `reject *:*`.  To comply with this, we check for
        // an existing final rule with an ALL pattern and add a `reject *:*`
        // if that is not the case.  This is not super nice and ideally we would
        // do this somewhere in the type construction, but we cannot do some
        // right now because the legacy parser accumulates it as it is.
        const ALL: AddrPortPattern = AddrPortPattern::new_all();
        const DEFAULT_DENY: AddrPolicyRule = AddrPolicyRule {
            kind: RuleKind::Reject,
            pattern: ALL,
        };

        // Add default deny in case of an absent trailing ALL.
        let default_deny = match self.rules.last() {
            // Do nothing if there already is a trailing ALL.
            Some(AddrPolicyRule {
                kind: _,
                pattern: ALL,
            }) => None,
            // Add a default deny to the end.
            _ => Some(&DEFAULT_DENY),
        };

        for rule in chain!(&self.rules, default_deny) {
            out.push_raw_string(&format_args!("{} {}\n", rule.kind, rule.pattern));
        }
        Ok(())
    }
}

/// A single rule in an address policy.
///
/// Contains a pattern and what to do with things that match it.
#[derive(Clone, Debug, PartialEq, Eq)]
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
/// When trying to process a policy, rather than merely construct one,
/// match the struct with an exhaustive pattern,
/// so that any new fields break the build rather than being silently ignored.
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
#[derive(Clone, Debug, Eq, PartialEq, Hash)] //
#[derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)]
#[allow(clippy::exhaustive_structs)]
pub struct AddrPortPattern {
    /// A pattern to match somewhere between zero and all IP addresses.
    pub addrs: IpPattern,
    /// A pattern to match a range of ports.
    pub ports: PortRange,
}

impl AddrPortPattern {
    /// Return an AddrPortPattern matching specified ports on specified addresses
    pub fn new(addrs: IpPattern, ports: PortRange) -> Self {
        Self { addrs, ports }
    }

    /// Return an AddrPortPattern matching all targets.
    pub const fn new_all() -> Self {
        Self {
            addrs: IpPattern::All,
            ports: PortRange::new_all(),
        }
    }

    /// Return true iff this pattern matches a given address and port.
    pub fn matches(&self, addr: &IpAddr, port: u16) -> bool {
        self.addrs.matches(addr) && self.ports.contains(port)
    }
    /// As matches, but accept a SocketAddr.
    pub fn matches_sockaddr(&self, addr: &SocketAddr) -> bool {
        self.matches(&addr.ip(), addr.port())
    }
}

impl Display for AddrPortPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.ports.is_all() {
            write!(f, "{}:*", self.addrs)
        } else {
            write!(f, "{}:{}", self.addrs, self.ports)
        }
    }
}

impl FromStr for AddrPortPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let (addrs, ports_s) = s.rsplit_once(':').ok_or(PolicyError::InvalidPolicy)?;
        let addrs: IpPattern = addrs.parse()?;
        let ports: PortRange = if ports_s == "*" {
            PortRange::new_all()
        } else {
            ports_s.parse()?
        };

        Ok(AddrPortPattern { addrs, ports })
    }
}

impl NormalItemArgument for AddrPortPattern {}

/// A pattern that matches one or more IP addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, derive_more::From)]
// We don't expect to extend this, and users (eg, tor-dirauth)
// will need to match it exhaustively to make sense of a policy.
#[allow(clippy::exhaustive_enums)]
pub enum IpPattern {
    /// Match all addresses.
    ///
    /// String representation: `*`.
    ///
    /// This is not the same as (say) `0.0.0.0/0`, because that matches only IPv4 addresses,
    /// whereas `*` matches both IPv4 and IPv6.
    All,
    /// Match addresses of a particular IP version, beginning with a given prefix.
    ///
    /// String representation: `n.n.n.n/prefix` or `[IPv6]/prefix`.
    /// If the prefix is maximum it is optional, and omitted by `Display`.
    Net(#[from] IpNet),
}

impl IpPattern {
    /// Construct an IpPattern that matches the first `prefix_len` bits of `addr`.
    pub fn from_addr_and_prefix_len(addr: IpAddr, prefix_len: u8) -> Result<Self, PolicyError> {
        IpNet::new(addr, prefix_len)
            .map(IpPattern::Net)
            .map_err(|_: ipnet::PrefixLenError| PolicyError::InvalidMask)
    }

    /// Return true iff `addr` is matched by this pattern.
    pub fn matches(&self, addr: &IpAddr) -> bool {
        match self {
            IpPattern::All => true,
            IpPattern::Net(n) => n.contains(addr),
        }
    }
}

impl Display for IpPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IpPattern::*;
        match self {
            All => write!(f, "*"),
            // We want to omit the /prefix_len if it's the maximum, for brevity
            Net(IpNet::V4(n)) if n.prefix_len() == 32 => write!(f, "{}", n.addr()),
            Net(IpNet::V4(n)) => write!(f, "{}", n),
            // We want to include the [ ] around IPv6 addresses, which ipnet omits
            Net(IpNet::V6(n)) if n.prefix_len() == 128 => write!(f, "[{}]", n.addr()),
            Net(IpNet::V6(n)) => write!(f, "[{}]/{}", n.addr(), n.prefix_len()),
        }
    }
}

/// Helper: try to parse a plain ipv4 address, or an IPv6 address
/// wrapped in brackets.
fn parse_addr(mut s: &str) -> Result<IpAddr, PolicyError> {
    let trimmed = s.strip_prefix('[').and_then(|s| s.strip_suffix(']'));
    if let Some(trimmed) = trimmed {
        s = trimmed;
    }
    let addr: IpAddr = s.parse().map_err(|_| PolicyError::InvalidAddress)?;
    if addr.is_ipv6() != trimmed.is_some() {
        return Err(PolicyError::InvalidAddress);
    }
    Ok(addr)
}

impl FromStr for IpPattern {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let (ip_s, plen_s) = match s.split_once('/') {
            Some((ip_s, plen_s)) => (ip_s, Some(plen_s)),
            None => (s, None),
        };
        match (ip_s, plen_s) {
            ("*", Some(_)) => Err(PolicyError::MaskWithStar),
            ("*", None) => Ok(IpPattern::All),
            (s, Some(m)) => {
                let a: IpAddr = parse_addr(s)?;
                let m: u8 = m.parse().map_err(|_| PolicyError::InvalidMask)?;
                IpPattern::from_addr_and_prefix_len(a, m)
            }
            (s, None) => {
                let a: IpAddr = parse_addr(s)?;
                let m = if a.is_ipv4() { 32 } else { 128 };
                IpPattern::from_addr_and_prefix_len(a, m)
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use crate::encode::{NetdocEncodable, NetdocEncoder};

    use super::*;

    #[test]
    fn test_roundtrip_rules() {
        fn check2(inp: &str, outp: &str) {
            let policy = inp.parse::<AddrPortPattern>().expect(inp);
            assert_eq!(format!("{}", policy), outp);
        }
        let check = |inp| check2(inp, inp);

        check2("127.0.0.2/32:77-10000", "127.0.0.2:77-10000");
        check2("127.0.0.2/32:*", "127.0.0.2:*");
        check("127.0.0.0/16:9-100");
        check("127.0.0.0/0:443");
        check("*:443");
        check("[::1]:443");
        check("[ffaa::]/16:80");
        check2("[ffaa::77]/128:80", "[ffaa::77]:80");
        check("[::]/0:443");

        // Patterns with excessive prefix length for the address.
        // It's not clear that it's correct to accept these.
        check("127.0.0.1/8:443");
        check("[::1]/8:443");
    }

    #[test]
    fn test_bad_rules() {
        fn check(s: &str) {
            let _: PolicyError = s.parse::<AddrPortPattern>().expect_err(s);
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

    #[test]
    fn parse2() {
        use crate::parse2::{self, ParseInput};
        use derive_deftly::Deftly;

        const RULES: &str = "\
        intro\n\
        reject *:25\n\
        reject 127.0.0.0/8:*\n\
        reject 192.168.0.0/16:*\n\
        accept *:80\n\
        accept *:443\n\
        accept *:9000-65535\n\
        reject *:*\n";

        #[derive(Deftly)]
        #[derive_deftly(NetdocParseable, NetdocEncodable)]
        struct Wrapper {
            #[allow(dead_code)]
            intro: (),
            #[deftly(netdoc(flatten))]
            ipv4_policy: AddrPolicy,
        }

        let wrapper = parse2::parse_netdoc::<Wrapper>(&ParseInput::new(RULES, "")).unwrap();
        let ap = wrapper.ipv4_policy.clone();

        assert_eq!(
            ap.allows_sockaddr(&"1.1.1.1:80".parse().unwrap()),
            Some(RuleKind::Accept)
        );
        assert_eq!(
            ap.allows_sockaddr(&"1.1.1.1:443".parse().unwrap()),
            Some(RuleKind::Accept)
        );
        assert_eq!(
            ap.allows_sockaddr(&"1.1.1.1:9005".parse().unwrap()),
            Some(RuleKind::Accept)
        );

        assert_eq!(
            ap.allows_sockaddr(&"1.1.1.1:25".parse().unwrap()),
            Some(RuleKind::Reject)
        );
        assert_eq!(
            ap.allows_sockaddr(&"127.0.0.1:80".parse().unwrap()),
            Some(RuleKind::Reject)
        );
        assert_eq!(
            ap.allows_sockaddr(&"1.1.1.1:70".parse().unwrap()),
            Some(RuleKind::Reject)
        );

        // Do round-trip encoding.
        let mut enc = NetdocEncoder::default();
        wrapper.encode_unsigned(&mut enc).unwrap();
        assert_eq!(RULES, enc.finish().unwrap());

        // Test default deny.
        let accept_all = {
            let mut ap = AddrPolicy::new();
            ap.push(RuleKind::Accept, AddrPortPattern::new_all());
            ap
        };
        let reject_all = {
            let mut ap = AddrPolicy::new();
            ap.push(RuleKind::Reject, AddrPortPattern::new_all());
            ap
        };

        let tests = [
            (accept_all.clone(), "accept *:*"), // do not add default deny to existing
            (reject_all.clone(), "reject *:*"), // do not add default deny to existing
            (AddrPolicy::new(), "reject *:*"),  // add default deny to empty
            (AddrPolicy::default(), "reject *:*"), // default policy is all-reject
        ];
        for (input, expected_tail) in tests {
            let mut enc = NetdocEncoder::default();
            Wrapper {
                intro: (),
                ipv4_policy: input,
            }
            .encode_unsigned(&mut enc)
            .unwrap();
            assert_eq!(expected_tail, enc.finish().unwrap().lines().last().unwrap());
        }
    }
}
