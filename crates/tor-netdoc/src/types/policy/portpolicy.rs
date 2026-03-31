//! Implement port-based policies
//!
//! These are also known as "short policies" or "policy summaries".

use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "parse2")]
use crate::parse2::{ErrorProblem as EP, ItemValueParseable, UnparsedItem};

use super::{PolicyError, PortRanges, RuleKind};
use tor_basic_utils::intern::InternCache;

#[cfg(feature = "parse2")]
use derive_deftly::Deftly;

/// A policy to match zero or more TCP/UDP ports.
///
/// These are used in Tor to summarize all policies in
/// microdescriptors, and Ipv6 policies in router descriptors.
///
/// NOTE: If a port is listed as accepted, it doesn't mean that the
/// relay allows _every_ address on that port.  Instead, a port is
/// listed if a relay will exit to _most public addresses_ on that
/// port. Therefore, unlike [super::addrpolicy::AddrPolicy] objects,
/// these policies cannot tell you if a port is _definitely_ allowed
/// or rejected: only if it is _probably_ allowed or rejected.
///
/// # Examples
/// ```
/// use tor_netdoc::types::policy::PortPolicy;
/// let policy: PortPolicy = "accept 1-1023,8000-8999,60000-65535".parse().unwrap();
///
/// assert!(policy.allows_port(22));
/// assert!(policy.allows_port(8000));
/// assert!(! policy.allows_port(1024));
/// assert!(! policy.allows_port(9000));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct PortPolicy {
    /// A list of port ranges that this policy allows.
    ///
    /// In case we see a reject, we simply invert the policy by the assumption
    /// that allows policies take less space than reject ones.
    allowed: PortRanges,
}

impl Display for PortPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.allowed.is_empty() {
            write!(f, "reject 1-65535")?;
        } else {
            write!(f, "accept ")?;
            let mut comma = "";
            for range in self.allowed.iter() {
                write!(f, "{}{}", comma, range)?;
                comma = ",";
            }
        }
        Ok(())
    }
}

impl PortPolicy {
    /// Return a new PortPolicy that rejects all ports.
    pub fn new_reject_all() -> Self {
        Self::default()
    }

    /// Create a PortPolicy from a list of allowed ports. All other ports will be rejected. The
    /// ports in the list may be in any order.
    pub fn from_allowed_port_list(ports: Vec<u16>) -> Self {
        Self {
            allowed: PortRanges::from_iter(ports),
        }
    }

    /// Return true iff `port` is allowed by this policy.
    pub fn allows_port(&self, port: u16) -> bool {
        self.allowed.contains(port)
    }

    /// Replace this PortPolicy with an interned copy, to save memory.
    pub fn intern(self) -> Arc<Self> {
        POLICY_CACHE.intern(self)
    }

    /// Return true if this policy allows any ports at all.
    ///
    /// # Example
    /// ```
    /// use tor_netdoc::types::policy::PortPolicy;
    ///
    /// let policy: PortPolicy = "accept 22".parse().unwrap();
    /// assert!(policy.allows_some_port());
    /// let policy2: PortPolicy = "reject 1-65535".parse().unwrap();
    /// assert!(! policy2.allows_some_port());
    /// ```
    pub fn allows_some_port(&self) -> bool {
        !self.allowed.is_empty()
    }
}

impl FromStr for PortPolicy {
    type Err = PolicyError;

    /// Very bad parser for [`PortPolicy`], please use `parse2`!
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // TODO: The error is bad but kept for backwards compatibility.
        // Also, we should do split_whitespace but I feel doing this is not
        // worth it anymore; introduces an unnecessary risk of adding
        // bugs.
        if s.len() < 7 {
            // We need to do this because RuleKind::from_str does not check for
            // the space between "accept/reject" and the arguments.
            return Err(PolicyError::InvalidPort);
        }
        let kind = RuleKind::from_str(&s[..6]).map_err(|_| PolicyError::InvalidPort)?;
        let mut allowed = PortRanges::new();
        let s = &s[7..];
        for item in s.split(',') {
            allowed.push(item.parse()?)?;
        }
        if kind == RuleKind::Reject {
            allowed.invert();
        }
        Ok(Self { allowed })
    }
}

#[cfg(feature = "parse2")]
impl ItemValueParseable for PortPolicy {
    // Manual implementation because we may want to invert this.
    fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, EP> {
        /// Wrapper type that also parses [`RuleKind`].
        #[derive(Deftly)]
        #[derive_deftly(ItemValueParseable)]
        struct Wrapper {
            /// Whether to [`RuleKind::Accept`] or [`RuleKind::Reject`].
            kind: RuleKind,
            /// The actual ranges before inversion.
            ranges: PortRanges,
        }

        item.check_no_object()?;

        // Obtain the kind and ranges and possibly invert them.
        let Wrapper { kind, mut ranges } = Wrapper::from_unparsed(item)?;
        if ranges.is_empty() {
            // This is one or more.
            return Err(EP::MissingArgument {
                field: "port-policy",
            });
        }
        if kind == RuleKind::Reject {
            ranges.invert();
        }
        Ok(Self { allowed: ranges })
    }
}

/// Cache of PortPolicy objects, for saving memory.
//
/// This only holds weak references to the policy objects, so we don't
/// need to worry about running out of space because of stale entries.
static POLICY_CACHE: InternCache<PortPolicy> = InternCache::new();

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
    use itertools::Itertools;

    #[cfg(feature = "parse2")]
    use crate::parse2::{self, ParseInput};

    use super::*;

    #[cfg(feature = "parse2")]
    #[derive(derive_deftly::Deftly)]
    #[derive_deftly(NetdocParseable)]
    struct Dummy {
        dummy: PortPolicy,
    }

    #[test]
    fn test_roundtrip() {
        fn check(inp: &str, outp: &str, allow: &[u16], deny: &[u16]) {
            let policy = inp.parse::<PortPolicy>().unwrap();
            assert_eq!(format!("{}", policy), outp);
            for p in allow {
                assert!(policy.allows_port(*p));
            }
            for p in deny {
                assert!(!policy.allows_port(*p));
            }
            #[cfg(feature = "parse2")]
            {
                let policy2 =
                    parse2::parse_netdoc::<Dummy>(&ParseInput::new(&format!("dummy {inp}"), ""))
                        .unwrap()
                        .dummy;
                for p in allow {
                    assert!(policy2.allows_port(*p));
                }
                for p in deny {
                    assert!(!policy2.allows_port(*p));
                }
            }
        }

        check(
            "accept 1-10,30-50,600",
            "accept 1-10,30-50,600",
            &[1, 10, 35, 600],
            &[0, 11, 55, 599, 601],
        );
        check("accept 1-10,11-20", "accept 1-20", &[], &[]);
        check(
            "reject 1-30",
            "accept 31-65535",
            &[31, 10001, 65535],
            &[0, 1, 30],
        );
        check(
            "reject 300-500",
            "accept 1-299,501-65535",
            &[31, 10001, 65535],
            &[300, 301, 500],
        );
        check("reject 10,11,12,13,15", "accept 1-9,14,16-65535", &[], &[]);
        check(
            "reject 1-65535",
            "reject 1-65535",
            &[],
            &[1, 300, 301, 500, 10001, 65535],
        );
    }

    #[test]
    fn test_bad() {
        for s in &[
            "ignore 1-10",
            "allow 1-100",
            "accept",
            "reject",
            "accept x-y",
            "accept ",
            "reject ",
            "ignore ",
            "accept 1-20,19-30",
            "accept 1-20,20-30",
            "reject 1,1,1,1",
            "reject 1,2,foo,4",
            "reject 5,4,3,2",
        ] {
            assert!(s.parse::<PortPolicy>().is_err());
            #[cfg(feature = "parse2")]
            {
                assert!(
                    parse2::parse_netdoc::<Dummy>(&ParseInput::new(&format!("dummy {s}"), ""))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn test_from_allowed_port_list() {
        let mut cases = vec![];
        cases.push((vec![1, 2, 3, 7, 8, 10, 42], "accept 1-3,7-8,10,42"));
        cases.push((vec![1, 3, 5], "accept 1,3,5"));
        cases.push((vec![1, 2, 3, 4], "accept 1-4"));
        cases.push((vec![65535], "accept 65535"));
        cases.push((vec![], "reject 1-65535"));

        for (port_list, port_range) in cases {
            let expected = port_range.parse::<PortPolicy>().unwrap();
            for port_list in port_list.iter().copied().permutations(port_list.len()) {
                assert_eq!(PortPolicy::from_allowed_port_list(port_list), expected,);
            }
        }
    }
}
