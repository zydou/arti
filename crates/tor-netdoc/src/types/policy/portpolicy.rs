//! Implement port-based policies
//!
//! These are also known as "short policies" or "policy summaries".

use std::fmt::Display;
use std::str::FromStr;

use crate::encode::{ItemEncoder, ItemValueEncodable};
use crate::parse2::{ErrorProblem as EP, ItemValueParseable, UnparsedItem};

use super::{PolicyError, PortRange, PortRanges, RuleKind};
use tor_basic_utils::derive_deftly_template_GloballyInternable;
use tor_basic_utils::intern::{GloballyInternable, Intern};
use tor_error::Bug;

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
///
/// `Default` is the all-reject policy, also constructible with [`PortPolicy::new_reject_all`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, Deftly)]
#[derive_deftly(GloballyInternable)]
pub struct PortPolicy {
    /// A list of port ranges that this policy allows.
    ///
    /// In case we see a reject, we simply invert the policy by the assumption
    /// that allows policies take less space than reject ones.
    allowed: PortRanges,
}

impl Display for PortPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format the list as an `accept`, and as a `reject`, and take the shortest.
        let shortest = [
            ("accept", &self.allowed),
            ("reject", &self.allowed.inverted()),
        ]
        .into_iter()
        .filter_map(|(keyword, allowed)| Some(format!("{keyword} {}", allowed.display()?)))
        // min_by_key takes the *last* if they're equal but we would prefer to take `accept`
        .rev()
        .min_by_key(|s| s.len())
        .expect("can't both be empty");

        write!(f, "{shortest}")
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

    /// Create a PortPolicy from an iterator of allowed port ranges.
    ///
    /// All other ports will be rejected.
    ///
    /// The input iterator must yield increasing nonoverlapping ranges,
    /// or it's a [`PolicyError`].
    pub fn from_ordered_allowed_ranges(
        allowed: impl IntoIterator<Item = PortRange>,
    ) -> Result<Self, PolicyError> {
        let allowed = allowed
            .into_iter()
            .try_fold(PortRanges::new(), |mut b, i| {
                b.push_ordered(i)?;
                Ok(b)
            })?;
        Ok(Self::from_allowed_port_ranges(allowed))
    }

    /// Create a PortPolicy from a set of allowed port ranges.
    ///
    /// All other ports will be rejected.
    ///
    /// Unlike `from_allowed_ranges`, `from_allowed_port_ranges` does not iterate
    /// over the input (which is a `Vec` underneath) and collect into a new `Vec`.
    pub(super) fn from_allowed_port_ranges(allowed: PortRanges) -> Self {
        Self { allowed }
    }

    /// Return true iff `port` is allowed by this policy.
    pub fn allows_port(&self, port: u16) -> bool {
        self.allowed.contains(port)
    }

    /// Replace this PortPolicy with an interned copy, to save memory.
    pub fn intern(self) -> Intern<Self> {
        Self::into_intern(self)
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
        // Splitting with a UTF-8 honoring method here is important, as
        // RuleKind and PortRanges need their arguments separately.
        let (kind, ranges) = s.split_once(' ').ok_or(PolicyError::InvalidPort)?;
        let kind = RuleKind::from_str(kind).map_err(|_| PolicyError::InvalidPort)?;
        let mut allowed = PortRanges::from_str(ranges)?;
        if kind == RuleKind::Reject {
            allowed.invert();
        }
        Ok(Self { allowed })
    }
}

impl ItemValueParseable for PortPolicy {
    // Manual implementation incorporating the `accept`/`reject`,
    // using `.invert()` if necessary to yield simply a `PortPolicy`,
    // rather than the `RuleKind` (`accept`/`reject`) plus port list.
    fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, EP> {
        /// Helper type just has the raw [`RuleKind`] and port list
        #[derive(Deftly)]
        #[derive_deftly(ItemValueParseable)]
        struct RawPortPolicy {
            /// Whether to [`RuleKind::Accept`] or [`RuleKind::Reject`].
            kind: RuleKind,
            /// The actual ranges before inversion.
            ranges: PortRanges,
        }

        item.check_no_object()?;

        // Obtain the kind and ranges and possibly invert them.
        let RawPortPolicy { kind, mut ranges } = RawPortPolicy::from_unparsed(item)?;
        if ranges.is_empty() {
            // This is one or more.
            return Err(EP::MissingArgument {
                field: "port-policy",
            });
        }
        // Potential post-processing depending on the rule kind.
        match kind {
            RuleKind::Accept => {}
            RuleKind::Reject => ranges.invert(),
        }
        Ok(Self { allowed: ranges })
    }
}

impl ItemValueEncodable for PortPolicy {
    fn write_item_value_onto(&self, mut out: ItemEncoder) -> Result<(), Bug> {
        out.args_raw_string(self);
        Ok(())
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
    use super::*;
    use crate::parse2::{self, ParseInput};
    use itertools::Itertools;

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

        check(
            "accept 1-10,30-50,600",
            "accept 1-10,30-50,600",
            &[1, 10, 35, 600],
            &[0, 11, 55, 599, 601],
        );
        check(
            //
            "accept 1-10,11-20",
            "accept 1-20",
            &[],
            &[],
        );
        check(
            "accept 31-65535",
            "reject 1-30",
            &[31, 10001, 65535],
            &[0, 1, 30],
        );
        check(
            "accept 1-299,501-65535",
            "reject 300-500",
            &[31, 10001, 65535],
            &[300, 301, 500],
        );
        check(
            //
            "reject 10,11,12,13,15",
            "reject 10-13,15",
            &[],
            &[],
        );
        check(
            "reject 1-65535",
            "reject 1-65535",
            &[],
            &[1, 300, 301, 500, 10001, 65535],
        );
    }

    #[test]
    fn test_default() {
        assert_eq!(
            //
            PortPolicy::default().to_string(),
            "reject 1-65535",
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
            "acce ¬",
        ] {
            assert!(s.parse::<PortPolicy>().is_err());
            assert!(
                parse2::parse_netdoc::<Dummy>(&ParseInput::new(&format!("dummy {s}"), "")).is_err()
            );
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
