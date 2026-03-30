//! Exit policies: match patterns of addresses and/or ports.
//!
//! Every Tor relays has a set of address:port combinations that it
//! actually allows connections to.  The set, abstractly, is the
//! relay's "exit policy".
//!
//! Address policies can be transmitted in two forms.  One is a "full
//! policy", that includes a list of rules that are applied in order
//! to represent addresses and ports.  We represent this with the
//! AddrPolicy type.
//!
//! In microdescriptors, and for IPv6 policies, policies are just
//! given a list of ports for which _most_ addresses are permitted.
//! We represent this kind of policy with the PortPolicy type.
//!
//! TODO: This module probably belongs in a crate of its own, with
//! possibly only the parsing code in this crate.

mod addrpolicy;
mod portpolicy;

use std::str::FromStr;
use std::{collections::BTreeSet, fmt::Display};
use thiserror::Error;

pub use addrpolicy::{AddrPolicy, AddrPortPattern};
pub use portpolicy::PortPolicy;

use crate::NormalItemArgument;
#[cfg(feature = "parse2")]
use crate::parse2::{ArgumentError, ArgumentStream, ItemArgumentParseable};

/// Error from an unparsable or invalid policy.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// A port was not a number in the range 1..65535
    #[error("Invalid port")]
    InvalidPort,
    /// A port range had its starting-point higher than its ending point.
    #[error("Invalid port range")]
    InvalidRange,
    /// An address could not be interpreted.
    #[error("Invalid address")]
    InvalidAddress,
    /// Tried to use a bitmask with the address "*".
    #[error("mask with star")]
    MaskWithStar,
    /// A bit mask was out of range.
    #[error("invalid mask")]
    InvalidMask,
    /// A policy could not be parsed for some other reason.
    #[error("Invalid policy")]
    InvalidPolicy,
}

/// A PortRange is a set of consecutively numbered TCP or UDP ports.
///
/// # Example
/// ```
/// use tor_netdoc::types::policy::PortRange;
///
/// let r: PortRange = "22-8000".parse().unwrap();
/// assert!(r.contains(128));
/// assert!(r.contains(22));
/// assert!(r.contains(8000));
///
/// assert!(! r.contains(21));
/// assert!(! r.contains(8001));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::exhaustive_structs)]
pub struct PortRange {
    /// The first port in this range.
    pub lo: u16,
    /// The last port in this range.
    pub hi: u16,
}

impl PortRange {
    /// Create a new port range spanning from lo to hi, asserting that
    /// the correct invariants hold.
    fn new_unchecked(lo: u16, hi: u16) -> Self {
        assert!(lo != 0);
        assert!(lo <= hi);
        PortRange { lo, hi }
    }
    /// Create a port range containing all ports.
    pub fn new_all() -> Self {
        PortRange::new_unchecked(1, 65535)
    }
    /// Create a new PortRange.
    ///
    /// The Portrange contains all ports between `lo` and `hi` inclusive.
    ///
    /// Returns None if lo is greater than hi, or if either is zero.
    pub fn new(lo: u16, hi: u16) -> Option<Self> {
        if lo != 0 && lo <= hi {
            Some(PortRange { lo, hi })
        } else {
            None
        }
    }
    /// Return true if a port is in this range.
    pub fn contains(&self, port: u16) -> bool {
        self.lo <= port && port <= self.hi
    }
    /// Return true if this range contains all ports.
    pub fn is_all(&self) -> bool {
        self.lo == 1 && self.hi == 65535
    }

    /// Helper for binary search: compare this range to a port.
    ///
    /// This range is "equal" to all ports that it contains.  It is
    /// "greater" than all ports that precede its starting point, and
    /// "less" than all ports that follow its ending point.
    fn compare_to_port(&self, port: u16) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        if port < self.lo {
            Greater
        } else if port <= self.hi {
            Equal
        } else {
            Less
        }
    }
}

/// A PortRange is displayed as a number if it contains a single port,
/// and as a start point and end point separated by a dash if it contains
/// more than one port.
impl Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl FromStr for PortRange {
    type Err = PolicyError;
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        let idx = s.find('-');
        // Find "lo" and "hi".
        let (lo, hi) = if let Some(pos) = idx {
            // This is a range; parse each part.
            (
                s[..pos]
                    .parse::<u16>()
                    .map_err(|_| PolicyError::InvalidPort)?,
                s[pos + 1..]
                    .parse::<u16>()
                    .map_err(|_| PolicyError::InvalidPort)?,
            )
        } else {
            // There was no hyphen, so try to parse this range as a singleton.
            let v = s.parse::<u16>().map_err(|_| PolicyError::InvalidPort)?;
            (v, v)
        };
        PortRange::new(lo, hi).ok_or(PolicyError::InvalidRange)
    }
}

impl NormalItemArgument for PortRange {}

/// A collection of port ranges as an interval tree like structure.
///
/// Please use this when storing multiple port ranges because it optimizies
/// them storage wise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
struct PortRanges(Vec<PortRange>);

impl PortRanges {
    /// Creates a new [`PortRanges`] collection with no elements in it.
    fn new() -> Self {
        Self(Vec::new())
    }

    /// Checks whether there are no ranges in this instance.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Adds a new range into this [`PortRanges`].
    fn push(&mut self, item: PortRange) -> Result<(), PolicyError> {
        if let Some(prev) = self.0.last() {
            // TODO SPEC: We don't enforce this in Tor, but we probably
            // should.  See torspec#60.
            if prev.hi >= item.lo {
                return Err(PolicyError::InvalidPolicy);
            } else if prev.hi == item.lo - 1 {
                // We compress a-b,(b+1)-c into a-c.
                let r = PortRange::new_unchecked(prev.lo, item.hi);
                self.0.pop();
                self.0.push(r);
                return Ok(());
            }
        }

        self.0.push(item);
        Ok(())
    }

    /// Checks whether `port` is contained in a range.
    ///
    /// Whether this means if `port` is allowed or rejected depends on the
    /// wrapping semantic.
    fn contains(&self, port: u16) -> bool {
        debug_assert!(self.0.is_sorted_by(|a, b| a.lo < b.lo));
        self.0
            .binary_search_by(|range| range.compare_to_port(port))
            .is_ok()
    }

    /// Inverts a [`PortRanges`].
    ///
    /// For example, a [`PortRanges`] of `80-443` would become `1-79,444-65535`.
    fn invert(&mut self) {
        let mut prev_hi = 0;
        let mut new_allowed = Vec::new();
        for entry in &self.0 {
            // ports prev_hi+1 through entry.lo-1 were rejected.  We should
            // make them allowed.
            if entry.lo > prev_hi + 1 {
                new_allowed.push(PortRange::new_unchecked(prev_hi + 1, entry.lo - 1));
            }
            prev_hi = entry.hi;
        }
        if prev_hi < 65535 {
            new_allowed.push(PortRange::new_unchecked(prev_hi + 1, 65535));
        }
        self.0 = new_allowed;
    }

    /// Returns an iterator for [`PortRanges`].
    fn iter(&self) -> impl Iterator<Item = &PortRange> {
        self.0.iter()
    }
}

impl FromIterator<u16> for PortRanges {
    fn from_iter<T: IntoIterator<Item = u16>>(iter: T) -> Self {
        // Collect all ports into a BTreeSet to have them sorted and deduped.
        let ports = iter.into_iter().collect::<BTreeSet<_>>();
        let mut ports = ports.into_iter().peekable();

        let mut out = Self::new();
        let mut current_min = None;
        while let Some(port) = ports.next() {
            if current_min.is_none() {
                current_min = Some(port);
            }
            if let Some(next_port) = ports.peek().copied() {
                if next_port != port + 1 {
                    let _ = out.push(PortRange::new_unchecked(
                        current_min.expect("Don't have min port number"),
                        port,
                    ));
                    current_min = None;
                }
            } else {
                let _ = out.push(PortRange::new_unchecked(
                    current_min.expect("Don't have min port number"),
                    port,
                ));
            }
        }

        out
    }
}

// There is deliberately no Display implementation for PortRanges because this
// highly depends on the semantic wrapper around it.  For example, an empty
// PortRanges may either be represented as `reject 1-65535` or `accept 1-65535`
// depending on the context.

impl FromStr for PortRanges {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Pitfall: Do not use a clever iterator here because we need the result
        // of .push() in order to avoid things such as `30-19`.
        let mut ranges = Self::new();
        for range in s.split(',') {
            ranges.push(range.parse()?)?;
        }
        Ok(ranges)
    }
}

#[cfg(feature = "parse2")]
impl ItemArgumentParseable for PortRanges {
    /// [`PortRanges`] argument parser which is odd because port ranges are
    /// syntactically a single argument although semantically multiple ones.
    fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, ArgumentError> {
        args.next()
            .map(Self::from_str)
            .unwrap_or(Ok(Self::new()))
            .map_err(|_| ArgumentError::Invalid)
    }
}

/// A kind of policy rule: either accepts or rejects addresses
/// matching a pattern.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, derive_more::Display, derive_more::FromStr)]
#[display(rename_all = "lowercase")]
#[from_str(rename_all = "lowercase")]
#[allow(clippy::exhaustive_enums)]
pub enum RuleKind {
    /// A rule that accepts matching address:port combinations.
    Accept,
    /// A rule that rejects matching address:port combinations.
    Reject,
}

impl NormalItemArgument for RuleKind {}

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
    use crate::Result;
    #[test]
    fn parse_portrange() -> Result<()> {
        assert_eq!(
            "1-100".parse::<PortRange>()?,
            PortRange::new(1, 100).unwrap()
        );
        assert_eq!(
            "01-100".parse::<PortRange>()?,
            PortRange::new(1, 100).unwrap()
        );
        assert_eq!("1-65535".parse::<PortRange>()?, PortRange::new_all());
        assert_eq!(
            "10-30".parse::<PortRange>()?,
            PortRange::new(10, 30).unwrap()
        );
        assert_eq!(
            "9001".parse::<PortRange>()?,
            PortRange::new(9001, 9001).unwrap()
        );
        assert_eq!(
            "9001-9001".parse::<PortRange>()?,
            PortRange::new(9001, 9001).unwrap()
        );

        assert!("hello".parse::<PortRange>().is_err());
        assert!("0".parse::<PortRange>().is_err());
        assert!("65536".parse::<PortRange>().is_err());
        assert!("65537".parse::<PortRange>().is_err());
        assert!("1-2-3".parse::<PortRange>().is_err());
        assert!("10-5".parse::<PortRange>().is_err());
        assert!("1-".parse::<PortRange>().is_err());
        assert!("-2".parse::<PortRange>().is_err());
        assert!("-".parse::<PortRange>().is_err());
        assert!("*".parse::<PortRange>().is_err());
        Ok(())
    }

    #[test]
    fn pr_manip() {
        assert!(PortRange::new_all().is_all());
        assert!(!PortRange::new(2, 65535).unwrap().is_all());

        assert!(PortRange::new_all().contains(1));
        assert!(PortRange::new_all().contains(65535));
        assert!(PortRange::new_all().contains(7777));

        assert!(PortRange::new(20, 30).unwrap().contains(20));
        assert!(PortRange::new(20, 30).unwrap().contains(25));
        assert!(PortRange::new(20, 30).unwrap().contains(30));
        assert!(!PortRange::new(20, 30).unwrap().contains(19));
        assert!(!PortRange::new(20, 30).unwrap().contains(31));

        use std::cmp::Ordering::*;
        assert_eq!(PortRange::new(20, 30).unwrap().compare_to_port(7), Greater);
        assert_eq!(PortRange::new(20, 30).unwrap().compare_to_port(20), Equal);
        assert_eq!(PortRange::new(20, 30).unwrap().compare_to_port(25), Equal);
        assert_eq!(PortRange::new(20, 30).unwrap().compare_to_port(30), Equal);
        assert_eq!(PortRange::new(20, 30).unwrap().compare_to_port(100), Less);
    }

    #[test]
    fn pr_fmt() {
        fn chk(a: u16, b: u16, s: &str) {
            let pr = PortRange::new(a, b).unwrap();
            assert_eq!(format!("{}", pr), s);
        }

        chk(1, 65535, "1-65535");
        chk(10, 20, "10-20");
        chk(20, 20, "20");
    }
}
