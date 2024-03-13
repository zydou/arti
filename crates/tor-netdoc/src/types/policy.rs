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

use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;

pub use addrpolicy::{AddrPolicy, AddrPortPattern, RuleKind};
pub use portpolicy::PortPolicy;

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
