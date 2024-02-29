#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use caret::caret_int;

use thiserror::Error;

caret_int! {
    /// A recognized subprotocol.
    ///
    /// These names are kept in sync with the names used in consensus
    /// documents; the values are kept in sync with the values in the
    /// cbor document format in the walking onions proposal.
    ///
    /// For the full semantics of each subprotocol, see tor-spec.txt.
    #[derive(Hash,Ord,PartialOrd)]
    pub struct ProtoKind(u16) {
        /// Initiating and receiving channels, and getting cells on them.
        Link = 0,
        /// Different kinds of authenticate cells
        LinkAuth = 1,
        /// CREATE cells, CREATED cells, and the encryption that they
        /// create.
        Relay = 2,
        /// Serving and fetching network directory documents.
        DirCache = 3,
        /// Serving onion service descriptors
        HSDir = 4,
        /// Providing an onion service introduction point
        HSIntro = 5,
        /// Providing an onion service rendezvous point
        HSRend = 6,
        /// Describing a relay's functionality using router descriptors.
        Desc = 7,
        /// Describing a relay's functionality using microdescriptors.
        MicroDesc = 8,
        /// Describing the network as a consensus directory document.
        Cons = 9,
        /// Sending and accepting circuit-level padding
        Padding = 10,
        /// Improved means of flow control on circuits.
        FlowCtrl = 11,
    }
}

/// How many recognized protocols are there?
const N_RECOGNIZED: usize = 12;

/// Representation for a known or unknown protocol.
#[derive(Eq, PartialEq, Clone, Debug, Hash, Ord, PartialOrd)]
enum Protocol {
    /// A known protocol; represented by one of ProtoKind.
    Proto(ProtoKind),
    /// An unknown protocol; represented by its name.
    Unrecognized(String),
}

impl Protocol {
    /// Return true iff `s` is the name of a protocol we do not recognize.
    fn is_unrecognized(&self, s: &str) -> bool {
        match self {
            Protocol::Unrecognized(s2) => s2 == s,
            _ => false,
        }
    }
    /// Return a string representation of this protocol.
    fn to_str(&self) -> &str {
        match self {
            Protocol::Proto(k) => k.to_str().unwrap_or("<bug>"),
            Protocol::Unrecognized(s) => s,
        }
    }
}

/// Representation of a set of versions supported by a protocol.
///
/// For now, we only use this type for unrecognized protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct SubprotocolEntry {
    /// Which protocol's versions does this describe?
    proto: Protocol,
    /// A bit-vector defining which versions are supported.  If bit
    /// `(1<<i)` is set, then protocol version `i` is supported.
    supported: u64,
}

/// A set of supported or required subprotocol versions.
///
/// This type supports both recognized subprotocols (listed in ProtoKind),
/// and unrecognized subprotocols (stored by name).
///
/// To construct an instance, use the FromStr trait:
/// ```
/// use tor_protover::Protocols;
/// let p: Result<Protocols,_> = "Link=1-3 LinkAuth=2-3 Relay=1-2".parse();
/// ```
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct Protocols {
    /// A mapping from protocols' integer encodings to bit-vectors.
    recognized: [u64; N_RECOGNIZED],
    /// A vector of unrecognized protocol versions.
    unrecognized: Vec<SubprotocolEntry>,
}

impl Protocols {
    /// Return a new empty set of protocol versions.
    pub fn new() -> Self {
        Protocols::default()
    }
    /// Helper: return true iff this protocol set contains the
    /// version `ver` of the protocol represented by the integer `proto`.
    fn supports_recognized_ver(&self, proto: usize, ver: u8) -> bool {
        if ver > 63 {
            return false;
        }
        if proto >= self.recognized.len() {
            return false;
        }
        (self.recognized[proto] & (1 << ver)) != 0
    }
    /// Helper: return true iff this protocol set contains version
    /// `ver` of the unrecognized protocol represented by the string
    /// `proto`.
    ///
    /// Requires that `proto` is not the name of a recognized protocol.
    fn supports_unrecognized_ver(&self, proto: &str, ver: u8) -> bool {
        if ver > 63 {
            return false;
        }
        let ent = self
            .unrecognized
            .iter()
            .find(|ent| ent.proto.is_unrecognized(proto));
        match ent {
            Some(e) => (e.supported & (1 << ver)) != 0,
            None => false,
        }
    }
    // TODO: Combine these next two functions into one by using a trait.
    /// Check whether a known protocol version is supported.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Link=1-3 HSDir=2,4-5".parse().unwrap();
    ///
    /// assert!(protos.supports_known_subver(ProtoKind::Link, 2));
    /// assert!(protos.supports_known_subver(ProtoKind::HSDir, 4));
    /// assert!(! protos.supports_known_subver(ProtoKind::HSDir, 3));
    /// assert!(! protos.supports_known_subver(ProtoKind::LinkAuth, 3));
    /// ```
    pub fn supports_known_subver(&self, proto: ProtoKind, ver: u8) -> bool {
        self.supports_recognized_ver(proto.get() as usize, ver)
    }
    /// Check whether a protocol version identified by a string is supported.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Link=1-3 Foobar=7".parse().unwrap();
    ///
    /// assert!(protos.supports_subver("Link", 2));
    /// assert!(protos.supports_subver("Foobar", 7));
    /// assert!(! protos.supports_subver("Link", 5));
    /// assert!(! protos.supports_subver("Foobar", 6));
    /// assert!(! protos.supports_subver("Wombat", 3));
    /// ```
    pub fn supports_subver(&self, proto: &str, ver: u8) -> bool {
        match ProtoKind::from_name(proto) {
            Some(p) => self.supports_recognized_ver(p.get() as usize, ver),
            None => self.supports_unrecognized_ver(proto, ver),
        }
    }

    /// Parsing helper: Try to add a new entry `ent` to this set of protocols.
    ///
    /// Uses `foundmask`, a bit mask saying which recognized protocols
    /// we've already found entries for.  Returns an error if `ent` is
    /// for a protocol we've already added.
    fn add(&mut self, foundmask: &mut u64, ent: SubprotocolEntry) -> Result<(), ParseError> {
        match ent.proto {
            Protocol::Proto(k) => {
                let idx = k.get() as usize;
                let bit = 1 << u64::from(k.get());
                if (*foundmask & bit) != 0 {
                    return Err(ParseError::Duplicate);
                }
                *foundmask |= bit;
                self.recognized[idx] = ent.supported;
            }
            Protocol::Unrecognized(ref s) => {
                if self
                    .unrecognized
                    .iter()
                    .any(|ent| ent.proto.is_unrecognized(s))
                {
                    return Err(ParseError::Duplicate);
                }
                self.unrecognized.push(ent);
            }
        }
        Ok(())
    }
}

/// An error representing a failure to parse a set of protocol versions.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum ParseError {
    /// A protocol version was not in the range 0..=63.
    #[error("Protocol version out of range")]
    OutOfRange,
    /// Some subprotocol or protocol version appeared more than once.
    #[error("Duplicate protocol entry")]
    Duplicate,
    /// The list of protocol versions was malformed in some other way.
    #[error("Malformed protocol entry")]
    Malformed,
}

/// Helper: return a new u64 in which bits `lo` through `hi` inclusive
/// are set to 1, and all the other bits are set to 0.
///
/// In other words, `bitrange(a,b)` is how we represent the range of
/// versions `a-b` in a protocol version bitmask.
///
/// ```ignore
/// # use tor_protover::bitrange;
/// assert_eq!(bitrange(0, 5), 0b111111);
/// assert_eq!(bitrange(2, 5), 0b111100);
/// assert_eq!(bitrange(2, 7), 0b11111100);
/// ```
fn bitrange(lo: u64, hi: u64) -> u64 {
    assert!(lo <= hi && lo <= 63 && hi <= 63);
    let mut mask = !0;
    mask <<= 63 - hi;
    mask >>= 63 - hi + lo;
    mask <<= lo;
    mask
}

/// Helper: return true if the provided string is a valid "integer"
/// in the form accepted by the protover spec.  This is stricter than
/// rust's integer parsing format.
fn is_good_number(n: &str) -> bool {
    n.chars().all(|ch| ch.is_ascii_digit()) && !n.starts_with('0')
}

/// A single SubprotocolEntry is parsed from a string of the format
/// Name=Versions, where Versions is a comma-separated list of
/// integers or ranges of integers.
impl std::str::FromStr for SubprotocolEntry {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        // split the string on the =.
        let (name, versions) = {
            let eq_idx = s.find('=').ok_or(ParseError::Malformed)?;
            (&s[..eq_idx], &s[eq_idx + 1..])
        };
        // Look up the protocol by name.
        let proto = match ProtoKind::from_name(name) {
            Some(p) => Protocol::Proto(p),
            None => Protocol::Unrecognized(name.to_string()),
        };
        if versions.is_empty() {
            // We need to handle this case specially, since otherwise
            // it would be treated below as a single empty value, which
            // would be rejected.
            return Ok(SubprotocolEntry {
                proto,
                supported: 0,
            });
        }
        // Construct a bitmask based on the comma-separated versions.
        let mut supported = 0_u64;
        for ent in versions.split(',') {
            // Find and parse lo and hi for a single range of versions.
            // (If this is not a range, but rather a single version v,
            // treat it as if it were a range v-v.)
            let (lo_s, hi_s) = {
                match ent.find('-') {
                    Some(pos) => (&ent[..pos], &ent[pos + 1..]),
                    None => (ent, ent),
                }
            };
            if !is_good_number(lo_s) {
                return Err(ParseError::Malformed);
            }
            if !is_good_number(hi_s) {
                return Err(ParseError::Malformed);
            }
            let lo: u64 = lo_s.parse().map_err(|_| ParseError::Malformed)?;
            let hi: u64 = hi_s.parse().map_err(|_| ParseError::Malformed)?;
            // Make sure that lo and hi are in-bounds and consistent.
            if lo > 63 || hi > 63 {
                return Err(ParseError::OutOfRange);
            }
            if lo > hi {
                return Err(ParseError::Malformed);
            }
            let mask = bitrange(lo, hi);
            // Make sure that no version is included twice.
            if (supported & mask) != 0 {
                return Err(ParseError::Duplicate);
            }
            // Add the appropriate bits to the mask.
            supported |= mask;
        }
        Ok(SubprotocolEntry { proto, supported })
    }
}

/// A Protocols set can be parsed from a string according to the
/// format used in Tor consensus documents.
///
/// A protocols set is represented by a space-separated list of
/// entries.  Each entry is of the form `Name=Versions`, where `Name`
/// is the name of a protocol, and `Versions` is a comma-separated
/// list of version numbers and version ranges.  Each version range is
/// a pair of integers separated by `-`.
///
/// No protocol name may be listed twice.  No version may be listed
/// twice for a single protocol.  All versions must be in range 0
/// through 63 inclusive.
impl std::str::FromStr for Protocols {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let mut result = Protocols::new();
        let mut foundmask = 0_u64;
        for ent in s.split(' ') {
            if ent.is_empty() {
                continue;
            }

            let s: SubprotocolEntry = ent.parse()?;
            result.add(&mut foundmask, s)?;
        }
        result.unrecognized.sort();
        Ok(result)
    }
}

/// Given a bitmask, return a list of the bits set in the mask, as a
/// String in the format expected by Tor consensus documents.
///
/// This implementation constructs ranges greedily.  For example, the
/// bitmask `0b0111011` will be represented as `0-1,3-5`, and not
/// `0,1,3,4,5` or `0,1,3-5`.
///
/// ```ignore
/// # use tor_protover::dumpmask;
/// assert_eq!(dumpmask(0b111111), "0-5");
/// assert_eq!(dumpmask(0b111100), "2-5");
/// assert_eq!(dumpmask(0b11111100), "2-7");
/// ```
fn dumpmask(mut mask: u64) -> String {
    /// Helper: push a range (which may be a singleton) onto `v`.
    fn append(v: &mut Vec<String>, lo: u32, hi: u32) {
        if lo == hi {
            v.push(lo.to_string());
        } else {
            v.push(format!("{}-{}", lo, hi));
        }
    }
    // We'll be building up our result here, then joining it with
    // commas.
    let mut result = Vec::new();
    // This implementation is a little tricky, but it should be more
    // efficient than a raw search.  Basically, we're using the
    // function u64::trailing_zeros to count how large each range of
    // 1s or 0s is, and then shifting by that amount.

    // How many bits have we already shifted `mask`?
    let mut shift = 0;
    while mask != 0 {
        let zeros = mask.trailing_zeros();
        mask >>= zeros;
        shift += zeros;
        let ones = mask.trailing_ones();
        append(&mut result, shift, shift + ones - 1);
        shift += ones;
        if ones == 64 {
            // We have to do this check to avoid overflow when formatting
            // the range `0-63`.
            break;
        }
        mask >>= ones;
    }
    result.join(",")
}

/// The Display trait formats a protocol set in the format expected by Tor
/// consensus documents.
///
/// ```
/// use tor_protover::*;
/// let protos: Protocols = "Link=1,2,3 Foobar=7 Relay=2".parse().unwrap();
/// assert_eq!(format!("{}", protos),
///            "Foobar=7 Link=1-3 Relay=2");
/// ```
impl std::fmt::Display for Protocols {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entries = Vec::new();
        for (idx, mask) in self.recognized.iter().enumerate() {
            if *mask != 0 {
                let pk: ProtoKind = (idx as u16).into();
                entries.push(format!("{}={}", pk, dumpmask(*mask)));
            }
        }
        for ent in &self.unrecognized {
            if ent.supported != 0 {
                entries.push(format!(
                    "{}={}",
                    ent.proto.to_str(),
                    dumpmask(ent.supported)
                ));
            }
        }
        // This sort is required.
        entries.sort();
        write!(f, "{}", entries.join(" "))
    }
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
    fn test_bitrange() {
        assert_eq!(0b1, bitrange(0, 0));
        assert_eq!(0b10, bitrange(1, 1));
        assert_eq!(0b11, bitrange(0, 1));
        assert_eq!(0b1111110000000, bitrange(7, 12));
        assert_eq!(!0, bitrange(0, 63));
    }

    #[test]
    fn test_dumpmask() {
        assert_eq!("", dumpmask(0));
        assert_eq!("0-5", dumpmask(0b111111));
        assert_eq!("4-5", dumpmask(0b110000));
        assert_eq!("1,4-5", dumpmask(0b110010));
        assert_eq!("0-63", dumpmask(!0));
    }

    #[test]
    fn test_canonical() -> Result<(), ParseError> {
        fn t(orig: &str, canonical: &str) -> Result<(), ParseError> {
            let protos: Protocols = orig.parse()?;
            let enc = format!("{}", protos);
            assert_eq!(enc, canonical);
            Ok(())
        }

        t("", "")?;
        t(" ", "")?;
        t("Link=5,6,7,9 Relay=4-7,2", "Link=5-7,9 Relay=2,4-7")?;
        t("FlowCtrl= Padding=8,7 Desc=1-5,6-8", "Desc=1-8 Padding=7-8")?;
        t("Zelda=7 Gannon=3,6 Link=4", "Gannon=3,6 Link=4 Zelda=7")?;

        Ok(())
    }

    #[test]
    fn test_invalid() {
        fn t(s: &str) -> ParseError {
            let protos: Result<Protocols, ParseError> = s.parse();
            assert!(protos.is_err());
            protos.err().unwrap()
        }

        assert_eq!(t("Link=1-100"), ParseError::OutOfRange);
        assert_eq!(t("Zelda=100"), ParseError::OutOfRange);
        assert_eq!(t("Link=100-200"), ParseError::OutOfRange);

        assert_eq!(t("Link=1,1"), ParseError::Duplicate);
        assert_eq!(t("Link=1 Link=1"), ParseError::Duplicate);
        assert_eq!(t("Link=1 Link=3"), ParseError::Duplicate);
        assert_eq!(t("Zelda=1 Zelda=3"), ParseError::Duplicate);

        assert_eq!(t("Link=Zelda"), ParseError::Malformed);
        assert_eq!(t("Link=6-2"), ParseError::Malformed);
        assert_eq!(t("Link=6-"), ParseError::Malformed);
        assert_eq!(t("Link=6-,2"), ParseError::Malformed);
        assert_eq!(t("Link=1,,2"), ParseError::Malformed);
        assert_eq!(t("Link=6-frog"), ParseError::Malformed);
        assert_eq!(t("Link=gannon-9"), ParseError::Malformed);
        assert_eq!(t("Link Zelda"), ParseError::Malformed);

        assert_eq!(t("Link=01"), ParseError::Malformed);
        assert_eq!(t("Link=waffle"), ParseError::Malformed);
        assert_eq!(t("Link=1_1"), ParseError::Malformed);
    }

    #[test]
    fn test_supports() -> Result<(), ParseError> {
        let p: Protocols = "Link=4,5-7 Padding=2 Lonk=1-3,5".parse()?;

        assert!(p.supports_known_subver(ProtoKind::Padding, 2));
        assert!(!p.supports_known_subver(ProtoKind::Padding, 1));
        assert!(p.supports_known_subver(ProtoKind::Link, 6));
        assert!(!p.supports_known_subver(ProtoKind::Link, 255));
        assert!(!p.supports_known_subver(ProtoKind::Cons, 1));
        assert!(!p.supports_known_subver(ProtoKind::Cons, 0));
        assert!(p.supports_subver("Link", 6));
        assert!(!p.supports_subver("link", 6));
        assert!(!p.supports_subver("Cons", 0));
        assert!(p.supports_subver("Lonk", 3));
        assert!(!p.supports_subver("Lonk", 4));
        assert!(!p.supports_subver("lonk", 3));
        assert!(!p.supports_subver("Lonk", 64));

        Ok(())
    }
}
