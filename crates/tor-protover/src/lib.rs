#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![allow(renamed_and_removed_lints)] // @@REMOVE_WHEN(ci_arti_stable)
#![allow(unknown_lints)] // @@REMOVE_WHEN(ci_arti_nightly)
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
#![deny(clippy::unchecked_time_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::mod_module_files)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
#![allow(clippy::needless_lifetimes)] // See arti#1765
#![allow(mismatched_lifetime_syntaxes)] // temporary workaround for arti#2060
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

#![allow(non_upper_case_globals)]
#![allow(clippy::upper_case_acronyms)]

use std::sync::Arc;

use caret::caret_int;

use thiserror::Error;
use tor_basic_utils::intern::InternCache;

pub mod named;

caret_int! {
    /// A recognized subprotocol.
    ///
    /// These names are kept in sync with the names used in consensus
    /// documents; the values are kept in sync with the values in the
    /// cbor document format in the walking onions proposal.
    ///
    /// For the full semantics of each subprotocol, see tor-spec.txt.
    #[derive(Hash,Ord,PartialOrd)]
    pub struct ProtoKind(u8) {
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
        Microdesc = 8,
        /// Describing the network as a consensus directory document.
        Cons = 9,
        /// Sending and accepting circuit-level padding
        Padding = 10,
        /// Improved means of flow control on circuits.
        FlowCtrl = 11,
        /// Multi-path circuit support.
        Conflux = 12,
    }
}

/// How many recognized protocols are there?
const N_RECOGNIZED: usize = 13;

/// Maximum allowable value for a protocol's version field.
const MAX_VER: usize = 63;

/// A specific, named subversion of a protocol.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct NamedSubver {
    /// The protocol in question
    ///
    /// Must be in-range for ProtoKind (0..N_RECOGNIZED).
    kind: ProtoKind,
    /// The version of the protocol
    ///
    /// Must be in 0..=MAX_VER
    version: u8,
}

impl NamedSubver {
    /// Create a new NamedSubver.
    ///
    /// # Panics
    ///
    /// Panics if `kind` is unrecognized or `version` is invalid.
    const fn new(kind: ProtoKind, version: u8) -> Self {
        assert!((kind.0 as usize) < N_RECOGNIZED);
        assert!((version as usize) <= MAX_VER);
        Self { kind, version }
    }
}

/// A subprotocol capability as represented by a (kind, version) tuple.
///
/// Does not necessarily represent a real subprotocol capability;
/// this type is meant for use in other pieces of the protocol.
///
/// # Ordering
///
/// Instances of `NumberedSubver` are sorted in lexicographic order by
/// their (kind, version) tuples.
//
// TODO: As with most other types in the crate, we should decide how to rename them as as part
// of #1934.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct NumberedSubver {
    /// The protocol in question
    kind: ProtoKind,
    /// The version of the protocol
    version: u8,
}

impl NumberedSubver {
    /// Construct a new [`NumberedSubver`]
    pub fn new(kind: impl Into<ProtoKind>, version: u8) -> Self {
        Self {
            kind: kind.into(),
            version,
        }
    }
    /// Return the ProtoKind and version for this [`NumberedSubver`].
    pub fn into_parts(self) -> (ProtoKind, u8) {
        (self.kind, self.version)
    }
}
impl From<NamedSubver> for NumberedSubver {
    fn from(value: NamedSubver) -> Self {
        Self {
            kind: value.kind,
            version: value.version,
        }
    }
}

#[cfg(feature = "tor-bytes")]
impl tor_bytes::Readable for NumberedSubver {
    fn take_from(b: &mut tor_bytes::Reader<'_>) -> tor_bytes::Result<Self> {
        let kind = b.take_u8()?;
        let version = b.take_u8()?;
        Ok(Self::new(kind, version))
    }
}

#[cfg(feature = "tor-bytes")]
impl tor_bytes::Writeable for NumberedSubver {
    fn write_onto<B: tor_bytes::Writer + ?Sized>(&self, b: &mut B) -> tor_bytes::EncodeResult<()> {
        b.write_u8(self.kind.into());
        b.write_u8(self.version);
        Ok(())
    }
}

/// Representation for a known or unknown protocol.
#[derive(Eq, PartialEq, Clone, Debug, Hash, Ord, PartialOrd)]
enum Protocol {
    /// A known protocol; represented by one of ProtoKind.
    ///
    /// ProtoKind must always be in the range 0..N_RECOGNIZED.
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
///
/// # Implementation notes
///
/// Because the number of distinct `Protocols` sets at any given time
/// is much smaller than the number of relays, this type is interned in order to
/// save memory and copying time.
///
/// This type is an Arc internally; it is cheap to clone.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::DeserializeFromStr, serde_with::SerializeDisplay)
)]
pub struct Protocols(Arc<ProtocolsInner>);

/// Inner representation of Protocols.
///
/// We make this a separate type so that we can intern it inside an Arc.
#[derive(Default, Clone, Debug, Eq, PartialEq, Hash)]
struct ProtocolsInner {
    /// A mapping from protocols' integer encodings to bit-vectors.
    recognized: [u64; N_RECOGNIZED],
    /// A vector of unrecognized protocol versions,
    /// in sorted order.
    ///
    /// Every entry in this list has supported != 0.
    unrecognized: Vec<SubprotocolEntry>,
}

/// An InternCache of ProtocolsInner.
///
/// We intern ProtocolsInner objects because:
///  - There are very few _distinct_ values in any given set of relays.
///  - Every relay has one.
///  - We often want to copy them when we're remembering information about circuits.
static PROTOCOLS: InternCache<ProtocolsInner> = InternCache::new();

impl From<ProtocolsInner> for Protocols {
    fn from(value: ProtocolsInner) -> Self {
        Protocols(PROTOCOLS.intern(value))
    }
}

impl Protocols {
    /// Return a new empty set of protocol versions.
    ///
    /// # Warning
    ///
    /// To the extend possible, avoid using empty lists to represent the capabilities
    /// of an unknown target.  Instead, if there is a consensus present, use the
    /// `required-relay-protocols` field of the consensus.
    pub fn new() -> Self {
        Protocols::default()
    }

    /// Helper: return true iff this protocol set contains the
    /// version `ver` of the protocol represented by the integer `proto`.
    fn supports_recognized_ver(&self, proto: usize, ver: u8) -> bool {
        if usize::from(ver) > MAX_VER {
            return false;
        }
        if proto >= self.0.recognized.len() {
            return false;
        }
        (self.0.recognized[proto] & (1 << ver)) != 0
    }
    /// Helper: return true iff this protocol set contains version
    /// `ver` of the unrecognized protocol represented by the string
    /// `proto`.
    ///
    /// Requires that `proto` is not the name of a recognized protocol.
    fn supports_unrecognized_ver(&self, proto: &str, ver: u8) -> bool {
        if usize::from(ver) > MAX_VER {
            return false;
        }
        let ent = self
            .0
            .unrecognized
            .iter()
            .find(|ent| ent.proto.is_unrecognized(proto));
        match ent {
            Some(e) => (e.supported & (1 << ver)) != 0,
            None => false,
        }
    }

    /// Return true if this list of protocols is empty.
    pub fn is_empty(&self) -> bool {
        self.0.recognized.iter().all(|v| *v == 0)
            && self.0.unrecognized.iter().all(|p| p.supported == 0)
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

    /// Check whether a protocol version is supported.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Link=1-5 Desc=2-4".parse().unwrap();
    /// assert!(protos.supports_named_subver(named::DESC_FAMILY_IDS)); // Desc=4
    /// assert!(! protos.supports_named_subver(named::CONFLUX_BASE)); // Conflux=1
    /// ```
    pub fn supports_named_subver(&self, protover: NamedSubver) -> bool {
        self.supports_known_subver(protover.kind, protover.version)
    }

    /// Check whether a numbered subprotocol capability is supported.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Link=1-5 Desc=2-4".parse().unwrap();
    /// assert!(protos.supports_numbered_subver(NumberedSubver::new(ProtoKind::Desc, 4)));
    /// assert!(! protos.supports_numbered_subver(NumberedSubver::new(ProtoKind::Conflux, 1)));
    /// ```
    pub fn supports_numbered_subver(&self, protover: NumberedSubver) -> bool {
        self.supports_known_subver(protover.kind, protover.version)
    }

    /// Return a Protocols holding every protocol flag that is present in `self`
    /// but not `other`.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Desc=2-4 Microdesc=1-5".parse().unwrap();
    /// let protos2: Protocols = "Desc=3 Microdesc=3".parse().unwrap();
    /// assert_eq!(protos.difference(&protos2),
    ///            "Desc=2,4 Microdesc=1-2,4-5".parse().unwrap());
    /// ```
    pub fn difference(&self, other: &Protocols) -> Protocols {
        let mut r = ProtocolsInner::default();

        for i in 0..N_RECOGNIZED {
            r.recognized[i] = self.0.recognized[i] & !other.0.recognized[i];
        }
        // This is not super efficient, but we don't have to do it often.
        for ent in self.0.unrecognized.iter() {
            let mut ent = ent.clone();
            if let Some(other_ent) = other.0.unrecognized.iter().find(|e| e.proto == ent.proto) {
                ent.supported &= !other_ent.supported;
            }
            if ent.supported != 0 {
                r.unrecognized.push(ent);
            }
        }
        Protocols::from(r)
    }

    /// Return a Protocols holding every protocol flag that is present in `self`
    /// or `other` or both.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Desc=2-4 Microdesc=1-5".parse().unwrap();
    /// let protos2: Protocols = "Desc=3 Microdesc=10".parse().unwrap();
    /// assert_eq!(protos.union(&protos2),
    ///            "Desc=2-4 Microdesc=1-5,10".parse().unwrap());
    /// ```
    pub fn union(&self, other: &Protocols) -> Protocols {
        let mut r = (*self.0).clone();
        for i in 0..N_RECOGNIZED {
            r.recognized[i] |= other.0.recognized[i];
        }
        for ent in other.0.unrecognized.iter() {
            if let Some(my_ent) = r.unrecognized.iter_mut().find(|e| e.proto == ent.proto) {
                my_ent.supported |= ent.supported;
            } else {
                r.unrecognized.push(ent.clone());
            }
        }
        r.unrecognized.sort();
        Protocols::from(r)
    }

    /// Return a Protocols holding every protocol flag that is present in both `self`
    /// and `other`.
    ///
    /// ```
    /// use tor_protover::*;
    /// let protos: Protocols = "Desc=2-4 Microdesc=1-5".parse().unwrap();
    /// let protos2: Protocols = "Desc=3 Microdesc=10".parse().unwrap();
    /// assert_eq!(protos.intersection(&protos2),
    ///            "Desc=3".parse().unwrap());
    /// ```
    pub fn intersection(&self, other: &Protocols) -> Protocols {
        let mut r = ProtocolsInner::default();
        for i in 0..N_RECOGNIZED {
            r.recognized[i] = self.0.recognized[i] & other.0.recognized[i];
        }
        for ent in self.0.unrecognized.iter() {
            if let Some(other_ent) = other.0.unrecognized.iter().find(|e| e.proto == ent.proto) {
                let supported = ent.supported & other_ent.supported;
                if supported != 0 {
                    r.unrecognized.push(SubprotocolEntry {
                        proto: ent.proto.clone(),
                        supported,
                    });
                }
            }
        }
        r.unrecognized.sort();
        Protocols::from(r)
    }
}

impl ProtocolsInner {
    /// Parsing helper: Try to add a new entry `ent` to this set of protocols.
    ///
    /// Uses `foundmask`, a bit mask saying which recognized protocols
    /// we've already found entries for.  Returns an error if `ent` is
    /// for a protocol we've already added.
    ///
    /// Does not preserve sorting order; the caller must call `self.unrecognized.sort()` before returning.
    fn add(&mut self, foundmask: &mut u64, ent: SubprotocolEntry) -> Result<(), ParseError> {
        match ent.proto {
            Protocol::Proto(k) => {
                let idx = k.get() as usize;
                assert!(idx < N_RECOGNIZED); // guaranteed by invariant on Protocol::Proto
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
                if ent.supported != 0 {
                    self.unrecognized.push(ent);
                }
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
            if lo > (MAX_VER as u64) || hi > (MAX_VER as u64) {
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
        let mut result = ProtocolsInner::default();
        let mut foundmask = 0_u64;
        for ent in s.split(' ') {
            if ent.is_empty() {
                continue;
            }

            let s: SubprotocolEntry = ent.parse()?;
            result.add(&mut foundmask, s)?;
        }
        result.unrecognized.sort();
        Ok(result.into())
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
        for (idx, mask) in self.0.recognized.iter().enumerate() {
            if *mask != 0 {
                let pk: ProtoKind = (idx as u8).into();
                entries.push(format!("{}={}", pk, dumpmask(*mask)));
            }
        }
        for ent in &self.0.unrecognized {
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

impl FromIterator<NamedSubver> for Protocols {
    fn from_iter<T: IntoIterator<Item = NamedSubver>>(iter: T) -> Self {
        let mut r = ProtocolsInner::default();
        for named_subver in iter {
            let proto_idx = usize::from(named_subver.kind.get());
            let proto_ver = named_subver.version;

            // These are guaranteed by invariants on NamedSubver.
            assert!(proto_idx < N_RECOGNIZED);
            assert!(usize::from(proto_ver) <= MAX_VER);
            r.recognized[proto_idx] |= 1_u64 << proto_ver;
        }
        Protocols::from(r)
    }
}

/// Documentation: when is a protocol "supported"?
///
/// Arti should consider itself to "support" a protocol if, _as built_,
/// it implements the protocol completely.
///
/// Just having the protocol listed among the [`named`]
/// protocols is not enough, and neither is an incomplete
/// or uncompliant implementation.
///
/// Similarly, if the protocol is not compiled in,
/// it is not technically _supported_.
///
/// When in doubt, ask yourself:
/// - If another Tor implementation believed that we implemented this protocol,
///   and began to speak it to us, would we be able to do so?
/// - If the protocol were required,
///   would this software as built actually meet that requirement?
///
/// If either answer is no, the protocol is not supported.
pub mod doc_supported {}

/// Documentation about changing lists of supported versions.
///
/// # Warning
///
/// You need to be extremely careful when removing
/// _any_ entry from a list of supported protocols.
///
/// If you remove an entry while it still appears as "recommended" in the consensus,
/// you'll cause all the instances without it to warn.
///
/// If you remove an entry while it still appears as "required" in the
///  consensus, you'll cause all the instances without it to refuse to connect
/// to the network, and shut down.
///
/// If you need to remove a version from a list of supported protocols,
/// you need to make sure that it is not listed in the _current consensuses_:
/// just removing it from the list that the authorities vote for is NOT ENOUGH.
/// You need to remove it from the required list,
/// and THEN let the authorities upgrade and vote on new
/// consensuses without it. Only once those consensuses are out is it safe to
/// remove from the list of required protocols.
///
/// ## Example
///
/// One concrete example of a very dangerous race that could occur:
///
/// Suppose that the client supports protocols "HsDir=1-2" and the consensus
/// requires protocols "HsDir=1-2".  If the client supported protocol list is
/// then changed to "HSDir=2", while the consensus stills lists "HSDir=1-2",
/// then these clients, even very recent ones, will shut down because they
/// don't support "HSDir=1".
///
/// And so, changes need to be done in strict sequence as described above.
pub mod doc_changing {}

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
    use std::str::FromStr;

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

    #[test]
    fn test_difference() -> Result<(), ParseError> {
        let p1: Protocols = "Link=1-10 Desc=5-10 Relay=1,3,5,7,9 Other=7-60 Mine=1-20".parse()?;
        let p2: Protocols = "Link=3-4 Desc=1-6 Relay=2-6 Other=8 Theirs=20".parse()?;

        assert_eq!(
            p1.difference(&p2),
            Protocols::from_str("Link=1-2,5-10 Desc=7-10 Relay=1,7,9 Other=7,9-60 Mine=1-20")?
        );
        assert_eq!(
            p2.difference(&p1),
            Protocols::from_str("Desc=1-4 Relay=2,4,6 Theirs=20")?,
        );

        let nil = Protocols::default();
        assert_eq!(p1.difference(&nil), p1);
        assert_eq!(p2.difference(&nil), p2);
        assert_eq!(nil.difference(&p1), nil);
        assert_eq!(nil.difference(&p2), nil);

        Ok(())
    }

    #[test]
    fn test_union() -> Result<(), ParseError> {
        let p1: Protocols = "Link=1-10 Desc=5-10 Relay=1,3,5,7,9 Other=7-60 Mine=1-20".parse()?;
        let p2: Protocols = "Link=3-4 Desc=1-6 Relay=2-6 Other=2,8 Theirs=20".parse()?;

        assert_eq!(
            p1.union(&p2),
            Protocols::from_str(
                "Link=1-10 Desc=1-10 Relay=1-7,9 Other=2,7-60 Theirs=20 Mine=1-20"
            )?
        );
        assert_eq!(
            p2.union(&p1),
            Protocols::from_str(
                "Link=1-10 Desc=1-10 Relay=1-7,9 Other=2,7-60 Theirs=20 Mine=1-20"
            )?
        );

        let nil = Protocols::default();
        assert_eq!(p1.union(&nil), p1);
        assert_eq!(p2.union(&nil), p2);
        assert_eq!(nil.union(&p1), p1);
        assert_eq!(nil.union(&p2), p2);

        Ok(())
    }

    #[test]
    fn test_intersection() -> Result<(), ParseError> {
        let p1: Protocols = "Link=1-10 Desc=5-10 Relay=1,3,5,7,9 Other=7-60 Mine=1-20".parse()?;
        let p2: Protocols = "Link=3-4 Desc=1-6 Relay=2-6 Other=2,8 Theirs=20".parse()?;

        assert_eq!(
            p1.intersection(&p2),
            Protocols::from_str("Link=3-4 Desc=5-6 Relay=3,5 Other=8")?
        );
        assert_eq!(
            p2.intersection(&p1),
            Protocols::from_str("Link=3-4 Desc=5-6 Relay=3,5 Other=8")?
        );

        let nil = Protocols::default();
        assert_eq!(p1.intersection(&nil), nil);
        assert_eq!(p2.intersection(&nil), nil);
        assert_eq!(nil.intersection(&p1), nil);
        assert_eq!(nil.intersection(&p2), nil);

        Ok(())
    }

    #[test]
    fn from_iter() {
        use named as n;
        let empty: [NamedSubver; 0] = [];
        let prs: Protocols = empty.iter().copied().collect();
        assert_eq!(prs, Protocols::default());
        let prs: Protocols = empty.into_iter().collect();
        assert_eq!(prs, Protocols::default());

        let prs = [
            n::LINK_V3,
            n::HSDIR_V3,
            n::LINK_V4,
            n::LINK_V5,
            n::CONFLUX_BASE,
        ]
        .into_iter()
        .collect::<Protocols>();
        assert_eq!(prs, "Link=3-5 HSDir=2 Conflux=1".parse().unwrap());
    }

    #[test]
    fn order_numbered_subvers() {
        // We rely on this sort order elsewhere in our protocol.
        assert!(NumberedSubver::new(5, 7) < NumberedSubver::new(7, 5));
        assert!(NumberedSubver::new(7, 5) < NumberedSubver::new(7, 6));
        assert!(NumberedSubver::new(7, 6) < NumberedSubver::new(8, 6));
    }
}
