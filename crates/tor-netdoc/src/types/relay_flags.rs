//! Relay flags (aka Router Status Flags), eg in network status documents

use std::collections::HashSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::str::FromStr;

use enumset::{EnumSet, EnumSetType, enum_set};
use thiserror::Error;

use tor_error::internal;

use super::Unknown;

/// Raw bits value for [`RelayFlags`]
pub type RelayFlagsBits = u16;

/// Router flags (aka relay flags), including, maybe, unknown ones
///
/// ### PartialEq implementation
///
/// `DocRelayFlags` implements `PartialEq`.
///
/// Two `DocRelayFlags` which both omit unknown flags (ie, contain `Unknown::Discarded`)
/// are treated as equal if they contain the same set of *known* flags.
/// This makes sense, because applications (like clients) that discard flags during netdoc
/// parsing *want* to completely ignore unknown flags, and want to have a working comparison
/// function for relay flags (eg to tell if two relays are similar enough).
///
/// Two `RelayFlags` only *one* of which retained unknown flags are treated as unequal.
/// Such a comparison is probably a bug, but panicking would be worse.
#[derive(Debug, Clone, derive_more::Deref, PartialEq)]
#[non_exhaustive]
pub struct DocRelayFlags {
    /// Known flags
    ///
    /// Invariant: contains no unknown set bits.
    #[deref]
    pub known: RelayFlags,

    /// Unknown flags, if they were parsed
    ///
    /// Not sorted.
    pub unknown: Unknown<HashSet<String>>,
}

/// Additional options for the representation of relay flags in network documents
///
/// This is a generic argument to `Parser`
/// (and will be used for the encoder too).
pub trait ReprMode: Debug + Copy {
    /// Flags that should be treated as being present when parsing
    ///
    /// Ie, they should be inferred even if they aren't actually listed in the document.
    ///
    /// But, when encoding, they should still be emitted.
    const PARSE_IMPLICIT: RelayFlags;

    /// Flags that should be treated as being present, and won't even be encoded.
    ///
    /// These are inferred when parsing, and omitted when encoding.
    ///
    /// (During parsing `ENCODE_OMIT` and `PARSE_IMPLICIT` flags are treated the same.)
    const ENCODE_OMIT: RelayFlags;
}

/// How relay flags are represented in a consensus
#[derive(Debug, Copy, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct ConsensusRepr;

impl ReprMode for ConsensusRepr {
    const PARSE_IMPLICIT: RelayFlags = enum_set!(RelayFlag::Running | RelayFlag::Valid);
    const ENCODE_OMIT: RelayFlags = RelayFlags::empty();
}

/// How relay flags are represented in a vote
#[derive(Debug, Copy, Clone)]
#[allow(clippy::exhaustive_structs)]
pub struct VoteRepr;

impl ReprMode for VoteRepr {
    const PARSE_IMPLICIT: RelayFlags = RelayFlags::empty();
    const ENCODE_OMIT: RelayFlags = RelayFlags::empty();
}

/// Set of (known) router status flags
///
/// Set of [`RelayFlag`], in a cheap and compact representation.
///
/// Can contain only flags known to this implementation.
/// This is a newtype around a machine integer.
///
/// Does not implement `ItemValueParseable`.  Parsing (and encoding) is different in
/// different documents.  Use an appropriate parameterised [`Parser`],
/// in `#[deftly(netdoc(with))]`.
///
/// To also maybe handle unknown flags, use [`DocRelayFlags`].
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:s>
pub type RelayFlags = EnumSet<RelayFlag>;

/// Router status flags - one recognized directory flag on a single relay.
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:s>
///
/// These flags come from a consensus directory document, and are
/// used to describe what the authorities believe about the relay.
/// If the document contained any flags that we _didn't_ recognize,
/// they are not listed in this type.
///
/// TODO SPEC: Make the terminology the same everywhere.
#[derive(Debug, strum::Display, strum::EnumString, strum::IntoStaticStr, EnumSetType)]
#[enumset(repr = "u16")] // Must be the same as RelayFlagBits
#[non_exhaustive]
pub enum RelayFlag {
    /// Is this a directory authority?
    Authority,
    /// Is this relay marked as a bad exit?
    ///
    /// Bad exits can be used as intermediate relays, but not to
    /// deliver traffic.
    BadExit,
    /// Is this relay marked as an exit for weighting purposes?
    Exit,
    /// Is this relay considered "fast" above a certain threshold?
    Fast,
    /// Is this relay suitable for use as a guard relay?
    ///
    /// Clients choose their their initial relays from among the set
    /// of Guard relays.
    Guard,
    /// Does this relay participate on the onion service directory
    /// ring?
    HSDir,
    /// Set if this relay is considered "middle only", not suitable to run
    /// as an exit or guard relay.
    ///
    /// Note that this flag is only used by authorities as part of
    /// the voting process; clients do not and should not act
    /// based on whether it is set.
    MiddleOnly,
    /// If set, there is no consensus for the ed25519 key for this relay.
    NoEdConsensus,
    /// Is this relay considered "stable" enough for long-lived circuits?
    Stable,
    /// Set if the authorities are requesting a fresh descriptor for
    /// this relay.
    StaleDesc,
    /// Set if this relay is currently running.
    ///
    /// This flag can appear in votes, but in consensuses, every relay
    /// is assumed to be running.
    Running,
    /// Set if this relay is considered "valid" -- allowed to be on
    /// the network.
    ///
    /// This flag can appear in votes, but in consensuses, every relay
    /// is assumed to be valid.
    Valid,
    /// Set if this relay supports a currently recognized version of the
    /// directory protocol.
    V2Dir,
}

/// Parsing helper for a relay flags line (eg `s` item in a routerdesc)
///
#[derive(Debug, Clone)]
pub struct Parser<'s, M: ReprMode> {
    /// Flags so far, including the implied ones
    flags: DocRelayFlags,

    /// The previous argument, if any
    ///
    /// Used only for checking that the arguments are sorted, as per the spec.
    prev: Option<&'s str>,

    /// The mode, which is just a type token
    repr_mode: PhantomData<M>,
}

/// Problem parsing a relay flags line
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum RelayFlagsParseError {
    /// Flags were not in lexical order by flag name
    #[error("Flags out of order")]
    OutOfOrder,
}

impl<'s, M: ReprMode> Parser<'s, M> {
    /// Start parsing relay flags
    ///
    /// If `PARSE_IMPLICIT` or `ENCODE_OMIT` contains unknown bits, compile will fail.
    pub fn new(unknown: Unknown<()>) -> Self {
        let known = M::PARSE_IMPLICIT | M::ENCODE_OMIT;
        Parser {
            flags: DocRelayFlags {
                known,
                unknown: unknown.map(|()| HashSet::new()),
            },
            prev: None,
            repr_mode: PhantomData,
        }
    }
    /// Parse the next relay flag argument
    pub fn add(&mut self, arg: &'s str) -> Result<(), RelayFlagsParseError> {
        if let Some(prev) = self.prev {
            if prev >= arg {
                // Arguments out of order.
                return Err(RelayFlagsParseError::OutOfOrder);
            }
        }
        match RelayFlag::from_str(arg) {
            Ok(fl) => self.flags.known |= fl,
            Err(_) => self.flags.unknown.with_mut_unknown(|u| {
                u.insert(arg.to_string());
            }),
        }

        self.prev = Some(arg);
        Ok(())
    }
    /// Finish parsing relay flags
    pub fn finish(self) -> DocRelayFlags {
        self.flags
    }
}

/// Old parser impl
mod parse_impl {
    use super::*;
    use crate::doc::netstatus::NetstatusKwd;
    use crate::parse::tokenize::Item;
    use crate::{Error, NetdocErrorKind as EK, Result};

    impl DocRelayFlags {
        /// Parse a relay-flags entry from an "s" line.
        pub(crate) fn from_item_consensus(item: &Item<'_, NetstatusKwd>) -> Result<DocRelayFlags> {
            if item.kwd() != NetstatusKwd::RS_S {
                return Err(
                    Error::from(internal!("Wrong keyword {:?} for S line", item.kwd()))
                        .at_pos(item.pos()),
                );
            }
            let mut flags = Parser::<ConsensusRepr>::new(Unknown::new_discard());

            for s in item.args() {
                flags
                    .add(s)
                    .map_err(|msg| EK::BadArgument.at_pos(item.pos()).with_msg(msg.to_string()))?;
            }

            Ok(flags.finish())
        }
    }
}

/// New parser impl
#[cfg(feature = "parse2")]
mod parse2_impl {
    use super::*;
    use crate::parse2;
    use parse2::ErrorProblem as EP;

    impl<'s, M: ReprMode> Parser<'s, M> {
        /// Parse relay flags
        #[allow(clippy::needless_pass_by_value)] // we must match trait signature
        pub(crate) fn from_unparsed(item: parse2::UnparsedItem<'_>) -> Result<DocRelayFlags, EP> {
            item.check_no_object()?;
            let mut flags = Self::new(item.parse_options().retain_unknown_values);
            for arg in item.args_copy() {
                flags
                    .add(arg)
                    .map_err(item.invalid_argument_handler("flags"))?;
            }
            Ok(flags.finish())
        }
    }
}
