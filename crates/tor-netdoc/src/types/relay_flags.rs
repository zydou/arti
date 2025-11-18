//! Relay flags (aka Router Status Flags), eg in network status documents

use std::collections::HashSet;

use enumset::{EnumSet, EnumSetType, enum_set};
use paste::paste;
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
#[derive(Debug, Clone, derive_more::Deref)]
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

/// Flags that are implied by existence of a relay in a consensus.
pub const RELAY_FLAGS_CONSENSUS_PARSE_IMPLICIT: RelayFlags =
    enum_set!(RelayFlag::RUNNING | RelayFlag::VALID);
/// Flags that are implied by existence of a relay in a consensus and not even stated there.
pub const RELAY_FLAGS_CONSENSUS_ENCODE_OMIT: RelayFlags = RelayFlags::empty();

/// Relay flags parsing as found in the consensus (md or plain)
pub(crate) type ConsensusRelayFlagsParser<'s> = RelayFlagsParser<
    's,
    { RELAY_FLAGS_CONSENSUS_PARSE_IMPLICIT.as_repr() },
    { RELAY_FLAGS_CONSENSUS_ENCODE_OMIT.as_repr() },
>;

/// Relay flags parsing as found in votes.
pub(crate) type VoteRelayFlagsParser<'s> = RelayFlagsParser<'s, 0, 0>;

/// Set of (known) router status flags
///
/// Set of [`RelayFlag`], in a cheap and compact representation.
///
/// Can contain only flags known to this implementation.
/// This is a newtype around a machine integer.
///
/// Does not implement `ItemValueParseable`.  Parsing (and encoding) is different in
/// different documents.  Use an appropriate parameterised [`RelayFlagsParser`],
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

/// Define conversions for `RelayFlags` to and from the netdoc keyword
///
/// The arguments are the netdoc flag keywords.
/// Every constant in the bitlfags must be in this list, and vice versa.
/// They are automatically recased in this macro to geet the corresponding Rust constants.
///
/// (Sadly we still need to list the keywords a second time, because we
/// can't sensibly derive from the bitlfags! input.)
///
/// `bitflags` would let us access the flags and access their names,
/// but it has no compile-time rename, so we would need to do run-time
/// re-casing (from netdoc keywords in pascal case to Rust constants in shouty snake case.).
/// We don't want to do that while parsing flags in routerstatus entries.
///
/// Generates the `FromStr` impl (which is weird, see [`RelayFlags`]),
/// and [`RelayFlag::set_iter_keywords`] for encoding flags in netdocs.
macro_rules! relay_flags_keywords { { $($keyword:ident)* } => { paste! {
    impl RelayFlag {
      $(
        /// Transitional constant - XXXX will be deleted
        pub const [< $keyword:snake:upper >]: RelayFlag = RelayFlag::$keyword;
      )*
    }

    impl RelayFlag {
        /// Parses *one* relay flag
        ///
        /// This function is not a `FromStr` impl.
        /// It recognises only a single flag at a time.
        //
        // XXXX abolish this and just use FromStr instead.
        #[allow(clippy::result_unit_err)] // internal function for RelayParser
        fn from_str_one(s: &str) -> Result<Self, ()> {
            s.parse().map_err(|_| ())
        }
    }

    impl RelayFlag {
        /// Report the keywords for the flags in this set
        ///
        /// If there are unknown bits in the flags, yields `Err` for those, once.
        // ^ XXXX this no longer makes any sense.
        ///
        /// The values are yielded in an arbitrary order.
        // XXXX this whole method is going to be deleted
        pub fn set_iter_keywords(self_: &RelayFlags) -> impl Iterator<Item = Result<&'static str, RelayFlags>> {
            self_.iter().map(|f| f.into()).map(Ok)
        }
    }
} } }

relay_flags_keywords! {
    Authority
    BadExit
    Exit
    Fast
    Guard
    HSDir
    MiddleOnly
    NoEdConsensus
    Stable
    StaleDesc
    Running
    Valid
    V2Dir
}

impl PartialEq for DocRelayFlags {
    fn eq(&self, other: &DocRelayFlags) -> bool {
        let DocRelayFlags { known, unknown } = self;
        known.as_repr() == other.known.as_repr() && unknown == &other.unknown
    }
}

/// Parsing helper for a relay flags line (eg `s` item in a routerdesc)
///
/// `PARSE_IMPLICIT` lists flags that should be treated as being present when parsing,
/// even if they aren't actually listed in the document.
///
/// `ENCODE_OMIT` lists flags that should be treated as being present,
/// and won't even be encoded.
///
/// (During parsing `ENCODE_OMIT` and `PARSE_IMPLICIT` flags are treated the same.)
#[derive(Debug, Clone)]
pub struct RelayFlagsParser<
    's,
    const PARSE_IMPLICIT: RelayFlagsBits,
    const ENCODE_OMIT: RelayFlagsBits,
> {
    /// Flags so far, including the implied ones
    flags: DocRelayFlags,

    /// The previous argument, if any
    ///
    /// Used only for checking that the arguments are sorted, as per the spec.
    prev: Option<&'s str>,
}

/// Problem parsing a relay flags line
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum RelayFlagsParseError {
    /// Flags were not in lexical order by flag name
    #[error("Flags out of order")]
    OutOfOrder,
}

impl<'s, const PARSE_IMPLICIT: RelayFlagsBits, const ENCODE_OMIT: RelayFlagsBits>
    RelayFlagsParser<'s, PARSE_IMPLICIT, ENCODE_OMIT>
{
    /// Start parsing relay flags
    ///
    /// If `PARSE_IMPLICIT` or `ENCODE_OMIT` contains unknown bits, compile will fail.
    pub fn new(unknown: Unknown<()>) -> Self {
        let known: RelayFlags = {
            /// The starting bits, as an integer.  Can't be a `const` or `let` for Rust Reasons.
            macro_rules! BITS { {} => { PARSE_IMPLICIT | ENCODE_OMIT } }
            // Prove, at compile-time, that the generic parameters contain no bad bits
            const {
                let wrong = BITS!() & !RelayFlags::all().as_repr();
                if wrong != 0 {
                    panic!()
                }
            };
            RelayFlags::try_from_repr(BITS!()).expect("but we checked!")
        };
        RelayFlagsParser {
            flags: DocRelayFlags {
                known,
                unknown: unknown.map(|()| HashSet::new()),
            },
            prev: None,
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
        match RelayFlag::from_str_one(arg) {
            Ok(fl) => self.flags.known |= fl,
            Err(()) => self.flags.unknown.with_mut_unknown(|u| {
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
            let mut flags = RelayFlagsParser::<
                { RELAY_FLAGS_CONSENSUS_PARSE_IMPLICIT.as_repr() },
                { RELAY_FLAGS_CONSENSUS_ENCODE_OMIT.as_repr() },
            >::new(Unknown::new_discard());

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

    impl<'s, const PARSE_IMPLICIT: RelayFlagsBits, const ENCODE_OMIT: RelayFlagsBits>
        RelayFlagsParser<'s, PARSE_IMPLICIT, ENCODE_OMIT>
    {
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

    #[test]
    fn relay_flags_keywords() {
        // Check that the macro lists all the known flags.
        // (If the macro has unknown flags, it won't compile.)
        for f in RelayFlag::set_iter_keywords(&RelayFlags::all()) {
            assert!(
                f.is_ok(),
                "flag {f:?} not listed in `relay_flags_keywords!` call"
            );
        }
    }
}
