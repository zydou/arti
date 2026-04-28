//! `dir-source` items, including the mutant `-legacy` version
//!
//! A `dir-source` line is normally an authority entry.
//! But it might also be a "superseded authority key entry".
//! That has a "nickname" ending in `-legacy` and appears only in consensuses.
//! (Note that `-legacy` is not legal syntax for a nickname.)
//!
//! <https://spec.torproject.org/dir-spec/consensus-formats.html#item:dir-source>
//!
//! This module will also handle the decoding of consensus authority sections,
//! which are fiddly because they can contain a mixture of things.
//!
//! <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>

use super::*;
use std::result::Result;

/// Keyword, which we need to recapitulate because of all the ad-hoc parsing
const DIR_SOURCE_KEYWORD: &str = "dir-source";

/// Nickname suffix for superseded authority key entries
const SUPERSEDED_SUFFIX: &str = "-legacy";

define_derive_deftly! {
    /// Derive `SupersededAuthorityKey` and its impls
    ///
    /// This includes `SomeDirSource`, a parsing helper type.
    ///
    /// This macro exists to avoid recapitulating the `dir-source` line field list many times.
    /// (The `ItemValueParseable` derive doesn't support `#[deftly(netdoc(flatten))]` for args.)
    SupersededAuthorityKey for struct:

    ${defcond F_NORMAL not(approx_equal($fname, nickname))}

    ${define DEFINE_NORMAL_FIELDS { $(
        ${when F_NORMAL}
        ${fattrs !_no_such_attr} // derive-deftly has no way to say all attrs even deftly
        $fname: $ftype,
    ) }}

    /// A `dir-source` line that *is* a "superseded authority key entry"
    ///
    /// Construct using [`from_dir_source`](SupersededAuthorityKey::from_dir_source).
    ///
    // The fields are private and we don't use Constructor because otherwise a caller
    // could create a SupersededAuthorityKey with mismatched `real_nickname` and
    // `raw_nickname_string` which would encode surprisingly.
    //
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:dir-source>
    #[derive(Debug, Clone, Deftly, amplify::Getters)]
    #[derive_deftly(ItemValueEncodable)]
    #[derive_deftly_adhoc] // ignore deftly attrs directed at Constructor
    pub struct SupersededAuthorityKey {
        /// Real nickname for this authority, not including the `-legacy`
        #[deftly(netdoc(skip))]
        real_nickname: Nickname,

        /// The raw nickname, including "-legacy"
        // We want #[getter(as_deref)] but it doesn't exist.  We open-code it, below.
        #[getter(skip)]
        raw_nickname_string: String,

        $DEFINE_NORMAL_FIELDS
    }

    impl SupersededAuthorityKey {
        /// The raw nickname, including "-legacy"
        pub fn raw_nickname_string(&self) -> &str {
            &self.raw_nickname_string
        }

        /// Make a superseded authority key entry from the data in a `DirSource`
        ///
        /// `ds.nickname` is the real nickname (without `-legacy`).
        // We don't need to check this because `-` is not allowed in a Nickname.
        ///
        /// `ds.fingerprint` is the *superseded* key.
        pub fn from_dir_source(ds: DirSource) -> Self {
            SupersededAuthorityKey {
                raw_nickname_string: format!("{}{SUPERSEDED_SUFFIX}", ds.nickname),
                real_nickname: ds.nickname,
                $( ${when F_NORMAL} $fname: ds.$fname, )
            }
        }
    }

    /// A `dir-source` line with unchecked nickname
    ///
    /// Used for parsing a superseded authority key entry.
    ///
    /// This is not quite the same as `DirSource`, because `DirSource` has a `Nickname`
    /// but the superseded entries' `-legacy` values are not valid nicknames.
    ///
    /// We can't derive `ItemValueParseable` for `SupersededAuthorityKey`,
    /// because we can't parse the `real_nickname` field.
    /// Instead we derive `ItemValueParseable` on this and convert it ad-hoc
    /// in `ConsensusAuthoritySection`'s parser.
    #[derive(Debug, Clone, Deftly)]
    #[derive_deftly(ItemValueParseable)]
    #[derive_deftly_adhoc] // ignore deftly attrs directed at Constructor
    struct RawDirSource {
        /// Raw nickname, as parsed
        raw_nickname_string: String,

        $DEFINE_NORMAL_FIELDS
    }

    impl RawDirSource {
        /// Convert into the public representation.
        fn into_superseded(self) -> Result<SupersededAuthorityKey, ErrorProblem> {
            let RawDirSource { raw_nickname_string, .. } = self;
            let real_nickname = raw_nickname_string
                .strip_suffix(SUPERSEDED_SUFFIX)
                .ok_or(ErrorProblem::Internal("RawDirSource::into_superseded for non `-legacy`"))?
                .parse()
                .map_err(|_: InvalidNickname| ErrorProblem::InvalidArgument {
                    field: "invalid nickname even after stripping `-legacy`",
                    column: DIR_SOURCE_KEYWORD.len() + 1, // urgh
                })?;
            Ok(SupersededAuthorityKey {
                real_nickname,
                raw_nickname_string,
                $( ${when F_NORMAL} $fname: self.$fname, )
            })
        }
    }
}

/// Description of an authority's identity and address.
///
/// Corresponds to a dir-source line which is *not* a "superseded authority key entry".
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#item:dir-source>
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor, ItemValueParseable, ItemValueEncodable)]
#[derive_deftly(SupersededAuthorityKey)]
#[allow(clippy::exhaustive_structs)]
pub struct DirSource {
    /// human-readable nickname for this authority.
    #[deftly(constructor)]
    pub nickname: Nickname,

    /// Fingerprint for the _authority_ identity key of this
    /// authority.
    ///
    /// This is the same key as the one that signs the authority's
    /// certificates.
    #[deftly(constructor)]
    pub identity: Fingerprint,

    /// IP address for the authority
    #[deftly(constructor)]
    pub hostname: InternetHost,

    /// IP address for the authority
    #[deftly(constructor(default = { net::Ipv6Addr::UNSPECIFIED.into() }))]
    pub ip: net::IpAddr,

    /// HTTP directory port for this authority
    pub dir_port: u16,

    /// OR port for this authority.
    pub or_port: u16,

    #[doc(hidden)]
    #[deftly(netdoc(skip))]
    pub __non_exhaustive: (),
}

/// Authority section as found in a consensus
///
/// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>
///
/// Note that though you can construct one with an empty `authorities` field,
/// that will generate a `Bug` when you encode it.
///
/// For votes, see [`VoteAuthoritySection`]
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(Constructor)]
#[allow(clippy::exhaustive_structs)]
pub struct ConsensusAuthoritySection {
    /// Authority entries
    ///
    /// Always nonempty when parsed; must be nonempty or encoding will fail with `Bug`.
    //
    // If the user wants to provide an empty vec, at least force them to write it out.
    #[deftly(constructor)]
    pub authorities: Vec<ConsensusAuthorityEntry>,

    /// Superseded authority key entries
    pub superseded_keys: Vec<SupersededAuthorityKey>,

    #[doc(hidden)]
    pub __non_exhaustive: (),
}

impl NetdocEncodable for ConsensusAuthoritySection {
    fn encode_unsigned(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
        // bind all fields so that if any are added we remember to encode them
        let ConsensusAuthoritySection {
            authorities,
            superseded_keys,
            __non_exhaustive,
        } = self;

        if authorities.is_empty() {
            return Err(internal!("tried to encode a consensus with 0 authorities"));
        }
        for a in authorities {
            a.encode_unsigned(out)?;
        }
        for s in superseded_keys {
            let out = out.item(DIR_SOURCE_KEYWORD);
            s.write_item_value_onto(out)?;
        }
        Ok(())
    }
}

impl NetdocParseable for ConsensusAuthoritySection {
    fn doctype_for_error() -> &'static str {
        "consensus.authorities"
    }

    fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
        ConsensusAuthorityEntry::is_intro_item_keyword(kw)
    }

    fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
        ConsensusAuthorityEntry::is_structural_keyword(kw)
    }

    fn from_items(input: &mut ItemStream<'_>, stop_at: stop_at!()) -> Result<Self, ErrorProblem> {
        let mut accum = ConsensusAuthoritySection {
            authorities: vec![],
            superseded_keys: vec![],
            __non_exhaustive: (),
        };

        while let Some(peeked) = input.peek_keyword()? {
            if !Self::is_intro_item_keyword(peeked) {
                break;
            }

            // Well, this is pretty terrible
            let rest = &input.whole_input()[input.byte_position()..];
            let line = rest.split_once('\n').map(|(l, _)| l).unwrap_or(rest);
            let mut line = line.split_ascii_whitespace();
            assert_eq!(line.next(), Some(DIR_SOURCE_KEYWORD));
            let raw_nickname = line
                .next()
                .ok_or(ErrorProblem::MissingArgument { field: "nickname" })?;

            if raw_nickname.ends_with(SUPERSEDED_SUFFIX) {
                let item = input.next().expect("peeked")?;
                let s = RawDirSource::from_unparsed(item)?.into_superseded()?;
                accum.superseded_keys.push(s);
            } else {
                let a = ConsensusAuthorityEntry::from_items(input, stop_at)?;
                accum.authorities.push(a);
            }
        }

        if accum.authorities.is_empty() {
            return Err(ErrorProblem::MissingItem {
                keyword: DIR_SOURCE_KEYWORD,
            });
        }

        Ok(accum)
    }
}
