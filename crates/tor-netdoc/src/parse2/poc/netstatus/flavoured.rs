//! network status documents - types that vary by flavour
//!
//! **This file is reincluded multiple times**,
//! once for each consensus flavour, and once for votes.
//!
//! Each time, with different behaviour for the macros `ns_***`.
//!
//! Thus, this file generates (for example) all three of:
//! `ns::NetworkStatus` aka `NetworkStatusNs`,
//! `NetworkStatusMd` and `NetworkStatusVote`.
//!
//! (We treat votes as a "flavour".)

use super::super::*;

/// Toplevel document string for error reporting
const TOPLEVEL_DOCTYPE_FOR_ERROR: &str =
    ns_expr!("NetworkStatusVote", "NetworkStatusNs", "NetworkStatusMd",);

/// The real router status entry type.
pub type Router = ns_type!(
    crate::doc::netstatus::VoteRouterStatus,
    crate::doc::netstatus::PlainRouterStatus,
    crate::doc::netstatus::MdRouterStatus,
);

/// Network status document (vote, consensus, or microdescriptor consensus) - body
///
/// The preamble items are members of this struct.
/// The rest are handled as sub-documents.
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(NetdocParseable, NetdocSigned)]
#[deftly(netdoc(doctype_for_error = "TOPLEVEL_DOCTYPE_FOR_ERROR"))]
#[non_exhaustive]
pub struct NetworkStatus {
    /// `network-status-version`
    pub network_status_version: (NdaNetworkStatusVersion, NdaNetworkStatusVersionFlavour),

    /// `vote-status`
    pub vote_status: NdiVoteStatus,

    /// `published`
    pub published: ns_type!((NdaSystemTimeDeprecatedSyntax,), Option<Void>,),

    /// `valid-after`
    pub valid_after: (NdaSystemTimeDeprecatedSyntax,),

    /// `valid-until`
    pub valid_until: (NdaSystemTimeDeprecatedSyntax,),

    /// `voting-delay`
    pub voting_delay: NdiVotingDelay,

    /// `params`
    #[deftly(netdoc(default))]
    pub params: NdiParams,

    /// Authority section
    #[deftly(netdoc(subdoc))]
    pub authority: NddAuthoritySection,

    /// `r` subdocuments
    #[deftly(netdoc(subdoc))]
    pub r: Vec<Router>,

    /// `directory-footer` section (which we handle as a sub-document)
    #[deftly(netdoc(subdoc))]
    pub directory_footer: Option<NddDirectoryFooter>,
}

/// Signatures on a network status document
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(NetdocParseable)]
#[deftly(netdoc(signatures))]
#[non_exhaustive]
pub struct NetworkStatusSignatures {
    /// `directory-signature`s
    pub directory_signature: ns_type!(NdiDirectorySignature, Vec<NdiDirectorySignature>),
}

/// `vote-status` value
///
/// In a non-demo we'd probably abolish this,
/// using `NdaStatus` directly in `NddNetworkStatus`
/// impl of `ItemValueParseable` for tuples.
#[derive(Deftly, Clone, Debug, Hash, Eq, PartialEq)]
#[derive_deftly(ItemValueParseable)]
#[non_exhaustive]
pub struct NdiVoteStatus {
    /// status
    pub status: NdaVoteStatus,
}

/// `vote-status` status argument (for a specific flavour)
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub struct NdaVoteStatus {}

/// `network-status-version` _flavour_ value
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
#[non_exhaustive]
pub struct NdaNetworkStatusVersionFlavour {}

/// The argument in `network-status-version` that is there iff it's a microdesc consensus.
const NDA_NETWORK_STATUS_VERSION_FLAVOUR: Option<&str> = ns_expr!(None, None, Some("microdesc"));

impl ItemArgumentParseable for NdaNetworkStatusVersionFlavour {
    fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, AE> {
        let exp: Option<&str> = NDA_NETWORK_STATUS_VERSION_FLAVOUR;
        if let Some(exp) = exp {
            let got = args.next().ok_or(AE::Missing)?;
            if got != exp {
                return Err(AE::Invalid);
            };
        } else {
            // NS consensus, or vote.  Reject additional arguments, since they
            // might be an unknown flavour.  See
            //   https://gitlab.torproject.org/tpo/core/torspec/-/issues/359
            args.reject_extra_args()?;
        }
        Ok(Self {})
    }
}

/// The document type argumnet in `vote-status`
const NDA_VOTE_STATUS: &str = ns_expr!("vote", "consensus", "consensus");

impl FromStr for NdaVoteStatus {
    type Err = InvalidNetworkStatusVoteStatus;
    fn from_str(s: &str) -> Result<Self, InvalidNetworkStatusVoteStatus> {
        if s == NDA_VOTE_STATUS {
            Ok(Self {})
        } else {
            Err(InvalidNetworkStatusVoteStatus {})
        }
    }
}

impl Display for NdaVoteStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(NDA_VOTE_STATUS, f)
    }
}

impl NormalItemArgument for NdaVoteStatus {}

/// `voting-delay` value
#[derive(Deftly, Clone, Debug, Hash, Eq, PartialEq)]
#[derive_deftly(ItemValueParseable)]
#[non_exhaustive]
pub struct NdiVotingDelay {
    /// VoteSeconds
    pub vote_seconds: u32,
    /// DistSeconds
    pub dist_seconds: u32,
}

/// `directory-footer` section
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(NetdocParseable)]
#[non_exhaustive]
pub struct NddDirectoryFooter {
    /// `directory-footer`
    pub directory_footer: (),
}

/// Authority Key Entry (in a network status document)
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(NetdocParseable)]
#[non_exhaustive]
pub struct NddAuthorityEntry {
    /// `dir-source`
    pub dir_source: NdiAuthorityDirSource,
}

/// `dir-source`
#[derive(Deftly, Clone, Debug)]
#[derive_deftly(ItemValueParseable)]
#[non_exhaustive]
pub struct NdiAuthorityDirSource {
    /// nickname
    pub nickname: types::Nickname,
    /// fingerprint
    pub h_p_auth_id_rsa: types::Fingerprint,
}

ns_choose! { (
    define_derive_deftly! {
        NddAuthoritySection:

        impl NetdocParseable for NddAuthoritySection {
            fn doctype_for_error() -> &'static str {
                "vote.authority.section"
            }
            fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
                NddAuthorityEntry::is_intro_item_keyword(kw)
            }
            fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
                NddAuthorityEntry::is_structural_keyword(kw)
                    .or_else(|| authcert::DirAuthKeyCertSigned::is_structural_keyword(kw))
            }
            fn from_items<'s>(
                input: &mut ItemStream<'s>,
                stop_outer: stop_at!(),
            ) -> Result<Self, ErrorProblem> {
                let stop_inner = stop_outer
                  $(
                    | StopAt($ftype::is_intro_item_keyword)
                  )
                ;
                Ok(NddAuthoritySection { $(
                    $fname: NetdocParseable::from_items(input, stop_inner)?,
                ) })
            }
        }
    }

    /// An authority section in a vote
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>
    //
    // We can't derive the parsing here with the normal macro, because it's not a document,
    // just a kind of ad-hoc thing which we've made into its own type
    // to avoid the NetworkStatus becoming very odd.
    #[derive(Deftly, Clone, Debug)]
    #[derive_deftly(NddAuthoritySection)]
    #[non_exhaustive]
    pub struct NddAuthoritySection {
        /// Authority entry
        pub authority: NddAuthorityEntry,
        /// Authority key certificate
        pub cert: crate::doc::authcert::EncodedAuthCert,
    }
)(
    /// An authority section in a consensus
    ///
    /// <https://spec.torproject.org/dir-spec/consensus-formats.html#section:authority>
    //
    // We can't derive the parsing here, because it's not a document,
    // just a kind of ad-hoc thing - and one which is quite weird.
    // https://gitlab.torproject.org/tpo/core/torspec/-/issues/361
    #[derive(Deftly, Clone, Debug)]
    #[non_exhaustive]
    pub struct NddAuthoritySection {
        /// The authority entries.
        ///
        /// Proper entries precede superseded ones.
        pub authorities: Vec<NddAuthorityEntryOrSuperseded>,
    }

    /// An element of an authority section in a consensus
    #[derive(Clone, Debug)]
    #[non_exhaustive]
    pub enum NddAuthorityEntryOrSuperseded {
        /// Proper Authority Entry
        Entry(NddAuthorityEntry),
        /// Superseded Key Authority
        ///
        /// `nickname` contains the value *with* `-legacy`
        Superseded(NdiAuthorityDirSource),
    }

    impl NetdocParseable for NddAuthoritySection {
        fn doctype_for_error() -> &'static str {
            "consensus.authority.section"
        }
        fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
            NddAuthorityEntry::is_intro_item_keyword(kw)
        }
        fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
            NddAuthorityEntry::is_structural_keyword(kw)
        }
        fn from_items(
            input: &mut ItemStream<'_>,
            stop_outer: stop_at!(),
        ) -> Result<Self, ErrorProblem> {
            let is_our_keyword = NddAuthorityEntry::is_intro_item_keyword;
            let stop_inner = stop_outer | StopAt(is_our_keyword);
            let mut authorities = vec![];
            while let Some(peek) = input.peek_keyword()? {
                if !is_our_keyword(peek) { break };

                // But is it a superseded entry or not?
                let mut lookahead = input.clone();
                let _: UnparsedItem<'_> = lookahead.next().expect("peeked")?;

                let entry = match lookahead.next().transpose()? {
                    Some(item) if !stop_inner.stop_at(item.keyword()) => {
                        // Non-structural item.  Non-superseded entry.
                        let entry = NddAuthorityEntry::from_items(input, stop_inner)?;
                        NddAuthorityEntryOrSuperseded::Entry(entry)
                    }
                    None | Some(_) => {
                        // EOF, or the item is another dir-source, or the item
                        // is the start of the next document at the next outer level
                        // (eg a router status entry)
                        let item = input.next().expect("just peeked")?;
                        let entry = NdiAuthorityDirSource::from_unparsed(item)?;
                        if !entry.nickname.as_str().ends_with("-legacy") {
                            return Err(EP::OtherBadDocument(
 "authority entry lacks mandatory fields (eg `contact`) so is not a proper (non-superseded) entry, but nickname lacks `-legacy` suffix so is not a superseded entry"
                            ))
                        }
                        NddAuthorityEntryOrSuperseded::Superseded(entry)
                    }
                };
                authorities.push(entry);
            }
            if !authorities.is_sorted_by_key(
                |entry| matches!(entry, NddAuthorityEntryOrSuperseded::Superseded(_))
            ) {
                return Err(EP::OtherBadDocument(
 "normal (non-superseded) authority entry follows superseded authority key entry"
                ))
            }

            Ok(NddAuthoritySection { authorities })
        }
    }
)}

ns_choose! { (
    impl NetworkStatusSigned {
        /// Verify this vote's signatures using the embedded certificate
        ///
        /// # Security considerations
        ///
        /// The caller should use `NetworkStatus::h_kp_auth_id_rsa`
        /// to find out which voters vote this is.
        pub fn verify_selfcert(
            self,
            now: SystemTime,
        ) -> Result<(NetworkStatus, NetworkStatusSignatures), VF> {
            let validity = *self.body.published.0 ..= *self.body.valid_until.0;
            check_validity_time(now, validity)?;

            let cert = self.body.parse_authcert()?.verify_selfcert(now)?;

            netstatus::verify_general_timeless(
                slice::from_ref(&self.signatures.directory_signature),
                &[*cert.fingerprint],
                &[&cert],
                1,
            )?;

            Ok(self.unwrap_unverified())
        }
    }

    impl NetworkStatus {
        /// Parse the embedded authcert
        fn parse_authcert(&self) -> Result<crate::doc::authcert::AuthCertSigned, EP> {
            let cert_input = ParseInput::new(
                self.authority.cert.as_str(),
                "<embedded auth cert>",
            );
            parse_netdoc(&cert_input).map_err(|e| e.problem)
        }

        /// Voter identity
        ///
        /// # Security considerations
        ///
        /// The returned identity has been confirmed to have properly certified
        /// this vote at this time.
        ///
        /// It is up to the caller to decide whether this identity is actually
        /// a voter, count up votes, etc.
        pub fn h_kp_auth_id_rsa(&self) -> pk::rsa::RsaIdentity {
            *self.parse_authcert()
                // SECURITY: if the user calls this function, they have a bare
                // NetworkStatus, not a NetworkStatusSigned, so parsing
                // and verification has already been done in verify_selfcert above.
                .expect("was verified already!")
                .inspect_unverified()
                .0
                .fingerprint
        }
    }
) (
    impl NetworkStatusSigned {
        /// Verify this consensus document
        ///
        /// # Security considerations
        ///
        /// The timeliness verification is relaxed, and incorporates the `DistSeconds` skew.
        /// The caller **must not use** the returned consensus before its `valid_after`,
        /// and must handle `fresh_until`.
        ///
        /// `authorities` should be a list of the authorities
        /// that the caller trusts.
        ///
        /// `certs` is a list of dir auth key certificates to use to try to link
        /// the signed consensus to those authorities.
        /// Extra certificates in `certs`, that don't come from anyone in `authorities`,
        /// are ignored.
        pub fn verify(
            self,
            now: SystemTime,
            authorities: &[pk::rsa::RsaIdentity],
            certs: &[&DirAuthKeyCert],
        ) -> Result<(NetworkStatus, NetworkStatusSignatures), VF> {
            let threshold = authorities.len() / 2 + 1; // strict majority
            let validity_start = self.body.valid_after.0
                .checked_sub(Duration::from_secs(self.body.voting_delay.dist_seconds.into()))
                .ok_or(VF::Other)?;
            check_validity_time(now, validity_start..= *self.body.valid_until.0)?;

            netstatus::verify_general_timeless(
                &self.signatures.directory_signature,
                authorities,
                certs,
                threshold,
            )?;

            Ok(self.unwrap_unverified())
        }
    }
)}
