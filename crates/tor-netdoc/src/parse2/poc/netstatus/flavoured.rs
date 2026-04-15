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
#[derive_deftly(NetdocParseableUnverified)]
#[deftly(netdoc(doctype_for_error = TOPLEVEL_DOCTYPE_FOR_ERROR))]
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
#[derive_deftly(NetdocParseableSignatures)]
#[deftly(netdoc(signatures(hashes_accu = "DirectorySignaturesHashesAccu")))]
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

/// The document type argument in `vote-status`
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
    use VoteAuthoritySection as NddAuthoritySection;
)(
    use ConsensusAuthoritySection as NddAuthoritySection;
)}

ns_choose! { (
    impl NetworkStatusUnverified {
        /// Verify this vote's signatures using the embedded certificate
        ///
        /// # Security considerations
        ///
        /// The caller should use `NetworkStatus::h_kp_auth_id_rsa`
        /// to find out which voter's vote this is.
        pub fn verify_selfcert(
            self,
            now: SystemTime,
        ) -> Result<(NetworkStatus, SignaturesData<NetworkStatusUnverified>), VF> {
            let validity = *self.body.published.0 ..= *self.body.valid_until.0;
            check_validity_time(now, validity)?;

            let cert = self.body.parse_authcert()?.verify_selfcert(now)?;

            netstatus::verify_general_timeless(
                &self.sigs.hashes,
                slice::from_ref(&self.sigs.sigs.directory_signature),
                &[*cert.fingerprint],
                &[&cert],
                1,
            )?;

            Ok(self.unwrap_unverified())
        }
    }

    impl NetworkStatus {
        /// Parse the embedded authcert
        fn parse_authcert(&self) -> Result<crate::doc::authcert::AuthCertUnverified, EP> {
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
                // NetworkStatus, not a NetworkStatusUnverified, so parsing
                // and verification has already been done in verify_selfcert above.
                .expect("was verified already!")
                .inspect_unverified()
                .0
                .fingerprint
        }
    }
) (
    impl NetworkStatusUnverified {
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
        ) -> Result<(NetworkStatus, SignaturesData<NetworkStatusUnverified>), VF> {
            let threshold = authorities.len() / 2 + 1; // strict majority
            let validity_start = self.body.valid_after.0
                .checked_sub(Duration::from_secs(self.body.voting_delay.dist_seconds.into()))
                .ok_or(VF::Other)?;
            check_validity_time(now, validity_start..= *self.body.valid_until.0)?;

            netstatus::verify_general_timeless(
                &self.sigs.hashes,
                &self.sigs.sigs.directory_signature,
                authorities,
                certs,
                threshold,
            )?;

            Ok(self.unwrap_unverified())
        }
    }
)}
