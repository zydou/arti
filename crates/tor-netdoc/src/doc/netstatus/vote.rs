//! Implementation for plain consensus documents.
//
// Read this file in conjunction with `each_variety.rs`.
// See "module scope" ns_variety_definition_macros.rs.

use super::*;

// Import `each_variety.rs`, appropriately variegated
ns_do_variety_vote! {}

/// Used for reporting errors when parsing this document type
const NETSTATUS_DOCTYPE_FOR_ERROR: &str = "network status vote";

/// The forbidden flavor keyword in a vote consensus heading line
///
/// This type is one of the fields in `NetworkStatusVersionItem`.
///
/// Votes start with `network-status-version 3`
/// and aren't allowed to have a variety.
///
/// So in *this* variety, we insist that there are no more arguments.
///
/// See also torspec#359.
pub type VarietyKeyword = NoMoreArguments;

impl NetworkStatusUnverified {
    /// Verify the signatures
    ///
    /// Doesn't check the validity period:
    /// the document is wrapped in [`TimeRangeBound`],
    /// ensuring that the caller does that check.
    pub fn verify(
        self,
        trusted: &mut VoteVerifier,
    ) -> Result<TimeRangeBound<NetworkStatus>, VoteVerifyFailed> {
        use VoteVerifyFailed as VVF;

        let (mut body, sigs) = self.unwrap_unverified();

        let authcert = {
            let input = parse2::ParseInput::new(
                body.authority.cert.raw_unverified().as_ref(),
                "<authcert>",
            );
            let authcert = parse2::parse_netdoc::<AuthCertUnverified>(&input)
                .map_err(VVF::AuthCertParseError)?;
            let authcert = authcert.verify(&trusted.trusted).map_err(VVF::InvalidSignature)?;

            // We do the authcert validity time check here, with reference to
            // the vote's declared validity period, not the current time or whatever.
            let test_validity_at = |t| {
                authcert
                    .check_valid_at(&t)
                    .map_err(VVF::AuthCertWrongValidity)
            };

            // test at all relevant times, in a uniform way so we can break out check
            test_validity_at(*body.preamble.lifetime.valid_after)?;
            test_validity_at(*body.preamble.lifetime.fresh_until)?;
            test_validity_at(*body.preamble.lifetime.valid_until)?;
            authcert.dangerously_assume_timely() // we just checked it ^ there
        };

        let authority = body.authority.authority.dir_source.identity;
        if authority != authcert.fingerprint {
            return Err(VVF::AuthCertWrongAuthority);
        }

        SignatureGroup {
            hashes: sigs.hashes,
            signatures: vec![sigs.sigs.directory_signature],
        }
        .verify_general(
            VerifyGeneralTrustedAuthorities::AnyOneOfThese { trusted: &trusted.trusted },
            slice::from_ref(&authcert),
            |tv| tv.verify().map_err(VVF::InvalidSignature),
        )?;

        if !trusted.remaining_good.remove(&*authority) {
            return Err(VVF::DuplicateAuthority(*authority));
        }

        body.authority.cert.set_verified(authcert);

        let time_range = body.preamble.validity_time_range();
        Ok(TimeRangeBound::new(body, time_range))
    }

    /// Look at the declared directory authority identity KHP_auth_id_rsa
    ///
    /// This tells you what the vote says the issuing authority is,
    /// but note that the signatures haven't been checked,
    /// so this information should be used with care.
    pub fn peek_alleged_authority(&self) -> RsaIdentity {
        *self
            .inspect_unverified()
            .0
            .authority
            .authority
            .dir_source
            .identity
    }
}

impl From<ConsensusVerifiabilityError> for VoteVerifyFailed {
    fn from(cve: ConsensusVerifiabilityError) -> VoteVerifyFailed {
        use ConsensusVerifiabilityError as CVE;
        use VerifyFailed as VF;
        use VoteVerifyFailed as VVF;

        match cve {
            CVE::InsufficientTrustedSigners => {
                VVF::InvalidSignature(VF::InsufficientTrustedSigners)
            }
            CVE::MissingAuthCerts { .. } => {
                // this should be impossible, because we checked the authcert was right
                VVF::AuthCertWrongAuthority
            }
        }
    }
}
