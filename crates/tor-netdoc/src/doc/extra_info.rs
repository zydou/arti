//! Extra-Info Document Implementation.
//!
//! Historically, there were no microdescriptors and bootstrapping
//! involved downloading all router descriptors.  In order to save
//! space, various information not required for bootstrapping was
//! outsourced into an external document called extra-info, which
//! itself would then be referred to by original router descriptor.
//!
//! In times of microdescriptors, this has become meaningless, yet it
//! still continues to be a part of the protocol.
//!
//! <https://spec.torproject.org/dir-spec/extra-info-document-format.html>

use derive_deftly::Deftly;
use tor_cert::KeyUnknownCert;
use tor_llcrypto::pk::ed25519;

use crate::{
    doc::routerdesc::RouterDesc,
    parse2::VerifyFailed,
    types::{descriptor::*, *},
};

/// Additional information about a relay not contained in it's router
/// descriptor.
///
/// See the module documentation for more information.
///
/// <https://spec.torproject.org/dir-spec/extra-info-document-format.html>
#[derive(Debug, Clone, PartialEq, Deftly)]
#[derive_deftly(NetdocParseableUnverified, NetdocEncodable)]
#[non_exhaustive]
pub struct ExtraInfo {
    /// `extra-info` — Introduce a server's extra-info
    ///
    /// <https://spec.torproject.org/dir-spec/extra-info-document-format.html#extra-info>
    pub extra_info: ExtraInfoIntroItem,

    /// `identity-ed25519` --- Specify the router's ed25519 identity.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:identity-ed25519>
    pub identity_ed25519: EmbeddedCert<Ed25519IdentityCert, KeyUnknownCert>,

    /// `published` --- Time this descriptor (and extra-info) was generated.
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:published>
    #[deftly(netdoc(single_arg))]
    pub published: Iso8601TimeSp,
}

/// Signatures for an [`ExtraInfo`] document.
///
/// The signature logic is the same as with router descriptors.
///
/// Technically redundant because the hash is referenced by the router
/// descriptor in a signed fashion already.
#[derive(Debug, Clone, PartialEq, Deftly)]
#[derive_deftly(NetdocParseableSignatures, NetdocEncodable)]
#[deftly(netdoc(signatures(hashes_accu = "RouterHashAccu")))]
#[non_exhaustive]
pub struct ExtraInfoSignatures {
    /// `router-sig-ed25519` --- Ed25519 signature
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:router-sig-ed25519>
    pub router_sig_ed25519: RouterSigEd25519,

    /// `router-signature` --- RSA signature
    ///
    /// <https://spec.torproject.org/dir-spec/server-descriptor-format.html#item:router-signature>
    pub router_signature: RouterSignature,
}

/// Introduction line of an extra-info document.
///
/// <https://spec.torproject.org/dir-spec/extra-info-document-format.html#extra-info--introduce-a-servers-extra-info>
#[derive(Debug, Clone, PartialEq, Deftly)]
#[derive_deftly(ItemValueParseable, ItemValueEncodable)]
#[non_exhaustive]
pub struct ExtraInfoIntroItem {
    /// A valid router [`Nickname`].
    pub nickname: Nickname,
    /// Fingerprint of the router's RSA identity.
    pub fingerprint: Fingerprint,
}

impl ExtraInfoUnverified {
    /// Verifies an extra-info document.
    ///
    /// This verification *requires* an already verified [`RouterDesc`].
    ///
    /// We do not work with time bounded values here, because all respective
    /// time bounded values in extra-info documents match up with the respective
    /// values in their associated [`RouterDesc`].  Instead, we simply require
    /// [`RouterDesc`] to be timely for this to be timely as well.
    ///
    /// For an extra-info document to be valid, the following constraints apply:
    /// * [`RouterDesc::router`] implies [`ExtraInfoIntroItem::nickname`]
    /// * [`RouterDesc::signing_key`] implies [`ExtraInfoIntroItem::fingerprint`]
    /// * [`RouterDesc::identity_ed25519`] == [`ExtraInfo::identity_ed25519`]
    /// * [`RouterDesc::published`] == [`ExtraInfo::published`]
    /// * [`RouterDesc::extra_info_digest`] implies this document.
    /// * This document has valid signatures.
    pub fn verify(self, rd: &RouterDesc) -> Result<ExtraInfo, VerifyFailed> {
        let (mut body, sigs): (ExtraInfo, _) = (self.body, self.sigs);

        // Check whether the nicknames match.
        if rd.router.nickname != body.extra_info.nickname {
            return Err(VerifyFailed::Inconsistent);
        }

        // Check whether the fingerprint is as expected.
        // Keep in mind, that we cannot use the fingerprint field in the router
        // descriptor, as it is optional.
        if rd.signing_key.to_rsa_identity() != body.extra_info.fingerprint.0 {
            return Err(VerifyFailed::Inconsistent);
        }

        // Check whether the Ed25519 signing key certificate is the same.
        if rd.identity_ed25519.raw_unverified() != body.identity_ed25519.raw_unverified() {
            return Err(VerifyFailed::Inconsistent);
        }
        // We do not re-verify the certificate but rather clone it.
        // This is okay, because we just verified that the unverified form in
        // this document is equal to the unverified form in the already verified
        // router descriptor, which implies that verifying it would lead to the
        // same (verified) result again.
        body.identity_ed25519 = rd.identity_ed25519.clone();
        let sign_ed25519 = body
            .identity_ed25519
            .get()
            .expect("rd must contain verified identity_ed25519")
            .sign_ed25519;

        // Check whether the published timestamp is the same.
        if body.published != rd.published {
            return Err(VerifyFailed::Inconsistent);
        }

        // Already obtain the hashes we got by having hashed the document.
        // We need to do that now for the next check but need it later on too.
        // A failure of this accumulation is a full verification failure.
        let this_sha1 = sigs.hashes.sha1.ok_or(VerifyFailed::VerifyFailed)?;
        let this_sha256 = sigs.hashes.sha256.ok_or(VerifyFailed::VerifyFailed)?;

        // Check whether the router descriptor implies this document.
        // If this field is not set, we should have not obtained this document
        // in the first place ...
        let Some(expected_digests) = rd.extra_info_digest.as_ref() else {
            return Err(VerifyFailed::Inconsistent);
        };
        // TODO DIRMIRROR: IMPORTANT, we MUST also verify the SHA-256 hash.
        // However, we cannot use the normal hash accumulator due to a
        // long-standig bug in the ExtraInfoDigests value, where the indicated
        // value there refers to the full document (including the signature
        // bytes) and not up until "router-sig-ed25519 ".  The solution would
        // most likely involve writing a different accumulator for this and/or
        // extending RouterHashAccu with an additional field?
        if *expected_digests.sha1 != this_sha1 {
            return Err(VerifyFailed::Inconsistent);
        }

        // Verify the actual outer document signatures.
        ed25519::PublicKey::try_from(sign_ed25519)
            .map_err(|_| VerifyFailed::Other)?
            .verify(&this_sha256, &sigs.sigs.router_sig_ed25519.0)?;
        rd.signing_key
            .verify(&this_sha1, &sigs.sigs.router_signature.0)?;

        Ok(body)
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
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::collections::HashMap;

    use tor_checkable::TimeBound;

    use super::*;
    use crate::doc::routerdesc::RouterDescUnverified;
    use crate::parse2::{self, NetdocParseableUnverified, ParseInput};

    /// Simple test that just validates all extra-infos in testdata2/.
    #[test]
    fn simple() {
        // Obtain the accompanying router descriptors.
        let routers = parse2::parse_netdoc_multiple::<RouterDescUnverified>(&ParseInput::new(
            include_str!("../../testdata2/cached-descriptors.new"),
            "cached-descriptors",
        ))
        .unwrap()
        .into_iter()
        // We need to verify because we make use of the embedded certificats.
        // However, we skip the time verification because it is out of scope
        // for this module.
        .map(|rd| rd.verify().unwrap().dangerously_assume_timely())
        .collect::<Vec<RouterDesc>>();

        // Now, parse all extra info documents and store them by their hash.
        let extras_list = parse2::parse_netdoc_multiple::<ExtraInfoUnverified>(&ParseInput::new(
            include_str!("../../testdata2/cached-extrainfo.new"),
            "cached-extrainfo",
        ))
        .unwrap();
        let mut extras = HashMap::new();
        for extra in extras_list {
            // We need to use the sha1 due to a long-lived bug in the sha256,
            // whereas the field contains the signature over the entire document,
            // rather than just up until router-sig-ed25519 ...
            let sha1 = extra.inspect_unverified().1.hashes.sha1.unwrap();
            // Ensure there are no duplicates.
            assert!(extras.insert(sha1, extra).is_none());
        }

        // We now have all router descriptors and all extra infos in a
        // content-addressable store.  Now we iterate over every router
        // descriptor, look up the extra-info and take it from the hash
        // map, followed by an actual verification.  In the end, all
        // verification calls should have been successful and the HashMap
        // should be empty.
        for router in routers {
            let sha1 = router.extra_info_digest.clone().unwrap().sha1.0;
            let extra = extras.remove(&sha1).unwrap();
            extra.verify(&router).unwrap();
        }
        assert!(extras.is_empty());
    }
}
