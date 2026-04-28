//! Test/example for `EmbeddedCert`

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
#![allow(clippy::disallowed_methods)] // SystemTime::now()
#![allow(unreachable_pub)] // pedagogy

use crate::encode::{NetdocEncodable, NetdocEncoder};
use crate::parse2::{ParseInput, VerifyFailed, parse_netdoc};
use crate::types::routerdesc::{RouterHashAccu, RouterSigEd25519};
use crate::types::{B64, EmbeddableCertObject, EmbeddedCert, RetainedOrderVec};
use derive_deftly::Deftly;
use std::time::{Duration, SystemTime};
use tor_cert::{Ed25519Cert, KeyUnknownCert};
use tor_checkable::{SelfSigned, Timebound};
use tor_error::{Bug, into_internal};
use tor_llcrypto::pk::ed25519::{self, Ed25519Identity, Ed25519PublicKey};

//----- cert type -----

// NOTE this type is probably not suitable for promoting to production as-is!
#[derive(Debug, Clone)]
pub struct FamilyCert {
    pub family_name: String,
}

impl EmbeddableCertObject<KeyUnknownCert> for FamilyCert {
    const LABEL: &str = "FAMILY CERT";
}

impl FamilyCert {
    fn from_kp_familyid(kp_familyid_ed: Ed25519Identity) -> Self {
        let family_name = format!("ed25519:{}", B64(kp_familyid_ed.as_bytes().to_vec()));
        FamilyCert { family_name }
    }

    pub fn new_signed(
        ks_familyid_ed: &ed25519::Keypair,
        kp_relayid_ed: Ed25519Identity,
        expiry: SystemTime,
    ) -> Result<EmbeddedCert<FamilyCert, KeyUnknownCert>, Bug> {
        let cert = Ed25519Cert::builder()
            .expiration(expiry)
            .signing_key(ks_familyid_ed.public_key().into())
            .cert_type(tor_cert::CertType::FAMILY_V_IDENTITY)
            .cert_key(kp_relayid_ed.into())
            .encode_and_sign(ks_familyid_ed)
            .map_err(into_internal!("failed to encode and sign family cert"))?;

        let family = FamilyCert::from_kp_familyid(ks_familyid_ed.public_key().into());
        let cert =
            Ed25519Cert::decode(&cert).map_err(into_internal!("re-decode just-parsed cert"))?;

        Ok(EmbeddedCert::new(family, cert))
    }

    pub fn verify(cert: KeyUnknownCert, now: SystemTime) -> Result<Self, VerifyFailed> {
        let cert = cert
            .should_have_signing_key()
            .map_err(|_| VerifyFailed::Inconsistent)?
            .check_signature()?
            .check_valid_at(&now)?;
        let family = cert
            .signing_key()
            .expect("we just checked that it had signing key");

        Ok(FamilyCert::from_kp_familyid(*family))
    }
}

//----- document type -----

#[derive(Debug, Clone, Deftly)]
#[derive_deftly(NetdocEncodable, NetdocParseableUnverified)]
pub struct RouterDesc {
    pub router: (), // dummy, for example
    pub family_cert: RetainedOrderVec<EmbeddedCert<FamilyCert, KeyUnknownCert>>,
}

#[derive(Debug, Clone, Deftly)]
#[derive_deftly(NetdocEncodable, NetdocParseableSignatures)]
#[deftly(netdoc(signatures(hashes_accu = RouterHashAccu)))]
pub struct RouterDescSignatures {
    pub router_sig_ed25519: RouterSigEd25519,
}

impl RouterDesc {
    pub fn encode_sign(&self, k_relaysign_ed: &ed25519::Keypair) -> Result<String, Bug> {
        let mut encoder = NetdocEncoder::new();
        self.encode_unsigned(&mut encoder)?;
        let router_sig_ed25519 =
            RouterSigEd25519::new_sign_netdoc(k_relaysign_ed, &encoder, "router_sig_ed25519")?;
        let signatures = RouterDescSignatures { router_sig_ed25519 };
        signatures.encode_unsigned(&mut encoder)?;
        encoder.finish()
    }
}

impl RouterDescUnverified {
    pub fn verify_self_signed(mut self, now: SystemTime) -> Result<RouterDesc, VerifyFailed> {
        for entry in &mut *self.body.family_cert {
            let verified = FamilyCert::verify(entry.raw_unverified().clone(), now)?;
            entry.set_verified(verified);
        }

        // INCOMPLETE: should verify outer signature on document!  etc.
        Ok(self.body)
    }
}

//----- usage -----

#[test]
fn main() -> anyhow::Result<()> {
    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(86400);
    let mut rng = tor_basic_utils::test_rng::testing_rng();

    let k_familyid = ed25519::Keypair::from_bytes(&[0x12; 32]);
    let k_relayid = ed25519::Keypair::generate(&mut rng);
    let k_relaysign = ed25519::Keypair::generate(&mut rng);

    let family = FamilyCert::new_signed(&k_familyid, k_relayid.public_key().into(), expiry)?;
    let routerdesc = RouterDesc {
        router: (),
        family_cert: vec![family].into(),
    };
    let encoded = routerdesc.encode_sign(&k_relaysign)?;

    let unverified: RouterDescUnverified = parse_netdoc(&ParseInput::new(&encoded, "<example>"))?;
    let verified = unverified.verify_self_signed(now)?;

    assert_eq!(
        verified.family_cert[0].get()?.family_name,
        "ed25519:IEBA42TBDyvsnB/lAKHNTCR8idZQoB7X6CyrqGeHfCE",
    );

    Ok(())
}
