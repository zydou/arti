//! Shared types between router descriptors and extra-info documents.
//!
//! For now, this only includes code related to signatures.
//!
//! Despite this being used by router descriptors and extra-info documents,
//! many types inside this module are prefixed with "router".  We keep this
//! prefix because we want the type names to align with the item keyword,
//! which is the same in both documents.

use crate::{
    encode::NetdocEncoder,
    parse2::{
        ErrorProblem as EP, ItemArgumentParseable, SignatureHashInputs, SignatureItemParseable,
        UnparsedItem,
    },
    types::FixedB64,
};

use derive_deftly::Deftly;

use digest::Digest;
use tor_error::Bug;
use tor_llcrypto::pk::ed25519;

/// Accumulator for router descriptor hash signatures.
#[derive(Debug, Clone, Default, Deftly)]
#[derive_deftly(AsMutSelf)]
#[allow(clippy::exhaustive_structs)]
pub struct RouterHashAccu {
    /// Potentially the SHA-1 for the signature.
    pub sha1: Option<[u8; 20]>,
    /// Potentially the SHA-256 for the signature.
    pub sha256: Option<[u8; 32]>,
}

/// SHA-256 router descriptor signature including magic and the keyword.
#[derive(Debug, Clone, PartialEq, Eq, Deftly)]
#[derive_deftly(ItemValueEncodable)]
#[allow(clippy::exhaustive_structs)]
// TODO SPEC is RouterSigEd25519 not a standard-ish kind of signature?
// TODO DIRAUTH is RouterSigEd25519 not a standard-ish kind of signature?
pub struct RouterSigEd25519(pub ed25519::Signature);

impl RouterSigEd25519 {
    /// The magic prefix for hashing this type of signature.
    //
    // TODO DIRMIRROR have the old parser's verification code use this
    // constant, thereby de-duplicating.
    const HASH_PREFIX_MAGIC: &str = "Tor router descriptor signature v1";

    /// Calculate the hash for signature
    ///
    /// `signature_item_kw_spc` is the keyword *with a trailing space*.
    /// It's `&[&str]` for the convenience of the two call sites.
    fn hash(document_sofar: &str, signature_item_kw_spc: &[&str]) -> [u8; 32] {
        debug_assert!(
            signature_item_kw_spc
                .last()
                .expect("signature_item_kw_spc")
                .ends_with(" ")
        );
        let mut h = tor_llcrypto::d::Sha256::new();
        h.update(Self::HASH_PREFIX_MAGIC);
        h.update(document_sofar);
        for b in signature_item_kw_spc {
            h.update(b);
        }
        h.finalize().into()
    }

    /// Make a signature during document encoding
    ///
    /// `item_keyword` is the keyword for the signature item.
    ///
    /// # Example
    ///
    /// ```
    /// use derive_deftly::Deftly;
    /// use tor_error::Bug;
    /// use tor_llcrypto::pk::ed25519;
    /// use tor_netdoc::derive_deftly_template_NetdocEncodable;
    /// use tor_netdoc::encode::{NetdocEncodable, NetdocEncoder};
    /// use tor_netdoc::types::descriptor::RouterSigEd25519;
    ///
    /// #[derive(Deftly, Default)]
    /// #[derive_deftly(NetdocEncodable)]
    /// pub struct Document {
    ///     pub document_intro_keyword: (),
    /// }
    /// #[derive(Deftly)]
    /// #[derive_deftly(NetdocEncodable)]
    /// pub struct DocumentSignatures {
    ///     pub document_signature: RouterSigEd25519,
    /// }
    /// impl Document {
    ///     pub fn encode_sign(&self, k: &ed25519::Keypair) -> Result<String, Bug> {
    ///         let mut encoder = NetdocEncoder::new();
    ///         self.encode_unsigned(&mut encoder)?;
    ///         let document_signature =
    ///             RouterSigEd25519::new_sign_netdoc(k, &encoder, "document-signature")?;
    ///         let sigs = DocumentSignatures { document_signature };
    ///         sigs.encode_unsigned(&mut encoder)?;
    ///         let encoded = encoder.finish()?;
    ///         Ok(encoded)
    ///     }
    /// }
    ///
    /// # fn main() -> Result<(), anyhow::Error> {
    /// let k = ed25519::Keypair::generate(&mut tor_basic_utils::test_rng::testing_rng());
    /// let doc = Document::default();
    /// let encoded = doc.encode_sign(&k)?;
    /// assert!(encoded.starts_with(concat!(
    ///     "document-intro-keyword\n",
    ///     "document-signature ",
    /// )));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_sign_netdoc(
        private_key: &ed25519::Keypair,
        encoder: &NetdocEncoder,
        item_keyword: &str,
    ) -> Result<Self, Bug> {
        let signature = private_key
            .sign(&Self::hash(encoder.text_sofar()?, &[item_keyword, " "]))
            .to_bytes()
            .into();
        Ok(RouterSigEd25519(signature))
    }
}

impl SignatureItemParseable for RouterSigEd25519 {
    type HashAccu = RouterHashAccu;

    fn from_unparsed_and_body(
        mut item: UnparsedItem<'_>,
        hash_inputs: &SignatureHashInputs<'_>,
        hash: &mut Self::HashAccu,
    ) -> Result<Self, EP> {
        // TODO DIRMIRROR break this out into impl ItemArgumentParseable for Signature
        let args = item.args_mut();
        let sig = FixedB64::<64>::from_args(args)
            .map_err(|e| args.handle_error("router-sig-ed25519", e))?
            .0;
        let sig = ed25519::Signature::from(sig);
        hash.sha256 = Some(Self::hash(
            hash_inputs.document_sofar,
            &[hash_inputs.signature_item_kw_spc],
        ));
        Ok(Self(sig))
    }
}

/// SHA-1 router descriptor signature over `router-sig-ed25519`.
// TODO DIRMIRROR Is this not the same as RsaSha1Signature ?
#[derive(Debug, Clone, PartialEq, Eq, Deftly)]
#[derive_deftly(ItemValueEncodable)]
#[allow(clippy::exhaustive_structs)]
pub struct RouterSignature(
    #[deftly(netdoc(object(label = "SIGNATURE"), with = crate::types::raw_data_object))] pub Vec<u8>,
);

impl SignatureItemParseable for RouterSignature {
    type HashAccu = RouterHashAccu;

    fn from_unparsed_and_body(
        mut item: UnparsedItem<'_>,
        hash_inputs: &SignatureHashInputs<'_>,
        hash: &mut Self::HashAccu,
    ) -> Result<Self, EP> {
        // There must be no additonal arguments.
        let args = item.args_mut();
        if args.next().is_some() {
            return Err(EP::UnexpectedArgument {
                column: args.prev_arg_column(),
            });
        }
        let obj = item.object().ok_or(EP::MissingObject)?.decode_data()?;

        let mut h = tor_llcrypto::d::Sha1::new();
        h.update(hash_inputs.document_sofar);
        h.update(hash_inputs.signature_item_line);
        h.update("\n");
        hash.sha1 = Some(h.finalize().into());

        Ok(Self(obj))
    }
}
