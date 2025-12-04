//! Handling of netdoc signatures
//
// TODO use tor_checkable to provide a generic .verify function.
//
// But the tor_checkable API might need some updates and this seems nontrivial.
// Each verification function seems to take different inputs.

use saturating_time::SaturatingTime;

use super::*;

/// A signature item that can appear in a netdoc
///
/// This is the type `T` of a field `item: T` in a netdoc signatures section type.
///
/// Types that implement this embody both:
///
///   * The item, parameters, and signature data, provided in the document.
///   * The hash of the document body, which will needed during verification.
///
/// Typically derived with
/// [`#[derive_deftly(ItemValueParseable)]`](derive_deftly_template_ItemValueParseable).
///
/// Normal (non-signature) items implement [`ItemValueParseable`].
pub trait SignatureItemParseable: Sized {
    /// Parse the item's value
    fn from_unparsed_and_body(
        item: UnparsedItem<'_>,
        document_body: &SignatureHashInputs<'_>,
    ) -> Result<Self, ErrorProblem>;
}

/// The part of a network document before the first signature item
///
/// This is used for both Regular signatures
/// where the hash does not contain any part of the signature Item
/// (of which there are none yet)
/// and Irregular signatures
/// where the hash contains part of the signature Item.
///
/// See <https://gitlab.torproject.org/tpo/core/torspec/-/issues/322>.
//
// This type exists as a separate newtype mostly to avoid mistakes inside
// parser implementations, where lots of different strings are floating about.
// In particular, the parser must save this value when it starts parsing
// signatures and must then reuse it for later ones.
#[derive(Copy, Debug, Clone, Eq, PartialEq, Hash, amplify::Getters)]
pub struct SignedDocumentBody<'s> {
    /// The actual body as a string
    #[getter(as_copy)]
    pub(crate) body: &'s str,
}

/// Inputs needed to calculate a specific signature hash for a specific Item
///
/// Embodies:
///
///  * `&str` for the body, as for `SignedDocumentBody`.
///    For calculating Regular signatures.
///
///  * Extra information for calculating Irregular signatures.
///    Irregular signature Items can only be implemented within this crate.
#[derive(Copy, Debug, Clone, Eq, PartialEq, Hash, amplify::Getters)]
pub struct SignatureHashInputs<'s> {
    /// The Regular body
    #[getter(as_copy)]
    pub(crate) body: SignedDocumentBody<'s>,
    /// The signature item keyword and the following space
    #[getter(skip)]
    pub(crate) signature_item_kw_spc: &'s str,
    /// The whole signature item keyword line not including the final newline
    #[getter(skip)]
    pub(crate) signature_item_line: &'s str,
}

impl<'s> SignatureHashInputs<'s> {
    /// Hash into `h` the body and the whole of the signature item's keyword line
    pub(crate) fn hash_whole_keyword_line(&self, h: &mut impl Digest) {
        h.update(self.body().body());
        h.update(self.signature_item_line);
        h.update("\n");
    }
}

/// Methods suitable for use with `#[deftly(netdoc(sig_hash = "METHOD"))]`
///
/// See
/// [`#[derive_deftly(ItemValueParseable)]`](derive_deftly_template_ItemValueParseable).
pub mod sig_hash_methods {
    use super::*;

    /// SHA-1 including the whole keyword line
    ///
    /// <https://spec.torproject.org/dir-spec/netdoc.html#signing>
    pub fn whole_keyword_line_sha1(body: &SignatureHashInputs) -> [u8; 20] {
        let mut h = tor_llcrypto::d::Sha1::new();
        body.hash_whole_keyword_line(&mut h);
        h.finalize().into()
    }
}

/// Utility function to check that a time is within a validity period
pub fn check_validity_time(
    now: SystemTime,
    validity: std::ops::RangeInclusive<SystemTime>,
) -> Result<(), VF> {
    if now < *validity.start() {
        Err(VF::TooNew)
    } else if now > *validity.end() {
        Err(VF::TooOld)
    } else {
        Ok(())
    }
}

/// Like [`check_validity_time()`] but with a tolerance to support clock skews.
///
/// This function does not use the `DirTolerance` struct because we want to be
/// agnostic of directories in this context.
pub fn check_validity_time_tolerance(
    now: SystemTime,
    validity: std::ops::RangeInclusive<SystemTime>,
    pre_tolerance: Duration,
    post_tolerance: Duration,
) -> Result<(), VF> {
    let start = *validity.start();
    let end = *validity.end();
    let validity = start.saturating_sub(pre_tolerance)..=end.saturating_add(post_tolerance);
    check_validity_time(now, validity)
}
