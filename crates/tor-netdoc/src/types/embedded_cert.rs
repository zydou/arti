//! Types related to certificates

use crate::encode::{ItemEncoder, ItemObjectEncodable, ItemValueEncodable};
use crate::parse2::{ErrorProblem as P2EP, ItemObjectParseable, ItemValueParseable, UnparsedItem};
use tor_bytes::{Writeable, Writer};
use tor_error::{Bug, internal};

/// One certificate *inside* a netdoc, covering data other than the netdoc itself
///
/// # Semantics and value
///
/// This type always embodies:
///
///  * The encoded form of a certificate or signature
///    (its actual bytes, for encoding/decoding.
///
///    This encoded unverified raw form is the **type parameter `UR`**.
///    Often `UR` will be [`tor_cert::KeyUnknownCert`].
///
/// Additionally, it can and usually does contain the "verified form":
///
///  * Interpreted, parsed, data, of whatever was certified.
///    For example, for a family certificate, the family IDs.
///
///    It might or might not include something like a [`tor_cert::Ed25519Cert`],
///    depending whether downstreams need that information.
///
///    This decoded verified data is the **type parameter `VD`**;
///    `EmbeddedCert` contains `Option<VD>` (or equivalent).
///
/// (We call an `EmbeddedCert` without the verified form an "unverified `EmbeddedCert`".)
///
/// # Correctness/availability invariant
///
/// Whenever an `EmbeddedCert` appears in a parsed and verified network document body,
/// the `EmbeddedCert` has been verified and the verified form is present.
///
/// During parsing of a network document, the document type's verification function
/// gets access to the unverified `EmbeddedCert`.
/// It is the verify function which must verify and timecheck the certificate,
/// and, if it is satisfied, call [`set_verified`](Self::set_verified).
/// Include fields of this type in documents deriving
/// [`NetdocParseableUnverified`](derive_deftly_template_NetdocParseableUnverified),
/// rather than plain `NetdocParseable`.
///
/// This invariant is somewhat fuzzy around the edges, and not 100% enforced by the compiler.
/// If it is relied on inappropriately, or violated, `Bug` is thrown.
///
// It is hard to do better than this.  Most alternatives involve some or all of
// proliferating type parameters, even more complex macrology, and
// significantly more complex marker types.
//
// See https://gitlab.torproject.org/tpo/core/arti/-/work_items/2485.
// This is Option E from that ticket:
// https://gitlab.torproject.org/tpo/core/arti/-/work_items/2485#note_3398883
//
/// # Security invariant
///
/// Presence of the verified form guarantees that, if the document came from outside,
/// we have verified the signature, and checked that it is timely.
/// So the interpreted form can safely be used.
///
/// This guarantee flows from the caller of [`set_verified`](Self::set_verified),
/// and may be relied on by users - eg, by callers of [`get`](Self::get).
///
/// # Parsing and encoding
///
/// This type implements applicable parsing and encoding traits,
/// if `VD` is [`EmbeddableCertObject<UR>`]
/// and `UR` is [`Readable`](tor_bytes::Readable) and [`Writable`](tor_bytes::Writeable).
///
/// See [`EmbeddableCertObject`] for full details.
///
/// # Example
///
/// See `crates/tor-netdoc/src/types/embedded_cert/test.rs`.
#[derive(Clone, Debug)]
pub struct EmbeddedCert<VD, UR> {
    /// The verified form, if this `EmbeddedCert` is verified.
    verified: Option<VD>,
    /// The unverified form.
    unverified: UR,
}

/// Certificate data whose unverified form `UR` is representable as a netdoc Object
///
/// Implement for `VD`.
///
/// Enables encoding/decoding traits for `EmbeddableCert<VD, UR>`.
/// See [`EmbeddedCert`].
///
/// # Usage
///
///  * implement [`tor_bytes::Writeable`] for `UR`
///  * implement [`tor_bytes::Readable`] for `UR`
///  * implement **`EmbeddableCertObject<UR>`** for `VD`
///
/// Then `EmbeddableCert<VD, UR>` will implement:
///
///  * [`ItemValueEncodable`] and [`ItemValueParseable`]
///  * [`ItemObjectEncodable`] and [`ItemObjectParseable`]
///  * [`Writeable`]
pub trait EmbeddableCertObject<UR> {
    /// The netdoc Object Label
    const LABEL: &str;
}

impl<VD, UR> EmbeddedCert<VD, UR> {
    /// Make a new (verified) `EmbeddedCert`
    ///
    /// # Security
    ///
    /// If this certificate originated elsewhere,
    /// it must have been verified and timechecked.
    pub fn new(data: VD, raw: UR) -> Self {
        EmbeddedCert {
            verified: Some(data),
            unverified: raw,
        }
    }

    /// Obtain the verified data
    ///
    /// This function will always succeed on a cert found in a (verified) netdoc.
    ///
    /// # Error conditions
    ///
    /// `get` will fail only if the correctness/availability invariant
    /// is violated or relied on inappropriately.
    /// See the [type-level documentation](EmbeddedCert).
    ///
    /// It can fail inside a netdoc verification function,
    /// or after `EmbeddedCert::new_unverified_hazardous`.
    /// It could also fail if an `EmbeddedCert` is included in an unsigned netdoc
    /// (ie one to which derived plain
    /// [`NetdocParseable`](derive_deftly_template_NetdocParseable)
    /// rather than
    /// [`NetdocParseableUnverified`](derive_deftly_template_NetdocParseableUnverified).
    pub fn get(&self) -> Result<&VD, Bug> {
        self.verified.as_ref().ok_or_else(|| internal!(
 "attempted to access verified data of unverified EmbeddedCert; buggy netdoc fn verify?"
        ))
    }

    /// Make a new unverified `EmbeddedCert`
    ///
    /// # Correctness
    ///
    /// It is the caller's responsibility to uphold the correctness/availability invariant.
    /// See the [type-level documentation](EmbeddedCert).
    ///
    /// Carelessly creating a loose unverified `EmbeddedCert`
    /// could expose it to naive code, which expects [`get`](Self::get) to succeed.
    pub fn new_unverified_hazardous(unverified: UR) -> Self {
        EmbeddedCert {
            unverified,
            verified: None,
        }
    }

    /// Obtain the raw data, for verification or encoding
    pub fn raw_unverified(&self) -> &UR {
        &self.unverified
    }

    /// Set the verified data
    ///
    /// Usually called from within a document-specific verify function.
    ///
    /// # Security
    ///
    /// The signature must have been verified, and timeliness checked.
    pub fn set_verified(&mut self, verified: VD) {
        self.verified = Some(verified);
    }
}

impl<VD, UR> Writeable for EmbeddedCert<VD, UR>
where
    UR: Writeable,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> Result<(), tor_bytes::EncodeError> {
        self.unverified.write_onto(b)
    }
}

impl<VD, UR> ItemObjectEncodable for EmbeddedCert<VD, UR>
where
    VD: EmbeddableCertObject<UR>,
    UR: Writeable,
{
    fn label(&self) -> &str {
        VD::LABEL
    }
    fn write_object_onto(&self, b: &mut Vec<u8>) -> Result<(), Bug> {
        Ok(self.write_onto(b)?)
    }
}

impl<VD, UR> ItemValueEncodable for EmbeddedCert<VD, UR>
where
    Self: ItemObjectEncodable,
{
    fn write_item_value_onto(&self, out: ItemEncoder) -> Result<(), Bug> {
        out.object(self);
        Ok(())
    }
}

impl<VD, UR> ItemObjectParseable for EmbeddedCert<VD, UR>
where
    VD: EmbeddableCertObject<UR>,
    UR: tor_bytes::Readable,
{
    fn check_label(label: &str) -> Result<(), P2EP> {
        (label == VD::LABEL)
            .then_some(())
            .ok_or(P2EP::ObjectIncorrectLabel)
    }
    fn from_bytes(input: &[u8]) -> Result<Self, P2EP> {
        let unverified = tor_bytes::Reader::from_slice(input)
            .extract()
            .map_err(|_| P2EP::ObjectInvalidData)?;
        Ok(EmbeddedCert::new_unverified_hazardous(unverified))
    }
}

impl<VD, UR> ItemValueParseable for EmbeddedCert<VD, UR>
where
    VD: EmbeddableCertObject<UR>,
    UR: tor_bytes::Readable,
{
    fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, P2EP> {
        let object = item.object().ok_or(P2EP::MissingObject)?;
        <Self as ItemObjectParseable>::check_label(object.label())?;
        <Self as ItemObjectParseable>::from_bytes(&object.decode_data()?)
    }
}

#[cfg(all(test, feature = "routerdesc"))]
mod test;
