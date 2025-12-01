//! Types and encodings used during circuit extension.

use super::extlist::{Ext, ExtList, ExtListRef, decl_extension_group};
#[cfg(feature = "hs")]
use super::hs::pow::ProofOfWork;
use caret::caret_int;
use itertools::Itertools as _;
use tor_bytes::{EncodeResult, Reader, Writeable as _, Writer};
use tor_protover::NumberedSubver;

caret_int! {
    /// A type of circuit request extension data (`EXT_FIELD_TYPE`).
    #[derive(PartialOrd,Ord)]
    pub struct CircRequestExtType(u8) {
        /// Request congestion control be enabled for a circuit.
        CC_REQUEST = 1,
        /// HS only: provide a completed proof-of-work solution for denial of service
        /// mitigation
        PROOF_OF_WORK = 2,
        /// Request that certain subprotocol features be enabled.
        SUBPROTOCOL_REQUEST = 3,
    }
}

caret_int! {
    /// A type of circuit response extension data (`EXT_FIELD_TYPE`).
    #[derive(PartialOrd,Ord)]
    pub struct CircResponseExtType(u8) {
        /// Acknowledge a congestion control request.
        CC_RESPONSE = 2
    }
}

/// Request congestion control be enabled for this circuit (client → exit node).
///
/// (`EXT_FIELD_TYPE` = 01)
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct CcRequest {}

impl Ext for CcRequest {
    type Id = CircRequestExtType;
    fn type_id(&self) -> Self::Id {
        CircRequestExtType::CC_REQUEST
    }
    fn take_body_from(_b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        Ok(Self {})
    }
    fn write_body_onto<B: Writer + ?Sized>(&self, _b: &mut B) -> EncodeResult<()> {
        Ok(())
    }
}

/// Acknowledge a congestion control request (exit node → client).
///
/// (`EXT_FIELD_TYPE` = 02)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcResponse {
    /// The exit's current view of the `cc_sendme_inc` consensus parameter.
    sendme_inc: u8,
}

impl CcResponse {
    /// Create a new AckCongestionControl with a given value for the
    /// `sendme_inc` parameter.
    pub fn new(sendme_inc: u8) -> Self {
        CcResponse { sendme_inc }
    }

    /// Return the value of the `sendme_inc` parameter for this extension.
    pub fn sendme_inc(&self) -> u8 {
        self.sendme_inc
    }
}

impl Ext for CcResponse {
    type Id = CircResponseExtType;
    fn type_id(&self) -> Self::Id {
        CircResponseExtType::CC_RESPONSE
    }

    fn take_body_from(b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let sendme_inc = b.take_u8()?;
        Ok(Self { sendme_inc })
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_u8(self.sendme_inc);
        Ok(())
    }
}

/// A request that a certain set of protocols should be enabled. (client to server)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubprotocolRequest {
    /// The protocols to enable.
    protocols: Vec<tor_protover::NumberedSubver>,
}

impl<A> FromIterator<A> for SubprotocolRequest
where
    A: Into<tor_protover::NumberedSubver>,
{
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let mut protocols: Vec<_> = iter.into_iter().map(Into::into).collect();
        protocols.sort();
        protocols.dedup();
        Self { protocols }
    }
}

impl Ext for SubprotocolRequest {
    type Id = CircRequestExtType;

    fn type_id(&self) -> Self::Id {
        CircRequestExtType::SUBPROTOCOL_REQUEST
    }

    fn take_body_from(b: &mut Reader<'_>) -> tor_bytes::Result<Self> {
        let mut protocols = Vec::new();
        while b.remaining() != 0 {
            protocols.push(b.extract()?);
        }

        if !is_strictly_ascending(&protocols) {
            return Err(tor_bytes::Error::InvalidMessage(
                "SubprotocolRequest not sorted and deduplicated.".into(),
            ));
        }

        Ok(Self { protocols })
    }

    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        for p in self.protocols.iter() {
            b.write(p)?;
        }
        Ok(())
    }
}
impl SubprotocolRequest {
    /// Return true if this [`SubprotocolRequest`] contains the listed capability.
    pub fn contains(&self, cap: tor_protover::NamedSubver) -> bool {
        self.protocols.binary_search(&cap.into()).is_ok()
    }

    /// Return true if this [`SubprotocolRequest`] contains no other
    /// capabilities except those listed in `list`.
    pub fn contains_only(&self, list: &tor_protover::Protocols) -> bool {
        self.protocols
            .iter()
            .all(|p| list.supports_numbered_subver(*p))
    }
}

decl_extension_group! {
    /// An extension to be sent along with a circuit extension request
    /// (CREATE2, EXTEND2, or INTRODUCE.)
    #[derive(Debug,Clone,PartialEq)]
    #[non_exhaustive]
    pub enum CircRequestExt [ CircRequestExtType ] {
        /// Request to enable congestion control.
        CcRequest,
        /// HS-only: Provide a proof-of-work solution.
        [ feature: #[cfg(feature = "hs")] ]
        ProofOfWork,
        /// Request to enable one or more subprotocol capabilities.
        SubprotocolRequest,
    }
}

decl_extension_group! {
    /// An extension to be sent along with a circuit extension response
    /// (CREATED2 or EXTENDED2.)
    ///
    /// RENDEZVOUS is not currently supported, but once we replace hs-ntor
    /// with something better, extensions will be possible there too.
    #[derive(Debug,Clone,PartialEq)]
    #[non_exhaustive]
    pub enum CircResponseExt [ CircResponseExtType ] {
        /// Response indicating that congestion control is enabled.
        CcResponse,
    }
}

/// Helper for generating encoding and decoding functions
/// for [`CircRequestExt`] and [`CircResponseExt`].
macro_rules! impl_encode_decode {
    ($extgroup:ty, $name:expr) => {
        impl $extgroup {
            /// Encode a set of extensions into a "message" for a circuit handshake.
            pub fn write_many_onto<W: Writer>(exts: &[Self], out: &mut W) -> EncodeResult<()> {
                ExtListRef::from(exts).write_onto(out)?;
                Ok(())
            }
            /// Decode a slice of bytes representing the "message" of a circuit handshake into a set of
            /// extensions.
            pub fn decode(message: &[u8]) -> crate::Result<Vec<Self>> {
                let err_cvt = |err| crate::Error::BytesErr { err, parsed: $name };
                let mut r = tor_bytes::Reader::from_slice(message);
                let list: ExtList<_> = r.extract().map_err(err_cvt)?;
                r.should_be_exhausted().map_err(err_cvt)?;
                Ok(list.into_vec())
            }
        }
    };
}

impl_encode_decode!(CircRequestExt, "CREATE2 extension list");
impl_encode_decode!(CircResponseExt, "CREATED2 extension list");

/// Return true iff the list of protocol capabilities is strictly ascending.
fn is_strictly_ascending(vers: &[NumberedSubver]) -> bool {
    // We don't use is_sorted, since that doesn't detect duplicates.
    vers.iter().tuple_windows().all(|(a, b)| a < b)
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
    fn subproto_ext_valid() {
        use tor_protover::named::*;
        let sp: SubprotocolRequest = [RELAY_NTORV3, RELAY_NTORV3, LINK_V4].into_iter().collect();
        let mut v = Vec::new();
        sp.write_body_onto(&mut v).unwrap();
        assert_eq!(&v[..], [0, 4, 2, 4]);

        let mut r = Reader::from_slice(&v[..]);
        let sp2: SubprotocolRequest = SubprotocolRequest::take_body_from(&mut r).unwrap();
        assert_eq!(sp, sp2);
    }

    #[test]
    fn subproto_invalid() {
        // Odd length.
        let mut r = Reader::from_slice(&[0, 4, 2]);
        let e = SubprotocolRequest::take_body_from(&mut r).unwrap_err();
        dbg!(e.to_string());
        assert!(e.to_string().contains("too short"));

        // Duplicate protocols.
        let mut r = Reader::from_slice(&[0, 4, 0, 4]);
        let e = SubprotocolRequest::take_body_from(&mut r).unwrap_err();
        dbg!(e.to_string());
        assert!(e.to_string().contains("deduplicated"));

        // not-sorted protocols.
        let mut r = Reader::from_slice(&[2, 4, 0, 4]);
        let e = SubprotocolRequest::take_body_from(&mut r).unwrap_err();
        dbg!(e.to_string());
        assert!(e.to_string().contains("sorted"));
    }

    #[test]
    fn subproto_supported() {
        use tor_protover::named::*;
        let sp: SubprotocolRequest = [RELAY_NTORV3, RELAY_NTORV3, LINK_V4].into_iter().collect();
        // "contains" tells us if a subprotocol capability is a member of the request.
        assert!(sp.contains(LINK_V4));
        assert!(!sp.contains(LINK_V2));

        // contains_only tells us if there are any subprotocol capabilities in the request
        // other than those listed.
        assert!(sp.contains_only(&[RELAY_NTORV3, LINK_V4, CONFLUX_BASE].into_iter().collect()));
        assert!(sp.contains_only(&[RELAY_NTORV3, LINK_V4].into_iter().collect()));
        assert!(!sp.contains_only(&[LINK_V4].into_iter().collect()));
        assert!(!sp.contains_only(&[LINK_V4, CONFLUX_BASE].into_iter().collect()));
        assert!(!sp.contains_only(&[CONFLUX_BASE].into_iter().collect()));
    }
}
