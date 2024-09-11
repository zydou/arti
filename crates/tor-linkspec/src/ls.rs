//! Link specifier objects
//!
//! (These are in a separate crate, since they get used both by
//! directory code and protocol code.)

use std::net::{IpAddr, SocketAddr};

use caret::caret_int;
use tor_bytes::{EncodeResult, Readable, Reader, Result, Writeable, Writer};
use tor_llcrypto::pk::ed25519;
use tor_llcrypto::pk::rsa::RsaIdentity;

use crate::RelayId;

/// A piece of information about a relay and how to connect to it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSpec {
    /// The TCP address of an OR Port for a relay
    OrPort(IpAddr, u16),
    /// The RSA identity fingerprint of the relay
    RsaId(RsaIdentity),
    /// The Ed25519 identity of the relay
    Ed25519Id(ed25519::Ed25519Identity),
    /// A link specifier that we didn't recognize
    Unrecognized(LinkSpecType, Vec<u8>),
}

caret_int! {
    /// A numeric identifier for the type of a [`LinkSpec`].
    pub struct LinkSpecType(u8) {
        /// Indicates an IPv4 ORPORT link specifier.
        ORPORT_V4 = 0,
        /// Indicates an IPv6 ORPORT link specifier.
        ORPORT_V6 = 1,
        /// Indicates an RSA ID fingerprint link specifier
        RSAID = 2,
        /// Indicates an Ed25519 link specifier
        ED25519ID = 3,
    }
}

impl Readable for LinkSpec {
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let lstype = b.take_u8()?.into();
        b.read_nested_u8len(|r| Self::from_type_and_body(lstype, r))
    }
}
impl Writeable for LinkSpec {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        w.write_u8(self.lstype().into());
        {
            let mut inner = w.write_nested_u8len();
            self.encode_body(&mut *inner)?;
            inner.finish()?;
        }
        Ok(())
    }
}

impl From<&SocketAddr> for LinkSpec {
    fn from(sa: &SocketAddr) -> Self {
        LinkSpec::OrPort(sa.ip(), sa.port())
    }
}
impl From<SocketAddr> for LinkSpec {
    fn from(sa: SocketAddr) -> Self {
        (&sa).into()
    }
}
impl From<RsaIdentity> for LinkSpec {
    fn from(id: RsaIdentity) -> Self {
        LinkSpec::RsaId(id)
    }
}
impl From<ed25519::Ed25519Identity> for LinkSpec {
    fn from(id: ed25519::Ed25519Identity) -> Self {
        LinkSpec::Ed25519Id(id)
    }
}
impl From<ed25519::PublicKey> for LinkSpec {
    fn from(pk: ed25519::PublicKey) -> Self {
        LinkSpec::Ed25519Id(pk.into())
    }
}
impl From<RelayId> for LinkSpec {
    fn from(id: RelayId) -> Self {
        match id {
            RelayId::Ed25519(key) => LinkSpec::Ed25519Id(key),
            RelayId::Rsa(key) => LinkSpec::RsaId(key),
        }
    }
}

impl LinkSpec {
    /// Helper: return the position in the list of identifiers
    /// in which a given linkspec should occur.
    fn sort_pos(&self) -> u8 {
        use LinkSpec::*;
        match self {
            OrPort(IpAddr::V4(_), _) => 0,
            RsaId(_) => 1,
            Ed25519Id(_) => 2,
            OrPort(IpAddr::V6(_), _) => 3,
            Unrecognized(n, _) => (*n).into(),
        }
    }

    /// Sort a slice of LinkSpec based on the order in which they should
    /// appear in an EXTEND cell.
    pub fn sort_by_type(lst: &mut [Self]) {
        lst.sort_by_key(LinkSpec::sort_pos);
    }

    /// Try to create a LinkSpec of encoded type `lstype`, taking its body from a
    /// given reader `r`.
    ///
    /// Does not check whether `r` is exhausted at the end of the operation or not.
    fn from_type_and_body(lstype: LinkSpecType, r: &mut Reader<'_>) -> Result<Self> {
        use LinkSpecType as LST;
        Ok(match lstype {
            LST::ORPORT_V4 => {
                let addr = IpAddr::V4(r.extract()?);
                LinkSpec::OrPort(addr, r.take_u16()?)
            }
            LST::ORPORT_V6 => {
                let addr = IpAddr::V6(r.extract()?);
                LinkSpec::OrPort(addr, r.take_u16()?)
            }
            LST::RSAID => LinkSpec::RsaId(r.extract()?),
            LST::ED25519ID => LinkSpec::Ed25519Id(r.extract()?),
            _ => LinkSpec::Unrecognized(lstype, r.take_rest().into()),
        })
    }

    /// Return the command for this linkspec.
    fn lstype(&self) -> LinkSpecType {
        use LinkSpecType as LST;
        match self {
            LinkSpec::OrPort(IpAddr::V4(_), _) => LST::ORPORT_V4,
            LinkSpec::OrPort(IpAddr::V6(_), _) => LST::ORPORT_V6,

            LinkSpec::RsaId(_) => LST::RSAID,
            LinkSpec::Ed25519Id(_) => LST::ED25519ID,
            LinkSpec::Unrecognized(lstype, _) => *lstype,
        }
    }

    /// Try to encode the body of this linkspec onto a given writer.
    fn encode_body<W: Writer + ?Sized>(&self, w: &mut W) -> EncodeResult<()> {
        use LinkSpec::*;
        match self {
            OrPort(IpAddr::V4(v4), port) => {
                w.write(v4)?;
                w.write_u16(*port);
            }
            OrPort(IpAddr::V6(v6), port) => {
                w.write(v6)?;
                w.write_u16(*port);
            }
            RsaId(r) => {
                w.write(r)?;
            }
            Ed25519Id(e) => {
                w.write(e)?;
            }
            Unrecognized(_, vec) => {
                w.write_all(&vec[..]);
            }
        }
        Ok(())
    }

    /// Return an encoded version of this link specifier.
    pub fn encode(&self) -> EncodeResult<EncodedLinkSpec> {
        let tp = self.lstype();
        let mut body = Vec::new();
        self.encode_body(&mut body)?;
        Ok(EncodedLinkSpec::new(tp, body))
    }
}

/// An unparsed piece of information about a relay and how to connect to it.
///
/// Unlike [`LinkSpec`], this can't be used directly; we only pass it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedLinkSpec {
    /// The link specifier type.
    lstype: LinkSpecType,
    /// The body of the link speciier.
    body: Vec<u8>,
}

impl EncodedLinkSpec {
    /// Create a new `EncodedLinkSpec`.
    pub fn new(lstype: LinkSpecType, body: impl Into<Vec<u8>>) -> Self {
        EncodedLinkSpec {
            lstype,
            body: body.into(),
        }
    }

    /// Try to parse this into a `LinkSpec`, if it appears well-formed.
    pub fn parse(&self) -> Result<LinkSpec> {
        let mut r = Reader::from_slice(&self.body[..]);
        let ls = LinkSpec::from_type_and_body(self.lstype, &mut r)?;
        r.should_be_exhausted()?;
        Ok(ls)
    }

    /// Return the link spec type for this `EncodedLinkSpec`.
    pub fn lstype(&self) -> LinkSpecType {
        self.lstype
    }
}

impl Readable for EncodedLinkSpec {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let lstype = r.take_u8()?.into();
        r.read_nested_u8len(|r| {
            let body = r.take_rest().to_vec();
            Ok(Self { lstype, body })
        })
    }
}
impl Writeable for EncodedLinkSpec {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        w.write_u8(self.lstype.into());
        let mut nested = w.write_nested_u8len();
        nested.write_all(&self.body[..]);
        nested.finish()
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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use hex_literal::hex;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tor_bytes::{Reader, Writer};

    #[test]
    fn test_parse_enc() {
        fn t(b: &[u8], val: &LinkSpec) {
            let mut r = Reader::from_slice_for_test(b);
            let got: LinkSpec = r.extract().unwrap();
            assert_eq!(r.remaining(), 0);
            assert_eq!(&got, val);
            let mut v = Vec::new();
            v.write(val).expect("Encoding failure");
            assert_eq!(&v[..], b);
        }

        t(
            &hex!("00 06 01020304 0050"),
            &LinkSpec::OrPort(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80),
        );
        t(
            &hex!("01 12 0001 0002 0003 0004 0005 0006 0007 0008 01bb"),
            &LinkSpec::OrPort(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)), 443),
        );
        t(
            &[
                2, 20, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 33, 33, 33, 33,
                33, 33, 33, 33,
            ],
            &LinkSpec::RsaId(RsaIdentity::from_bytes(b"hello world!!!!!!!!!").unwrap()),
        );
        let key = ed25519::PublicKey::from_bytes(&hex!(
            "B440EEDB32D5C89EF21D6B16BE85A658774CE5992355737411678EE1041BDFBA"
        ))
        .unwrap()
        .into();
        t(
            &hex!("03 20 B440EEDB32D5C89EF21D6B16BE85A658774CE5992355737411678EE1041BDFBA"),
            &LinkSpec::Ed25519Id(key),
        );

        t(
            &[77, 7, 115, 116, 114, 97, 110, 103, 101],
            &LinkSpec::Unrecognized(77.into(), (&b"strange"[..]).into()),
        );
    }

    #[test]
    fn test_parse_bad() {
        use tor_bytes::Error;

        fn t(b: &[u8]) -> Error {
            let mut r = Reader::from_slice_for_test(b);
            let got: Result<LinkSpec> = r.extract();
            got.err().unwrap()
        }

        assert_eq!(t(&hex!("00 03")), Error::new_incomplete_for_test(3));
        assert_eq!(t(&hex!("00 06 01020304")), Error::new_incomplete_for_test(2));
        assert_eq!(t(&hex!("99 07 010203")), Error::new_incomplete_for_test(4));
    }

    #[test]
    fn test_unparsed() {
        fn t(b: &[u8], val: &EncodedLinkSpec) {
            let mut r = Reader::from_slice_for_test(b);
            let got: EncodedLinkSpec = r.extract().unwrap();
            assert_eq!(r.remaining(), 0);
            assert_eq!(&got, val);
            let mut v = Vec::new();
            v.write(val).expect("Encoding failure");
            assert_eq!(&v[..], b);
        }

        // Note that these are not valid linkspecs, but we accept them here.
        t(
            &hex!("00 00"),
            &EncodedLinkSpec {
                lstype: 0.into(),
                body: vec![],
            },
        );
        t(
            &hex!("00 03 010203"),
            &EncodedLinkSpec {
                lstype: 0.into(),
                body: vec![1, 2, 3],
            },
        );

        t(
            &hex!("99 10 000102030405060708090a0b0c0d0e0f"),
            &EncodedLinkSpec {
                lstype: 0x99.into(),
                body: (0..=15).collect(),
            },
        );
    }

    #[test]
    fn test_unparsed_bad() {
        use tor_bytes::Error;
        fn t(b: &[u8]) -> Error {
            let mut r = Reader::from_slice_for_test(b);
            let got: Result<EncodedLinkSpec> = r.extract();
            got.err().unwrap()
        }

        assert_eq!(t(&hex!("00")), Error::new_incomplete_for_test(1));
        assert_eq!(t(&hex!("00 04 010203")), Error::new_incomplete_for_test(1));
        assert_eq!(t(&hex!("00 05 01020304")), Error::new_incomplete_for_test(1));
    }
}
