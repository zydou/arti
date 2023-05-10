//! Link specifier objects
//!
//! (These are in a separate crate, since they get used both by
//! directory code and protocol code.)

use std::net::{IpAddr, SocketAddr};

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
    Unrecognized(u8, Vec<u8>),
}

/// Indicates an IPv4 ORPORT link specifier.
const LSTYPE_ORPORT_V4: u8 = 0;
/// Indicates an IPv6 ORPORT link specifier.
const LSTYPE_ORPORT_V6: u8 = 1;
/// Indicates an RSA ID fingerprint link specifier
const LSTYPE_RSAID: u8 = 2;
/// Indicates an Ed25519 link specifier
const LSTYPE_ED25519ID: u8 = 3;

impl Readable for LinkSpec {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let lstype = r.take_u8()?;
        r.read_nested_u8len(|r| {
            Ok(match lstype {
                LSTYPE_ORPORT_V4 => {
                    let addr = IpAddr::V4(r.extract()?);
                    LinkSpec::OrPort(addr, r.take_u16()?)
                }
                LSTYPE_ORPORT_V6 => {
                    let addr = IpAddr::V6(r.extract()?);
                    LinkSpec::OrPort(addr, r.take_u16()?)
                }
                LSTYPE_RSAID => LinkSpec::RsaId(r.extract()?),
                LSTYPE_ED25519ID => LinkSpec::Ed25519Id(r.extract()?),
                _ => LinkSpec::Unrecognized(lstype, r.take_rest().into()),
            })
        })
    }
}
impl Writeable for LinkSpec {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        use LinkSpec::*;
        match self {
            OrPort(IpAddr::V4(v4), port) => {
                w.write_u8(LSTYPE_ORPORT_V4);
                w.write_u8(6); // Length
                w.write(v4)?;
                w.write_u16(*port);
            }
            OrPort(IpAddr::V6(v6), port) => {
                w.write_u8(LSTYPE_ORPORT_V6);
                w.write_u8(18); // Length
                w.write(v6)?;
                w.write_u16(*port);
            }
            RsaId(r) => {
                w.write_u8(LSTYPE_RSAID);
                w.write_u8(20); // Length
                w.write(r)?;
            }
            Ed25519Id(e) => {
                w.write_u8(LSTYPE_ED25519ID);
                w.write_u8(32); // Length
                w.write(e)?;
            }
            Unrecognized(tp, vec) => {
                w.write_u8(*tp);
                let vec_len = vec
                    .len()
                    .try_into()
                    .map_err(|_| tor_bytes::EncodeError::BadLengthValue)?;
                w.write_u8(vec_len);
                w.write_all(&vec[..]);
            }
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
            Unrecognized(n, _) => *n,
        }
    }

    /// Sort a slice of LinkSpec based on the order in which they should
    /// appear in an EXTEND cell.
    pub fn sort_by_type(lst: &mut [Self]) {
        lst.sort_by_key(LinkSpec::sort_pos);
    }
}

/// An unparsed piece of information about a relay and how to connect to it.
///
/// Unlike [`LinkSpec`], this can't be used directly; we only pass it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedLinkSpec {
    /// The link specifier type.
    lstype: u8,
    /// The body of the link speciier.
    body: Vec<u8>,
}

impl EncodedLinkSpec {
    /// Create a new `EncodedLinkSpec`.
    pub fn new(lstype: u8, body: impl Into<Vec<u8>>) -> Self {
        EncodedLinkSpec {
            lstype,
            body: body.into(),
        }
    }
}

impl Readable for EncodedLinkSpec {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let lstype = r.take_u8()?;
        r.read_nested_u8len(|r| {
            let body = r.take_rest().to_vec();
            Ok(Self { lstype, body })
        })
    }
}
impl Writeable for EncodedLinkSpec {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        w.write_u8(self.lstype);
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
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use hex_literal::hex;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tor_bytes::{Reader, Writer};

    #[test]
    fn test_parse_enc() {
        fn t(b: &[u8], val: &LinkSpec) {
            let mut r = Reader::from_slice(b);
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
            &LinkSpec::Unrecognized(77, (&b"strange"[..]).into()),
        );
    }

    #[test]
    fn test_parse_bad() {
        use tor_bytes::Error;

        fn t(b: &[u8]) -> Error {
            let mut r = Reader::from_slice(b);
            let got: Result<LinkSpec> = r.extract();
            got.err().unwrap()
        }

        assert!(matches!(t(&hex!("00 03")), Error::Truncated));
        assert!(matches!(t(&hex!("00 06 01020304")), Error::Truncated));
        assert!(matches!(t(&hex!("99 07 010203")), Error::Truncated));
    }

    #[test]
    fn test_unparsed() {
        fn t(b: &[u8], val: &EncodedLinkSpec) {
            let mut r = Reader::from_slice(b);
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
                lstype: 0,
                body: vec![],
            },
        );
        t(
            &hex!("00 03 010203"),
            &EncodedLinkSpec {
                lstype: 0,
                body: vec![1, 2, 3],
            },
        );

        t(
            &hex!("99 10 000102030405060708090a0b0c0d0e0f"),
            &EncodedLinkSpec {
                lstype: 0x99,
                body: (0..=15).collect(),
            },
        );
    }

    #[test]
    fn test_unparsed_bad() {
        use tor_bytes::Error;
        fn t(b: &[u8]) -> Error {
            let mut r = Reader::from_slice(b);
            let got: Result<EncodedLinkSpec> = r.extract();
            got.err().unwrap()
        }

        assert!(matches!(t(&hex!("00")), Error::Truncated));
        assert!(matches!(t(&hex!("00 04 010203")), Error::Truncated));
        assert!(matches!(t(&hex!("00 05 01020304")), Error::Truncated));
    }
}
