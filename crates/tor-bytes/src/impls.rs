//! Implementations of Writeable and Readable for several items that
//! we use in Tor.
//!
//! These don't need to be in a separate module, but for convenience
//! this is where I'm putting them.

use super::*;

// ----------------------------------------------------------------------

/// `Vec<u8>` is the main type that implements [`Writer`].
impl Writer for Vec<u8> {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
    fn write_u8(&mut self, byte: u8) {
        // specialize for performance
        self.push(byte);
    }
    fn write_zeros(&mut self, n: usize) {
        // specialize for performance
        let new_len = self.len().saturating_add(n);
        self.resize(new_len, 0);
    }
}

impl Writer for bytes::BytesMut {
    fn write_all(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

// ----------------------------------------------------------------------

impl Writeable for [u8] {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_all(self);
        Ok(())
    }
}

impl Writeable for Vec<u8> {
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_all(&self[..]);
        Ok(())
    }
}

// We also need to implement our traits for an older version (0.14) of
// generic_array, since that's what the digest crate uses (as of digest 0.10.)
impl<N> Readable for digest::generic_array::GenericArray<u8, N>
where
    N: digest::generic_array::ArrayLength<u8>,
{
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        // safety -- "take" returns the requested bytes or error.
        Ok(Self::clone_from_slice(b.take(N::to_usize())?))
    }
}

impl<N> Writeable for digest::generic_array::GenericArray<u8, N>
where
    N: digest::generic_array::ArrayLength<u8>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        b.write_all(self.as_slice());
        Ok(())
    }
}

/*
// We could add these as well as our implementations over GenericArray<u8>,
// except that we don't actually need them, and Rust doesn't support
// specialization.

impl<T, N> Readable for GenericArray<T, N>
where
    T: Readable + Clone,
    N: generic_array::ArrayLength<T>,
{
    fn take_from(b: &mut Reader<'_>) -> Result<Self> {
        let mut v: Vec<T> = Vec::new();
        for _ in 0..N::to_usize() {
            v.push(T::take_from(b)?);
        }
        // TODO(nickm) I wish I didn't have to clone this.
        Ok(Self::from_slice(v.as_slice()).clone())
    }
}

impl<T, N> Writeable for GenericArray<T, N>
where
    T: Writeable,
    N: generic_array::ArrayLength<T>,
{
    fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) {
        for item in self {
            item.write_onto(b)
        }
    }
}
*/

/// Make Readable and Writeable implementations for a provided
/// unsigned type, delegating to the `read_uNN` and `write_uNN` functions.
macro_rules! impl_u {
    ( $t:ty, $wrfn:ident, $rdfn:ident ) => {
        impl Writeable for $t {
            fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
                b.$wrfn(*self);
                Ok(())
            }
        }
        impl Readable for $t {
            fn take_from(b: &mut Reader<'_>) -> Result<Self> {
                b.$rdfn()
            }
        }
    };
}

impl_u!(u8, write_u8, take_u8);
impl_u!(u16, write_u16, take_u16);
impl_u!(u32, write_u32, take_u32);
impl_u!(u64, write_u64, take_u64);
impl_u!(u128, write_u128, take_u128);

// ----------------------------------------------------------------------

/// Implement [`Readable`] and [`Writeable`] for IPv4 and IPv6 addresses.
///
/// These are encoded as a sequence of octets, not as strings.
mod net_impls {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    impl Writeable for Ipv4Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(&self.octets()[..]);
            Ok(())
        }
    }

    impl Readable for Ipv4Addr {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            Ok(b.take_u32()?.into())
        }
    }

    impl Writeable for Ipv6Addr {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(&self.octets()[..]);
            Ok(())
        }
    }
    impl Readable for Ipv6Addr {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            Ok(b.take_u128()?.into())
        }
    }
}

/// Implement [`Readable`] and [`Writeable`] for Ed25519 types.
mod ed25519_impls {
    use super::*;
    use tor_llcrypto::pk::ed25519;

    impl Writeable for ed25519::PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(self.as_bytes());
            Ok(())
        }
    }
    impl Readable for ed25519::PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes: [u8; 32] = b.extract()?;
            Self::from_bytes(&bytes)
                .map_err(|_| Error::InvalidMessage("Couldn't decode Ed25519 public key".into()))
        }
    }

    impl Writeable for ed25519::Ed25519Identity {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(self.as_bytes());
            Ok(())
        }
    }
    impl Readable for ed25519::Ed25519Identity {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes: [u8; 32] = b.extract()?;
            Ok(Self::new(bytes))
        }
    }
    impl Writeable for ed25519::Signature {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(&self.to_bytes()[..]);
            Ok(())
        }
    }
    impl Readable for ed25519::Signature {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes: [u8; 64] = b.extract()?;
            Ok(Self::from_bytes(&bytes))
        }
    }
}

/// Implement Readable and Writeable for Curve25519 types.
mod curve25519_impls {
    use super::*;
    use tor_llcrypto::pk::curve25519::{PublicKey, SharedSecret};

    impl Writeable for PublicKey {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(self.as_bytes());
            Ok(())
        }
    }
    impl Readable for PublicKey {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let bytes: [u8; 32] = b.extract()?;
            Ok(bytes.into())
        }
    }
    impl Writeable for SharedSecret {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(self.as_bytes());
            Ok(())
        }
    }
}

/// Implement readable and writeable for the RsaIdentity type.
mod rsa_impls {
    use super::*;
    use tor_llcrypto::pk::rsa::*;

    impl Writeable for RsaIdentity {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(self.as_bytes());
            Ok(())
        }
    }
    impl Readable for RsaIdentity {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let m = b.take(RSA_ID_LEN)?;
            RsaIdentity::from_bytes(m)
                .ok_or_else(|| tor_error::internal!("wrong number of bytes from take").into())
        }
    }
}

/// Implement readable and writeable for the digest::CtOutput type.
mod digest_impls {
    use super::*;
    use digest::{CtOutput, OutputSizeUser};
    impl<T: OutputSizeUser> WriteableOnce for CtOutput<T> {
        fn write_into<B: Writer + ?Sized>(self, b: &mut B) -> EncodeResult<()> {
            let code = self.into_bytes();
            b.write_all(&code[..]);
            Ok(())
        }
    }
    impl<T: OutputSizeUser> Readable for CtOutput<T> {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            let array = digest::generic_array::GenericArray::take_from(b)?;
            Ok(CtOutput::new(array))
        }
    }
}

/// Implement readable and writeable for u8 arrays.
mod u8_array_impls {
    use super::*;
    impl<const N: usize> Writeable for [u8; N] {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(&self[..]);
            Ok(())
        }
    }

    impl<const N: usize> Readable for [u8; N] {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            // note: Conceivably this should use MaybeUninit, but let's
            // avoid that unless there is some measurable benefit.
            let mut array = [0_u8; N];
            b.take_into(&mut array[..])?;
            Ok(array)
        }
    }
}

/// Implement Readable and Writeable for `CtByteArray`
mod ctbytearray_impls {
    use super::*;
    use tor_llcrypto::util::ct::CtByteArray;
    impl<const N: usize> Writeable for CtByteArray<N> {
        fn write_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
            b.write_all(&self.as_ref()[..]);
            Ok(())
        }
    }

    impl<const N: usize> Readable for CtByteArray<N> {
        fn take_from(b: &mut Reader<'_>) -> Result<Self> {
            Ok(CtByteArray::from(b.extract::<[u8; N]>()?))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::{Reader, Writer};
    use hex_literal::hex;
    macro_rules! check_encode {
        ($e:expr, $e2:expr) => {
            let mut w = Vec::new();
            w.write(&$e).expect("encoding failed");
            assert_eq!(&w[..], &$e2[..]);
        };
    }
    macro_rules! check_decode {
        ($t:ty, $e:expr, $e2:expr) => {
            let mut b = Reader::from_slice(&$e[..]);
            let obj: $t = b.extract().unwrap();
            assert_eq!(obj, $e2);
            assert!(b.should_be_exhausted().is_ok());
        };
    }
    macro_rules! check_roundtrip {
        ($t:ty, $e:expr, $e2:expr) => {
            check_encode!($e, $e2);
            check_decode!($t, $e2, $e);
        };
    }
    macro_rules! check_bad {
        ($t:ty, $e:expr) => {
            let mut b = Reader::from_slice(&$e[..]);
            let len_orig = b.remaining();
            let res: Result<$t, _> = b.extract();
            assert!(res.is_err());
            assert_eq!(b.remaining(), len_orig);
        };
    }
    #[test]
    fn vec_u8() {
        let v: Vec<u8> = vec![1, 2, 3, 4];
        check_encode!(v, b"\x01\x02\x03\x04");
    }

    #[test]
    fn genarray() {
        use digest::generic_array as ga;
        let a: ga::GenericArray<u8, ga::typenum::U7> = [4, 5, 6, 7, 8, 9, 10].into();
        check_roundtrip!(ga::GenericArray<u8, ga::typenum::U7>,
                         a,
                         [4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn roundtrip_u64() {
        check_roundtrip!(u64, 0x4040111_u64, [0, 0, 0, 0, 4, 4, 1, 17]);
    }

    #[test]
    fn u8_array() {
        check_roundtrip!(
            [u8; 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
    }

    #[test]
    fn ipv4addr() {
        use std::net::Ipv4Addr;
        check_roundtrip!(Ipv4Addr, Ipv4Addr::new(192, 168, 0, 1), [192, 168, 0, 1]);
    }

    #[test]
    fn ipv6addr() {
        use std::net::Ipv6Addr;
        check_roundtrip!(
            Ipv6Addr,
            Ipv6Addr::new(65535, 77, 1, 1, 1, 0, 0, 0),
            [255, 255, 0, 77, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ed25519() {
        use tor_llcrypto::pk::ed25519;
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f8967ff"
        );
        check_roundtrip!(
            ed25519::PublicKey,
            ed25519::PublicKey::from_bytes(b).unwrap(),
            b
        );
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f8967"
        ); // too short
        check_bad!(ed25519::PublicKey, b);
        let b = &hex!(
            "68a6cee11d2883661f5876f7aac748992cd140f
             cfc36923aa957d04b5f896700"
        ); // not a valid compressed Y
        check_bad!(ed25519::PublicKey, b);

        let sig = &hex!(
            "b8842c083a56076fc27c8af21211f9fe57d1c32d9d
             c804f76a8fa858b9ab43622b9e8335993c422eab15
             6ebb5a047033f35256333a47a508b02699314d22550e"
        );
        check_roundtrip!(ed25519::Signature, ed25519::Signature::from_bytes(sig), sig);

        // Test removed: The ed25519::Signature type is now happy to hold any
        // 64-byte sequence.
        //
        // let sig = &hex!(
        //   "b8842c083a56076fc27c8af21211f9fe57d1c32d9d
        //     c804f76a8fa858b9ab43622b9e8335993c422eab15
        //     6ebb5a047033f35256333a47a508b02699314d2255ff"
        // );
        // check_bad!(ed25519::Signature, sig);
    }

    #[test]
    fn curve25519() {
        use tor_llcrypto::pk::curve25519;
        let b = &hex!("5f6df7a2fe3bcf1c9323e9755250efd79b9db4ed8f3fd21c7515398b6662a365");
        let pk: curve25519::PublicKey = (*b).into();
        check_roundtrip!(curve25519::PublicKey, pk, b);
    }

    #[test]
    fn rsa_id() {
        use tor_llcrypto::pk::rsa::RsaIdentity;
        let b = &hex!("9432D4CEA2621ED09F5A8088BE0E31E0D271435C");
        check_roundtrip!(RsaIdentity, RsaIdentity::from_bytes(b).unwrap(), b);
    }
}
