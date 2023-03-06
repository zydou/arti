//! Implementation for the encrypted portion of an INTRODUCE message.
//!
//! TODO HS: maybe rename this module.
//!
//! TODO HS: Maybe this doesn't belong in tor-cell.

use super::ext::{decl_extension_group, ExtGroup, ExtList, UnrecognizedExt};
use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Error, Readable, Reader, Result, Writeable, Writer};
use tor_hscrypto::RendCookie;
use tor_linkspec::UnparsedLinkSpec;

caret_int! {
    /// Type code for an extension in an [`IntroduceHandshakePayload`].
    #[derive(Ord,PartialOrd)]
    pub struct IntroPayloadExtType(u8) {
    }
}

decl_extension_group! {
    /// An extension to an [`IntroduceHandshakePayload`].
    ///
    /// (Currently, no extensions of this type are recognized)
    #[derive(Debug,Clone)]
    enum IntroPayloadExt [ IntroPayloadExtType ] {
    }
}

caret_int! {
    /// An enumeration value to identify a type of onion key.
    struct OnionKeyType(u8) {
        NTOR = 0x01,
    }
}

/// An onion key provided in an IntroduceHandshakePayload.
///
/// TODO HS: Is there a logical type somewhere else to coalesce this with?
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum OnionKey {
    /// A key usable with the ntor or ntor-v3 handshake.
    NtorOnionKey(tor_llcrypto::pk::curve25519::PublicKey),
    // There is no "unknown" variant for this type, since we don't support any
    // other key types yet.
}

impl Readable for OnionKey {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let kind: OnionKeyType = r.take_u8()?.into();
        r.read_nested_u16len(|r_inner| match kind {
            OnionKeyType::NTOR => Ok(OnionKey::NtorOnionKey(r_inner.extract()?)),
            _ => Err(Error::InvalidMessage(
                format!("Unrecognized onion key type {kind}").into(),
            )),
        })
    }
}

impl Writeable for OnionKey {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        match self {
            OnionKey::NtorOnionKey(key) => {
                w.write_u8(OnionKeyType::NTOR.into());
                let mut w_inner = w.write_nested_u16len();
                w_inner.write(key)?;
                w_inner.finish()?;
            }
        }
        Ok(())
    }
}

/// The plaintext of the encrypted portion of an INTRODUCE message.
///
/// This is not a RelayMsg itself; it is instead used as the payload for an
/// `hs-ntor` handshake, which is passed to the onion service in `Introduce[12]`
/// message.
///
/// This payload is sent from a client to the onion service to tell it how to reach
/// the client's chosen rendezvous point.
#[derive(Clone, Debug)]
pub struct IntroduceHandshakePayload {
    /// The rendezvous cookie to use at the rendezvous point.
    cookie: RendCookie,
    /// A list of extensions to this payload
    extensions: ExtList<IntroPayloadExt>,
    /// The onion key to use when extending a circuit to the rendezvous point.
    onion_key: OnionKey,
    /// A list of link specifiers to identify the rendezvous point.
    link_specifiers: Vec<UnparsedLinkSpec>,
}

impl Readable for IntroduceHandshakePayload {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        let extensions = r.extract()?;
        let onion_key = r.extract()?;
        let n_link_specifiers = r.take_u8()?;
        let link_specifiers = r.extract_n(n_link_specifiers.into())?;
        Ok(Self {
            cookie,
            extensions,
            onion_key,
            link_specifiers,
        })
    }
}

impl Writeable for IntroduceHandshakePayload {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        w.write(&self.cookie)?;
        w.write(&self.extensions)?;
        w.write(&self.onion_key)?;
        w.write_u8(
            self.link_specifiers
                .len()
                .try_into()
                .map_err(|_| EncodeError::BadLengthValue)?,
        );
        self.link_specifiers.iter().try_for_each(|ls| w.write(ls))?;

        Ok(())
    }
}

impl IntroduceHandshakePayload {
    /// Construct a new [`IntroduceHandshakePayload`]
    pub fn new(
        cookie: RendCookie,
        onion_key: OnionKey,
        link_specifiers: Vec<UnparsedLinkSpec>,
    ) -> Self {
        let extensions = ExtList::default();
        Self {
            cookie,
            extensions,
            onion_key,
            link_specifiers,
        }
    }
}
