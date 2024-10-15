//! The encrypted portion of an INTRODUCE{1,2} message.
//!
//! (This is as described as the "decrypted plaintext" in section 3.3 of
//! rend-spec-v3.txt.  It tells the onion service how to find the rendezvous
//! point, and how to handshake with the client there.)

use super::ext::{decl_extension_group, Ext, ExtGroup, ExtList, UnrecognizedExt};
use super::pow::ProofOfWork;
use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Error, Readable, Reader, Result, Writeable, Writer};
use tor_hscrypto::RendCookie;
use tor_linkspec::EncodedLinkSpec;

caret_int! {
    /// Type code for an extension in an [`IntroduceHandshakePayload`].
    #[derive(Ord,PartialOrd)]
    pub struct IntroPayloadExtType(u8) {
        /// The extension to provide a completed proof-of-work solution for denial of service
        /// mitigation
        PROOF_OF_WORK = 2,
    }
}

decl_extension_group! {
    /// An extension to an [`IntroduceHandshakePayload`].
    #[derive(Debug,Clone)]
    enum IntroPayloadExt [ IntroPayloadExtType ] {
        ProofOfWork,
    }
}

caret_int! {
    /// An enumeration value to identify a type of onion key.
    ///
    /// Corresponds to `ONION_KEY_TYPE` in section 3.3 of
    /// rend-spec-v3.txt \[PROCESS_INTRO].
    //
    // TODO this shouldn't live here.  It ought to be in some more general crate.
    // But it should then also be usable in the netdoc parser.  In particular, it ought
    // to be able to handle the *textual* values in `hsdesc/inner.rs`, and maybe
    // the ad-hocery in the routerdesc parsing too.
    struct OnionKeyType(u8) {
        NTOR = 0x01,
    }
}

/// An onion key provided in an IntroduceHandshakePayload.
///
/// Corresponds to `ONION_KEY` in the spec.
//
// TODO: Is there a logical type somewhere else to coalesce this with?
// Currently there is no wrapper around curve25519::PublicKey when it's used as
// an Ntor key, nor is there (yet) a generic onion key enum.  tor-linkspec might be
// the logical place for those.  See arti#893.
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

/// The plaintext of the encrypted portion of an INTRODUCE{1,2} message.
///
/// This is not a RelayMsg itself; it is instead used as the payload for an
/// `hs-ntor` handshake, which is passed to the onion service in `Introduce[12]`
/// message.
///
/// This payload is sent from a client to the onion service to tell it how to reach
/// the client's chosen rendezvous point.
///
/// This corresponds to the "decrypted payload" in section 3.3 of
/// rend-spec-v3.txt, **excluding the PAD field**.
///
/// The user of this type is expected to discard, or generate, appropriate
/// padding, as required.
#[derive(Clone, Debug)]
pub struct IntroduceHandshakePayload {
    /// The rendezvous cookie to use at the rendezvous point.
    ///
    /// (`RENDEZVOUS_COOKIE` in the spec.)
    cookie: RendCookie,
    /// A list of extensions to this payload.
    ///
    /// (`N_EXTENSIONS`, `EXT_FIELD_TYPE`, `EXT_FIELD_LEN`, and `EXT_FIELD` in
    /// the spec.)
    extensions: ExtList<IntroPayloadExt>,
    /// The onion key to use when extending a circuit to the rendezvous point.
    ///
    /// (`ONION_KEY_TYPE`, `ONION_KEY_LEN`, and `ONION_KEY` in the spec. This
    /// represents `KP_ntor` for the rendezvous point.)
    onion_key: OnionKey,
    /// A list of link specifiers to identify the rendezvous point.
    ///
    /// (`NSPEC`, `LSTYPE`, `LSLEN`, and `LSPEC` in the spec.)
    link_specifiers: Vec<EncodedLinkSpec>,
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
        link_specifiers: Vec<EncodedLinkSpec>,
        proof_of_work: Option<ProofOfWork>,
    ) -> Self {
        let mut extensions = ExtList::default();
        if let Some(proof_of_work) = proof_of_work {
            extensions.push(proof_of_work.into());
        }
        Self {
            cookie,
            extensions,
            onion_key,
            link_specifiers,
        }
    }

    /// Return the rendezvous cookie specified in this handshake payload.
    pub fn cookie(&self) -> &RendCookie {
        &self.cookie
    }

    /// Return the provided onion key for the specified rendezvous point
    pub fn onion_key(&self) -> &OnionKey {
        &self.onion_key
    }

    /// Return the provided link specifiers for the specified rendezvous point.
    pub fn link_specifiers(&self) -> &[EncodedLinkSpec] {
        &self.link_specifiers[..]
    }
}
