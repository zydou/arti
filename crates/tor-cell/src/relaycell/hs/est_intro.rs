//! Define the ESTABLISH_INTRO message and related types.

use caret::caret_int;
use derive_deftly::Deftly;
use tor_bytes::{EncodeError, EncodeResult, Readable, Reader, Result, Writeable, Writer};
use tor_error::bad_api_usage;
use tor_hscrypto::ops::{HsMacKey, HS_MAC_LEN};
use tor_llcrypto::{
    pk::ed25519::{self, Ed25519Identity, ED25519_SIGNATURE_LEN},
    traits::ShortMac as _,
    util::ct::CtByteArray,
};
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_units::BoundedInt32;

use crate::relaycell::{hs::ext::*, hs::AuthKeyType, msg};

caret_int! {
    /// The introduction protocol extension type.
    ///
    /// Documented in <https://spec.torproject.org/rend-spec/introduction-protocol.html#EST_INTRO>
    #[derive(Ord, PartialOrd)]
    pub struct EstIntroExtType(u8) {
        /// The extension used to send DoS parameters
        DOS_PARAMS = 1,
    }
}

caret_int! {
    /// The recognized parameter types in an establish intro
    /// DoS extension.
    ///
    /// See <https://spec.torproject.org/rend-spec/introduction-protocol.html#EST_INTRO_DOS_EXT>
    pub struct EstIntroExtDosParamType(u8) {
        /// The rate per second of INTRODUCE2 cell relayed
        /// to the service.
        DOS_INTRODUCE2_RATE_PER_SEC = 1,
        /// The burst per second of INTRODUCE2 cell relayed
        /// to the service
        DOS_INTRODUCE2_BURST_PER_SEC = 2,
    }
}

/// Extension to tell the introduction point to rate-limit.
///
/// When we sent this extension, it tells the introduction point to rate-limit
/// the INTRODUCE2 messages it sends us to the rates shown here.
///
/// When this extension is not sent, the introduction point imposes a rate-limit
/// depending on parameters in the latest consensus.
///
/// This extension requires protover `HSIntro=5`.
///
/// See <https://spec.torproject.org/rend-spec/introduction-protocol.html#EST_INTRO_DOS_EXT>.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct DosParams {
    /// An optional parameter indicates the rate per second of
    /// INTRODUCE2 cell relayed to the service.
    ///
    /// Min: 0, Max: 2147483647
    rate_per_sec: Option<BoundedInt32<0, { i32::MAX }>>,
    /// An optional parameter indicates the burst per second of
    /// INTRODUCE2 cell relayed to the service
    ///
    /// Min: 0, Max: 2147483647
    burst_per_sec: Option<BoundedInt32<0, { i32::MAX }>>,
}

impl DosParams {
    /// Create a new establish intro DoS extension.
    pub fn new(rate_per_sec: Option<i32>, burst_per_sec: Option<i32>) -> crate::Result<Self> {
        let normalize = |supplied: Option<i32>| -> crate::Result<_> {
            supplied
                .map(|val| {
                    BoundedInt32::checked_new(val).map_err(|_| {
                        crate::err::Error::CantEncode(
                            "EST_INTRO_DOS_EXT parameter value out of bound.",
                        )
                    })
                })
                .transpose()
        };
        Ok(Self {
            rate_per_sec: normalize(rate_per_sec)?,
            burst_per_sec: normalize(burst_per_sec)?,
        })
    }
}

impl Ext for DosParams {
    type Id = EstIntroExtType;
    fn type_id(&self) -> EstIntroExtType {
        EstIntroExtType::DOS_PARAMS
    }
    fn take_body_from(b: &mut Reader<'_>) -> Result<Self> {
        let n_prams = b.take_u8()?;
        let mut rate_per_sec = None;
        let mut burst_per_sec = None;
        for _i in 0..n_prams {
            let param_to_store = match b.take_u8()?.into() {
                EstIntroExtDosParamType::DOS_INTRODUCE2_RATE_PER_SEC => Some(&mut rate_per_sec),
                EstIntroExtDosParamType::DOS_INTRODUCE2_BURST_PER_SEC => Some(&mut burst_per_sec),
                _ => None,
            };
            if let Some(param) = param_to_store {
                if let Ok(rate) = i32::try_from(b.take_u64()?) {
                    *param = BoundedInt32::checked_new(rate).ok();
                }
            }
        }
        Ok(Self {
            rate_per_sec,
            burst_per_sec,
        })
    }
    fn write_body_onto<B: Writer + ?Sized>(&self, b: &mut B) -> EncodeResult<()> {
        let mut params = vec![];
        let mut push_params = |ty, value| {
            if let Some(value) = value {
                params.push((ty, value));
            }
        };
        push_params(
            EstIntroExtDosParamType::DOS_INTRODUCE2_RATE_PER_SEC,
            self.rate_per_sec,
        );
        push_params(
            EstIntroExtDosParamType::DOS_INTRODUCE2_BURST_PER_SEC,
            self.burst_per_sec,
        );
        b.write_u8(u8::try_from(params.len()).map_err(|_| EncodeError::BadLengthValue)?);
        for (t, v) in params {
            b.write_u8(t.get());
            b.write_u64(v.get() as u64);
        }
        Ok(())
    }
}

decl_extension_group! {
    /// An extension to an EstablishIntro cell.
    #[derive(Debug,Clone,Deftly)]
    #[derive_deftly(HasMemoryCost)]
    enum EstablishIntroExt [ EstIntroExtType ] {
        DosParams,
    }
}

/// The body of an EstablishIntro message, after the signature and MAC are
/// verified.
///
/// This tells the introduction point which key it should act as an introduction
/// for, and how.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct EstablishIntroDetails {
    /// The public introduction point auth key.
    auth_key: Ed25519Identity,
    /// A list of extensions on this cell.
    extensions: ExtList<EstablishIntroExt>,
}

/// A hidden services establishes a new introduction point, by sending an
/// EstablishIntro message.
///
/// This may represent either an outbound body that we're sending, or a decoded
/// body that we're receiving.
///
/// # Usage
///
/// This type is a good choice for handling an incoming EstablishIntro message
/// on a Relay, but not for generating an outgoing EstablishIntro message.
///
/// Onion services should not construct this message object; instead, they
/// should construct an [`EstablishIntroDetails`], and then call its
/// `sign_and_encode` method.
#[derive(educe::Educe, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
#[educe(Debug)]
pub struct EstablishIntro {
    /// The underlying body of this, wrapped in authentication.
    body: EstablishIntroDetails,
    /// The MAC of all earlier fields in the cell, using a key derived from the
    /// handshake between the onion service and the introduction point.
    ///
    /// This MAC binds the EstablishIntro message to a single circuit, and keeps
    /// it from being replayed.
    handshake_auth: CtByteArray<HS_MAC_LEN>,
    /// A textual record of all the fields in the message that are covered by the MAC.
    #[educe(Debug(ignore))]
    mac_plaintext: Vec<u8>,
    /// A signature using `auth_key` of all contents of the message.
    ///
    /// This signature proves possession of `auth_key` and thereby ensures that
    /// the request really comes from that key's holder.
    ///
    /// (This field is boxed to manage variant size.)
    #[educe(Debug(ignore))]
    sig: Box<ed25519::ValidatableEd25519Signature>,
}

impl Writeable for EstablishIntroDetails {
    fn write_onto<B: Writer + ?Sized>(&self, w: &mut B) -> EncodeResult<()> {
        let auth_key_type = AuthKeyType::ED25519_SHA3_256;
        w.write_u8(auth_key_type.get());
        {
            let mut w_nested = w.write_nested_u16len();
            w_nested.write(&self.auth_key)?;
            w_nested.finish()?;
        }
        w.write(&self.extensions)?;
        Ok(())
    }
}

/// A string that we prefix onto any establish_intro body before signing it.
const SIG_PREFIX: &[u8] = b"Tor establish-intro cell v1";

impl msg::Body for EstablishIntro {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cursor_start = r.cursor();
        let auth_key_type: AuthKeyType = r.take_u8()?.into();
        // Only Ed25519 is recognized... and it *needs* to be recognized or else we
        // can't verify the signature.
        let auth_key = match auth_key_type {
            AuthKeyType::ED25519_SHA3_256 => r.read_nested_u16len(|r| r.extract())?,
            _ => {
                return Err(tor_bytes::Error::InvalidMessage(
                    format!("unrecognized authkey type {:?}", auth_key_type).into(),
                ))
            }
        };

        let extensions = r.extract()?;
        let cursor_mac = r.cursor();
        let handshake_auth = r.extract()?;
        let cursor_sig = r.cursor();
        let sig = r.read_nested_u16len(|r| r.extract())?;

        let mac_plaintext = r.range(cursor_start, cursor_mac).into();

        let public_key = ed25519::PublicKey::try_from(&auth_key)
            .map_err(|_| tor_bytes::Error::InvalidMessage("Invalid ed25519 key".into()))?;
        let mut signed_material = Vec::from(SIG_PREFIX);
        signed_material.extend(r.range(cursor_start, cursor_sig));
        let sig = Box::new(ed25519::ValidatableEd25519Signature::new(
            public_key,
            sig,
            &signed_material[..],
        ));

        Ok(EstablishIntro {
            body: EstablishIntroDetails {
                auth_key,
                extensions,
            },
            handshake_auth,
            mac_plaintext,
            sig,
        })
    }

    // Note: this is not the typical way to encode an EstablishIntro message. Actual onion services
    // will use `sign_and_encode`.
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.body)?;
        w.write_all(self.handshake_auth.as_ref());
        {
            let mut w_inner = w.write_nested_u16len();
            w_inner.write(self.sig.signature())?;
            w_inner.finish()?;
        }
        Ok(())
    }
}

impl EstablishIntroDetails {
    /// All arguments constructor
    pub fn new(auth_key: Ed25519Identity) -> Self {
        Self {
            auth_key,
            extensions: Default::default(),
        }
    }

    /// Set EST_INTRO_DOS_EXT with given `extension_dos`.
    pub fn set_extension_dos(&mut self, extension_dos: DosParams) {
        self.extensions.replace_by_type(extension_dos.into());
    }

    /// Add an extension of some other type.
    pub fn set_extension_other(&mut self, other: UnrecognizedExt<EstIntroExtType>) {
        self.extensions.replace_by_type(other.into());
    }

    /// Sign and authenticate this body using a provided Ed25519 keypair and MAC
    /// key.
    ///
    /// The MAC key is derived from the circuit handshake between the onion
    /// service and the introduction point.  The Ed25519 keypair must match the
    /// one given as the auth_key for this body.
    pub fn sign_and_encode<'a>(
        self,
        keypair: &ed25519::Keypair,
        mac_key: impl Into<HsMacKey<'a>>,
    ) -> crate::Result<Vec<u8>> {
        use tor_llcrypto::pk::ed25519::Signer;
        if Ed25519Identity::from(keypair.verifying_key()) != self.auth_key {
            return Err(crate::Error::Internal(bad_api_usage!("Key mismatch")));
        }

        let mut output = Vec::new();

        output.write(&self)?;
        let mac_key: HsMacKey<'_> = mac_key.into();
        let mac = mac_key.mac(&output[..]);
        output.write(&mac)?;
        let signature = {
            let mut signed_material = Vec::from(SIG_PREFIX);
            signed_material.extend(&output[..]);
            keypair.sign(&signed_material[..])
        };
        output.write_u16(
            ED25519_SIGNATURE_LEN
                .try_into()
                .expect("ed25519 signature len is somehow > u16::MAX"),
        );
        output.write(&signature)?;

        Ok(output)
    }
}

impl EstablishIntro {
    /// Construct a new EstablishIntro message from its constituent parts.
    ///
    /// # Limitations
    ///
    /// This is really only useful for testing; it will construct a version of the
    /// object whose signatures will probably never check as valid.
    ///
    /// # Panics
    ///
    /// Panics if the body's public key is not a valid ed25519 public key
    #[cfg(feature = "testing")]
    pub fn from_parts_for_test(
        body: EstablishIntroDetails,
        mac: CtByteArray<HS_MAC_LEN>,
        signature: ed25519::Signature,
    ) -> Self {
        use tor_llcrypto::pk::ed25519::ValidatableEd25519Signature;
        let sig = Box::new(ValidatableEd25519Signature::new(
            body.auth_key.try_into().expect("Invalid public key"),
            signature,
            &[],
        ));
        Self {
            body,
            handshake_auth: mac,
            mac_plaintext: vec![],
            sig,
        }
    }

    /// Check whether this EstablishIntro message is well-signed (with its
    /// included key), and well authenticated with the provided MAC key.
    ///
    /// On success, return the [`EstablishIntroDetails`] describing how to function
    /// as an introduction point for this service.  On failure, return an error.
    pub fn check_and_unwrap<'a>(
        self,
        mac_key: impl Into<HsMacKey<'a>>,
    ) -> std::result::Result<EstablishIntroDetails, EstablishIntroSigError> {
        use tor_llcrypto::pk::ValidatableSignature;

        let mac_key: HsMacKey<'_> = mac_key.into();
        let mac_okay = mac_key.validate(&self.mac_plaintext, &self.handshake_auth);
        let sig_okay = self.sig.is_valid();

        if !(bool::from(mac_okay) & sig_okay) {
            return Err(EstablishIntroSigError::Invalid);
        }

        Ok(self.dangerously_unwrap())
    }

    /// Consume this EstablishIntro message and return its  body.
    ///
    /// This is a "dangerous" function because it does not check correctness for the signature or the MAC.
    pub fn dangerously_unwrap(self) -> EstablishIntroDetails {
        self.body
    }
}

/// An error that has occurred while trying to validate an EstablishIntro message.
///
/// This error is deliberately uninformative.
#[derive(thiserror::Error, Clone, Debug)]
#[non_exhaustive]
pub enum EstablishIntroSigError {
    /// The authentication information on an EstablishIntro message was incorrect.
    #[error("Invalid signature or MAC on ESTABLISH_INTRO message.")]
    Invalid,
}
