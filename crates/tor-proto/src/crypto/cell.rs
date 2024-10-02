//! Relay cell cryptography
//!
//! The Tor protocol centers around "RELAY cells", which are transmitted through
//! the network along circuits.  The client that creates a circuit shares two
//! different sets of keys and state with each of the relays on the circuit: one
//! for "outbound" traffic, and one for "inbound" traffic.
//!
//! So for example, if a client creates a 3-hop circuit with relays R1, R2, and
//! R3, the client has:
//!   * An "inbound" cryptographic state shared with R1.
//!   * An "inbound" cryptographic state shared with R2.
//!   * An "inbound" cryptographic state shared with R3.
//!   * An "outbound" cryptographic state shared with R1.
//!   * An "outbound" cryptographic state shared with R2.
//!   * An "outbound" cryptographic state shared with R3.
//!
//! In this module at least, we'll call each of these state objects a "layer" of
//! the circuit's encryption.
//!
//! The Tor specification does not describe these layer objects very explicitly.
//! In the current relay cryptography protocol, each layer contains:
//!    * A keyed AES-CTR state. (AES-128 or AES-256)  This cipher uses a key
//!      called `Kf` or `Kb` in the spec, where `Kf` is a "forward" key used in
//!      the outbound direction, and `Kb` is a "backward" key used in the
//!      inbound direction.
//!    * A running digest. (SHA1 or SHA3)  This digest is initialized with a
//!      value called `Df` or `Db` in the spec.
//!
//! This `crypto::cell` module itself provides traits and implementations that
//! should work for all current future versions of the relay cell crypto design.
//! The current Tor protocols are instantiated in a `tor1` submodule.

use crate::{Error, Result};
use derive_deftly::Deftly;
use tor_cell::chancell::BoxedCellBody;
use tor_error::internal;
use tor_memquota::derive_deftly_template_HasMemoryCost;

use digest::generic_array::GenericArray;

use super::binding::CircuitBinding;

/// Type for the body of a relay cell.
#[derive(Clone, derive_more::From, derive_more::Into)]
pub(crate) struct RelayCellBody(BoxedCellBody);

impl AsRef<[u8]> for RelayCellBody {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
impl AsMut<[u8]> for RelayCellBody {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

/// Represents the ability for one hop of a circuit's cryptographic state to be
/// initialized from a given seed.
pub(crate) trait CryptInit: Sized {
    /// Return the number of bytes that this state will require.
    fn seed_len() -> usize;
    /// Construct this state from a seed of the appropriate length.
    fn initialize(seed: &[u8]) -> Result<Self>;
    /// Initialize this object from a key generator.
    fn construct<K: super::handshake::KeyGenerator>(keygen: K) -> Result<Self> {
        let seed = keygen.expand(Self::seed_len())?;
        Self::initialize(&seed[..])
    }
}

/// A paired object containing the inbound and outbound cryptographic layers
/// used by a client to communicate with a single hop on one of its circuits.
///
/// TODO: Maybe we should fold this into CryptInit.
pub(crate) trait ClientLayer<F, B>
where
    F: OutboundClientLayer,
    B: InboundClientLayer,
{
    /// Consume this ClientLayer and return a paired forward and reverse
    /// crypto layer, and a [`CircuitBinding`] object
    fn split(self) -> (F, B, CircuitBinding);
}

/// Represents a relay's view of the crypto state on a given circuit.
#[allow(dead_code)] // TODO #1383 ????
pub(crate) trait RelayCrypt {
    /// Prepare a RelayCellBody to be sent towards the client.
    fn originate(&mut self, cell: &mut RelayCellBody);
    /// Encrypt a RelayCellBody that is moving towards the client.
    fn encrypt_inbound(&mut self, cell: &mut RelayCellBody);
    /// Decrypt a RelayCellBody that is moving towards the client.
    ///
    /// Return true if it is addressed to us.
    fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool;
}

/// A client's view of the cryptographic state shared with a single relay on a
/// circuit, as used for outbound cells.
pub(crate) trait OutboundClientLayer {
    /// Prepare a RelayCellBody to be sent to the relay at this layer, and
    /// encrypt it.
    ///
    /// Return the authentication tag.
    fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8];
    /// Encrypt a RelayCellBody to be decrypted by this layer.
    fn encrypt_outbound(&mut self, cell: &mut RelayCellBody);
}

/// A client's view of the crypto state shared with a single relay on a circuit,
/// as used for inbound cells.
pub(crate) trait InboundClientLayer {
    /// Decrypt a CellBody that passed through this layer.
    ///
    /// Return an authentication tag if this layer is the originator.
    fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]>;
}

/// Type to store hop indices on a circuit.
///
/// Hop indices are zero-based: "0" denotes the first hop on the circuit.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct HopNum(u8);

impl HopNum {
    /// Return an object that implements [`Display`](std::fmt::Display) for printing `HopNum`s.
    ///
    /// This will display the `HopNum` as a 1-indexed value (the string representation of the first
    /// hop is `"#1"`).
    ///
    /// To display the zero-based underlying representation of the `HopNum`, use
    /// [`Debug`](std::fmt::Debug).
    pub fn display(&self) -> HopNumDisplay {
        HopNumDisplay(*self)
    }
}

/// A helper for displaying [`HopNum`]s.
///
/// The [`Display`](std::fmt::Display) of this type displays the `HopNum` as a 1-based index
/// prefixed with the number sign (`#`). For example, the string representation of the first hop is
/// `"#1"`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct HopNumDisplay(HopNum);

impl std::fmt::Display for HopNumDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let hop_num: u8 = self.0.into();

        write!(f, "#{}", hop_num + 1)
    }
}

impl From<HopNum> for u8 {
    fn from(hop: HopNum) -> u8 {
        hop.0
    }
}

impl From<u8> for HopNum {
    fn from(v: u8) -> HopNum {
        HopNum(v)
    }
}

impl From<HopNum> for usize {
    fn from(hop: HopNum) -> usize {
        hop.0 as usize
    }
}

/// A client's view of the cryptographic state for an entire
/// constructed circuit, as used for sending cells.
pub(crate) struct OutboundClientCrypt {
    /// Vector of layers, one for each hop on the circuit, ordered from the
    /// closest hop to the farthest.
    layers: Vec<Box<dyn OutboundClientLayer + Send>>,
}

/// A client's view of the cryptographic state for an entire
/// constructed circuit, as used for receiving cells.
pub(crate) struct InboundClientCrypt {
    /// Vector of layers, one for each hop on the circuit, ordered from the
    /// closest hop to the farthest.
    layers: Vec<Box<dyn InboundClientLayer + Send>>,
}

/// The length of the tag that we include (with this algorithm) in an
/// authenticated SENDME message.
const SENDME_TAG_LEN: usize = 20;

impl OutboundClientCrypt {
    /// Return a new (empty) OutboundClientCrypt.
    pub(crate) fn new() -> Self {
        OutboundClientCrypt { layers: Vec::new() }
    }
    /// Prepare a cell body to sent away from the client.
    ///
    /// The cell is prepared for the `hop`th hop, and then encrypted with
    /// the appropriate keys.
    ///
    /// On success, returns a reference to tag that should be expected
    /// for an authenticated SENDME sent in response to this cell.
    pub(crate) fn encrypt(
        &mut self,
        cell: &mut RelayCellBody,
        hop: HopNum,
    ) -> Result<&[u8; SENDME_TAG_LEN]> {
        let hop: usize = hop.into();
        if hop >= self.layers.len() {
            return Err(Error::NoSuchHop);
        }

        let mut layers = self.layers.iter_mut().take(hop + 1).rev();
        let first_layer = layers.next().ok_or(Error::NoSuchHop)?;
        let tag = first_layer.originate_for(cell);
        for layer in layers {
            layer.encrypt_outbound(cell);
        }
        Ok(tag.try_into().expect("wrong SENDME digest size"))
    }

    /// Add a new layer to this OutboundClientCrypt
    pub(crate) fn add_layer(&mut self, layer: Box<dyn OutboundClientLayer + Send>) {
        assert!(self.layers.len() < u8::MAX as usize);
        self.layers.push(layer);
    }

    /// Return the number of layers configured on this OutboundClientCrypt.
    pub(crate) fn n_layers(&self) -> usize {
        self.layers.len()
    }
}

impl InboundClientCrypt {
    /// Return a new (empty) InboundClientCrypt.
    pub(crate) fn new() -> Self {
        InboundClientCrypt { layers: Vec::new() }
    }
    /// Decrypt an incoming cell that is coming to the client.
    ///
    /// On success, return which hop was the originator of the cell.
    // TODO(nickm): Use a real type for the tag, not just `&[u8]`.
    pub(crate) fn decrypt(&mut self, cell: &mut RelayCellBody) -> Result<(HopNum, &[u8])> {
        for (hopnum, layer) in self.layers.iter_mut().enumerate() {
            if let Some(tag) = layer.decrypt_inbound(cell) {
                let hopnum = HopNum(u8::try_from(hopnum).expect("Somehow > 255 hops"));
                return Ok((hopnum, tag));
            }
        }
        Err(Error::BadCellAuth)
    }
    /// Add a new layer to this InboundClientCrypt
    pub(crate) fn add_layer(&mut self, layer: Box<dyn InboundClientLayer + Send>) {
        assert!(self.layers.len() < u8::MAX as usize);
        self.layers.push(layer);
    }

    /// Return the number of layers configured on this InboundClientCrypt.
    ///
    /// TODO: use HopNum
    #[allow(dead_code)]
    pub(crate) fn n_layers(&self) -> usize {
        self.layers.len()
    }
}

/// Standard Tor relay crypto, as instantiated for RELAY cells.
pub(crate) type Tor1RelayCrypto<RCF> =
    tor1::CryptStatePair<tor_llcrypto::cipher::aes::Aes128Ctr, tor_llcrypto::d::Sha1, RCF>;

/// Standard Tor relay crypto, as instantiated for the HSv3 protocol.
///
/// (The use of SHA3 is ridiculously overkill.)
#[cfg(feature = "hs-common")]
pub(crate) type Tor1Hsv3RelayCrypto<RCF> =
    tor1::CryptStatePair<tor_llcrypto::cipher::aes::Aes256Ctr, tor_llcrypto::d::Sha3_256, RCF>;

/// An implementation of Tor's current relay cell cryptography.
///
/// These are not very good algorithms; they were the best we could come up with
/// in ~2002.  They are somewhat inefficient, and vulnerable to tagging attacks.
/// They should get replaced within the next several years.  For information on
/// some older proposed alternatives so far, see proposals 261, 295, and 298.
///
/// I am calling this design `tor1`; it does not have a generally recognized
/// name.
pub(crate) mod tor1 {
    use std::marker::PhantomData;

    use crate::crypto::binding::CIRC_BINDING_LEN;

    use super::*;
    use cipher::{KeyIvInit, StreamCipher};
    use digest::Digest;
    use tor_cell::relaycell::{RelayCellFields, RelayCellFormatTrait};
    use typenum::Unsigned;

    /// A CryptState represents one layer of shared cryptographic state between
    /// a relay and a client for a single hop, in a single direction.
    ///
    /// For example, if a client makes a 3-hop circuit, then it will have 6
    /// `CryptState`s, one for each relay, for each direction of communication.
    ///
    /// Note that although `CryptState` implements [`OutboundClientLayer`],
    /// [`InboundClientLayer`], and [`RelayCrypt`], any single `CryptState`
    /// instance will only be used for one of these roles.
    ///
    /// It is parameterized on a stream cipher and a digest type: most circuits
    /// will use AES-128-CTR and SHA1, but v3 onion services use AES-256-CTR and
    /// SHA-3.
    pub(crate) struct CryptState<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait> {
        /// Stream cipher for en/decrypting cell bodies.
        ///
        /// This cipher is the one keyed with Kf or Kb in the spec.
        cipher: SC,
        /// Digest for authenticating cells to/from this hop.
        ///
        /// This digest is the one keyed with Df or Db in the spec.
        digest: D,
        /// Most recent digest value generated by this crypto.
        last_digest_val: GenericArray<u8, D::OutputSize>,
        /// The format used for relay cells at this layer.
        relay_cell_format: PhantomData<RCF>,
    }

    /// A pair of CryptStates shared between a client and a relay, one for the
    /// outbound (away from the client) direction, and one for the inbound
    /// (towards the client) direction.
    pub(crate) struct CryptStatePair<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait> {
        /// State for en/decrypting cells sent away from the client.
        fwd: CryptState<SC, D, RCF>,
        /// State for en/decrypting cells sent towards the client.
        back: CryptState<SC, D, RCF>,
        /// A circuit binding key.
        binding: CircuitBinding,
    }

    impl<SC: StreamCipher + KeyIvInit, D: Digest + Clone, RCF: RelayCellFormatTrait> CryptInit
        for CryptStatePair<SC, D, RCF>
    {
        fn seed_len() -> usize {
            SC::KeySize::to_usize() * 2 + D::OutputSize::to_usize() * 2 + CIRC_BINDING_LEN
        }
        fn initialize(mut seed: &[u8]) -> Result<Self> {
            // This corresponds to the use of the KDF algorithm as described in
            // tor-spec 5.2.2
            if seed.len() != Self::seed_len() {
                return Err(Error::from(internal!(
                    "seed length {} was invalid",
                    seed.len()
                )));
            }

            // Advances `seed` by `n` bytes, returning the advanced bytes
            let mut take_seed = |n: usize| -> &[u8] {
                let res = &seed[..n];
                seed = &seed[n..];
                res
            };

            let dlen = D::OutputSize::to_usize();
            let keylen = SC::KeySize::to_usize();

            let df = take_seed(dlen);
            let db = take_seed(dlen);
            let kf = take_seed(keylen);
            let kb = take_seed(keylen);
            let binding_key = take_seed(CIRC_BINDING_LEN);

            let fwd = CryptState {
                cipher: SC::new(kf.into(), &Default::default()),
                digest: D::new().chain_update(df),
                last_digest_val: GenericArray::default(),
                relay_cell_format: PhantomData,
            };
            let back = CryptState {
                cipher: SC::new(kb.into(), &Default::default()),
                digest: D::new().chain_update(db),
                last_digest_val: GenericArray::default(),
                relay_cell_format: PhantomData,
            };
            let binding = CircuitBinding::try_from(binding_key)?;

            Ok(CryptStatePair { fwd, back, binding })
        }
    }

    impl<SC, D, RCF> ClientLayer<CryptState<SC, D, RCF>, CryptState<SC, D, RCF>>
        for CryptStatePair<SC, D, RCF>
    where
        SC: StreamCipher,
        D: Digest + Clone,
        RCF: RelayCellFormatTrait,
    {
        fn split(
            self,
        ) -> (
            CryptState<SC, D, RCF>,
            CryptState<SC, D, RCF>,
            CircuitBinding,
        ) {
            (self.fwd, self.back, self.binding)
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait> RelayCrypt
        for CryptStatePair<SC, D, RCF>
    {
        fn originate(&mut self, cell: &mut RelayCellBody) {
            let mut d_ignored = GenericArray::default();
            cell.set_digest::<_, RCF>(&mut self.back.digest, &mut d_ignored);
        }
        fn encrypt_inbound(&mut self, cell: &mut RelayCellBody) {
            // This is describe in tor-spec 5.5.3.1, "Relaying Backward at Onion Routers"
            self.back.cipher.apply_keystream(cell.as_mut());
        }
        fn decrypt_outbound(&mut self, cell: &mut RelayCellBody) -> bool {
            // This is describe in tor-spec 5.5.2.2, "Relaying Forward at Onion Routers"
            self.fwd.cipher.apply_keystream(cell.as_mut());
            let mut d_ignored = GenericArray::default();
            cell.is_recognized::<_, RCF>(&mut self.fwd.digest, &mut d_ignored)
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait> OutboundClientLayer
        for CryptState<SC, D, RCF>
    {
        fn originate_for(&mut self, cell: &mut RelayCellBody) -> &[u8] {
            cell.set_digest::<_, RCF>(&mut self.digest, &mut self.last_digest_val);
            self.encrypt_outbound(cell);
            // Note that we truncate the authentication tag here if we are using
            // a digest with a more-than-20-byte length.
            &self.last_digest_val[..SENDME_TAG_LEN]
        }
        fn encrypt_outbound(&mut self, cell: &mut RelayCellBody) {
            // This is a single iteration of the loop described in tor-spec
            // 5.5.2.1, "routing away from the origin."
            self.cipher.apply_keystream(&mut cell.0[..]);
        }
    }

    impl<SC: StreamCipher, D: Digest + Clone, RCF: RelayCellFormatTrait> InboundClientLayer
        for CryptState<SC, D, RCF>
    {
        fn decrypt_inbound(&mut self, cell: &mut RelayCellBody) -> Option<&[u8]> {
            // This is a single iteration of the loop described in tor-spec
            // 5.5.3, "routing to the origin."
            self.cipher.apply_keystream(&mut cell.0[..]);
            if cell.is_recognized::<_, RCF>(&mut self.digest, &mut self.last_digest_val) {
                Some(&self.last_digest_val[..SENDME_TAG_LEN])
            } else {
                None
            }
        }
    }

    /// Functions on RelayCellBody that implement the digest/recognized
    /// algorithm.
    ///
    /// The current relay crypto protocol uses two wholly inadequate fields to
    /// see whether a cell is intended for its current recipient: a two-byte
    /// "recognized" field that needs to be all-zero; and a four-byte "digest"
    /// field containing a running digest of all cells (for this recipient) to
    /// this one, seeded with an initial value (either Df or Db in the spec).
    ///
    /// These operations is described in tor-spec section 6.1 "Relay cells"
    impl RelayCellBody {
        /// Returns the byte slice of the `recognized` field.
        fn recognized<RCF: RelayCellFormatTrait>(&self) -> &[u8] {
            &self.0[RCF::FIELDS::RECOGNIZED_RANGE]
        }
        /// Returns the mut byte slice of the `recognized` field.
        fn recognized_mut<RCF: RelayCellFormatTrait>(&mut self) -> &mut [u8] {
            &mut self.0[RCF::FIELDS::RECOGNIZED_RANGE]
        }
        /// Returns the byte slice of the `digest` field.
        fn digest<RCF: RelayCellFormatTrait>(&self) -> &[u8] {
            &self.0[RCF::FIELDS::DIGEST_RANGE]
        }
        /// Returns the mut byte slice of the `digest` field.
        fn digest_mut<RCF: RelayCellFormatTrait>(&mut self) -> &mut [u8] {
            &mut self.0[RCF::FIELDS::DIGEST_RANGE]
        }
        /// Prepare a cell body by setting its digest and recognized field.
        fn set_digest<D: Digest + Clone, RCF: RelayCellFormatTrait>(
            &mut self,
            d: &mut D,
            used_digest: &mut GenericArray<u8, D::OutputSize>,
        ) {
            self.recognized_mut::<RCF>().fill(0); // Set 'Recognized' to zero
            self.digest_mut::<RCF>().fill(0); // Set Digest to zero

            d.update(&self.0[..]);
            // TODO(nickm) can we avoid this clone?  Probably not.
            *used_digest = d.clone().finalize();
            let used_digest_prefix = &used_digest[0..RCF::FIELDS::DIGEST_RANGE.len()];
            self.digest_mut::<RCF>().copy_from_slice(used_digest_prefix);
        }
        /// Check whether this just-decrypted cell is now an authenticated plaintext.
        ///
        /// This method returns true if the `recognized` field is all zeros, and if the
        /// `digest` field is a digest of the correct material.
        ///
        /// If this method returns false, then either further decryption is required,
        /// or the cell is corrupt.
        // TODO #1336: Further optimize and/or benchmark this.
        fn is_recognized<D: Digest + Clone, RCF: RelayCellFormatTrait>(
            &self,
            d: &mut D,
            rcvd: &mut GenericArray<u8, D::OutputSize>,
        ) -> bool {
            use crate::util::ct;

            // Validate 'Recognized' field
            if !ct::is_zero(self.recognized::<RCF>()) {
                return false;
            }

            // Now also validate the 'Digest' field:

            let mut dtmp = d.clone();
            // Add bytes up to the 'Digest' field
            dtmp.update(&self.0[..RCF::FIELDS::DIGEST_RANGE.start]);
            // Add zeroes where the 'Digest' field is
            dtmp.update(RCF::FIELDS::EMPTY_DIGEST);
            // Add the rest of the bytes
            dtmp.update(&self.0[RCF::FIELDS::DIGEST_RANGE.end..]);
            // Clone the digest before finalize destroys it because we will use
            // it in the future
            let dtmp_clone = dtmp.clone();
            let result = dtmp.finalize();

            if ct::bytes_eq(
                self.digest::<RCF>(),
                &result[0..RCF::FIELDS::DIGEST_RANGE.len()],
            ) {
                // Copy useful things out of this cell (we keep running digest)
                *d = dtmp_clone;
                *rcvd = result;
                return true;
            }

            false
        }
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
    use rand::RngCore;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_bytes::SecretBuf;
    use tor_cell::relaycell::RelayCellFormatV0;

    fn add_layers(
        cc_out: &mut OutboundClientCrypt,
        cc_in: &mut InboundClientCrypt,
        // TODO #1067: test other formats
        pair: Tor1RelayCrypto<RelayCellFormatV0>,
    ) {
        let (outbound, inbound, _) = pair.split();
        cc_out.add_layer(Box::new(outbound));
        cc_in.add_layer(Box::new(inbound));
    }

    #[test]
    fn roundtrip() {
        // Take canned keys and make sure we can do crypto correctly.
        use crate::crypto::handshake::ShakeKeyGenerator as KGen;
        fn s(seed: &[u8]) -> SecretBuf {
            seed.to_vec().into()
        }

        let seed1 = s(b"hidden we are free");
        let seed2 = s(b"free to speak, to free ourselves");
        let seed3 = s(b"free to hide no more");

        let mut cc_out = OutboundClientCrypt::new();
        let mut cc_in = InboundClientCrypt::new();
        let pair = Tor1RelayCrypto::construct(KGen::new(seed1.clone())).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);
        let pair = Tor1RelayCrypto::construct(KGen::new(seed2.clone())).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);
        let pair = Tor1RelayCrypto::construct(KGen::new(seed3.clone())).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);

        assert_eq!(cc_in.n_layers(), 3);
        assert_eq!(cc_out.n_layers(), 3);

        let mut r1 = Tor1RelayCrypto::<RelayCellFormatV0>::construct(KGen::new(seed1)).unwrap();
        let mut r2 = Tor1RelayCrypto::<RelayCellFormatV0>::construct(KGen::new(seed2)).unwrap();
        let mut r3 = Tor1RelayCrypto::<RelayCellFormatV0>::construct(KGen::new(seed3)).unwrap();

        let mut rng = testing_rng();
        for _ in 1..300 {
            // outbound cell
            let mut cell = Box::new([0_u8; 509]);
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig);
            cell.copy_from_slice(&cell_orig);
            let mut cell = cell.into();
            let _tag = cc_out.encrypt(&mut cell, 2.into()).unwrap();
            assert_ne!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);
            assert!(!r1.decrypt_outbound(&mut cell));
            assert!(!r2.decrypt_outbound(&mut cell));
            assert!(r3.decrypt_outbound(&mut cell));

            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // inbound cell
            let mut cell = Box::new([0_u8; 509]);
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig);
            cell.copy_from_slice(&cell_orig);
            let mut cell = cell.into();

            r3.originate(&mut cell);
            r3.encrypt_inbound(&mut cell);
            r2.encrypt_inbound(&mut cell);
            r1.encrypt_inbound(&mut cell);
            let (layer, _tag) = cc_in.decrypt(&mut cell).unwrap();
            assert_eq!(layer, 2.into());
            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // TODO: Test tag somehow.
        }

        // Try a failure: sending a cell to a nonexistent hop.
        {
            let mut cell = Box::new([0_u8; 509]).into();
            let err = cc_out.encrypt(&mut cell, 10.into());
            assert!(matches!(err, Err(Error::NoSuchHop)));
        }

        // Try a failure: A junk cell with no correct auth from any layer.
        {
            let mut cell = Box::new([0_u8; 509]).into();
            let err = cc_in.decrypt(&mut cell);
            assert!(matches!(err, Err(Error::BadCellAuth)));
        }
    }

    // From tor's test_relaycrypt.c

    #[test]
    fn testvec() {
        use digest::XofReader;
        use digest::{ExtendableOutput, Update};

        // (The ....s at the end here are the KH ca)
        const K1: &[u8; 92] =
            b"    'My public key is in this signed x509 object', said Tom assertively.      (N-PREG-VIRYL)";
        const K2: &[u8; 92] =
            b"'Let's chart the pedal phlanges in the tomb', said Tom cryptographically.  (PELCG-GBR-TENCU)";
        const K3: &[u8; 92] =
            b"     'Segmentation fault bugs don't _just happen_', said Tom seethingly.        (P-GUVAT-YL)";

        const SEED: &[u8;108] = b"'You mean to tell me that there's a version of Sha-3 with no limit on the output length?', said Tom shakily.";

        // These test vectors were generated from Tor.
        let data: &[(usize, &str)] = &include!("../../testdata/cell_crypt.rs");

        let mut cc_out = OutboundClientCrypt::new();
        let mut cc_in = InboundClientCrypt::new();
        let pair = Tor1RelayCrypto::<RelayCellFormatV0>::initialize(&K1[..]).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);
        let pair = Tor1RelayCrypto::<RelayCellFormatV0>::initialize(&K2[..]).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);
        let pair = Tor1RelayCrypto::<RelayCellFormatV0>::initialize(&K3[..]).unwrap();
        add_layers(&mut cc_out, &mut cc_in, pair);

        let mut xof = tor_llcrypto::d::Shake256::default();
        xof.update(&SEED[..]);
        let mut stream = xof.finalize_xof();

        let mut j = 0;
        for cellno in 0..51 {
            let mut body = Box::new([0_u8; 509]);
            body[0] = 2; // command: data.
            body[4] = 1; // streamid: 1.
            body[9] = 1; // length: 498
            body[10] = 242;
            stream.read(&mut body[11..]);

            let mut cell = body.into();
            let _ = cc_out.encrypt(&mut cell, 2.into());

            if cellno == data[j].0 {
                let expected = hex::decode(data[j].1).unwrap();
                assert_eq!(cell.as_ref(), &expected[..]);
                j += 1;
            }
        }
    }

    #[test]
    fn hop_num_display() {
        for i in 0..10 {
            let hop_num = HopNum::from(i);
            let expect = format!("#{}", i + 1);

            assert_eq!(expect, hop_num.display().to_string());
        }
    }
}
