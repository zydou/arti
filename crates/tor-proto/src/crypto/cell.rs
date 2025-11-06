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

#[cfg(feature = "bench")]
pub(crate) mod bench_utils;
#[cfg(feature = "counter-galois-onion")]
pub(crate) mod cgo;
pub(crate) mod tor1;

use crate::{Error, Result};
use derive_deftly::Deftly;
use tor_cell::{
    chancell::{BoxedCellBody, ChanCmd},
    relaycell::msg::SendmeTag,
};
use tor_memquota::derive_deftly_template_HasMemoryCost;

use super::binding::CircuitBinding;

/// Type for the body of a relay cell.
#[cfg_attr(feature = "bench", visibility::make(pub))]
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
#[cfg_attr(feature = "bench", visibility::make(pub))]
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
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait ClientLayer<F, B>
where
    F: OutboundClientLayer,
    B: InboundClientLayer,
{
    /// Consume this ClientLayer and return a paired forward and reverse
    /// crypto layer, and a [`CircuitBinding`] object
    fn split_client_layer(self) -> (F, B, CircuitBinding);
}

/// A paired object containing the inbound and outbound cryptographic layers
/// used by a relay to implement a client's circuits.
///
#[allow(dead_code)] // To be used by relays.
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait RelayLayer<F, B>
where
    F: OutboundRelayLayer,
    B: InboundRelayLayer,
{
    /// Consume this ClientLayer and return a paired forward and reverse
    /// crypto layers, and a [`CircuitBinding`] object
    fn split_relay_layer(self) -> (F, B, CircuitBinding);
}

/// Represents a relay's view of the inbound crypto state on a given circuit.
#[allow(dead_code)] // Relays are not yet implemented.
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait InboundRelayLayer {
    /// Prepare a RelayCellBody to be sent towards the client,
    /// and encrypt it.
    ///
    /// Return the authentication tag.
    fn originate(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody) -> SendmeTag;
    /// Encrypt a RelayCellBody that is moving towards the client.
    fn encrypt_inbound(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody);
}

/// Represent a relay's view of the outbound crypto state on a given circuit.
#[allow(dead_code)]
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait OutboundRelayLayer {
    /// Decrypt a RelayCellBody that is coming from the client.
    ///
    /// Return an authentication tag if it is addressed to us.
    fn decrypt_outbound(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody) -> Option<SendmeTag>;
}

/// A client's view of the cryptographic state shared with a single relay on a
/// circuit, as used for outbound cells.
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait OutboundClientLayer {
    /// Prepare a RelayCellBody to be sent to the relay at this layer, and
    /// encrypt it.
    ///
    /// Return the authentication tag.
    fn originate_for(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody) -> SendmeTag;
    /// Encrypt a RelayCellBody to be decrypted by this layer.
    fn encrypt_outbound(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody);
}

/// A client's view of the crypto state shared with a single relay on a circuit,
/// as used for inbound cells.
#[cfg_attr(feature = "bench", visibility::make(pub))]
pub(crate) trait InboundClientLayer {
    /// Decrypt a CellBody that passed through this layer.
    ///
    /// Return an authentication tag if this layer is the originator.
    fn decrypt_inbound(&mut self, cmd: ChanCmd, cell: &mut RelayCellBody) -> Option<SendmeTag>;
}

/// Type to store hop indices on a circuit.
///
/// Hop indices are zero-based: "0" denotes the first hop on the circuit.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deftly, Ord, PartialOrd)]
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

    /// Return true if this is  the first hop of a circuit.
    pub(crate) fn is_first_hop(&self) -> bool {
        self.0 == 0
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
#[cfg_attr(feature = "bench", visibility::make(pub), derive(Default))]
pub(crate) struct OutboundClientCrypt {
    /// Vector of layers, one for each hop on the circuit, ordered from the
    /// closest hop to the farthest.
    layers: Vec<Box<dyn OutboundClientLayer + Send>>,
}

/// A client's view of the cryptographic state for an entire
/// constructed circuit, as used for receiving cells.
#[cfg_attr(feature = "bench", visibility::make(pub), derive(Default))]
pub(crate) struct InboundClientCrypt {
    /// Vector of layers, one for each hop on the circuit, ordered from the
    /// closest hop to the farthest.
    layers: Vec<Box<dyn InboundClientLayer + Send>>,
}

impl OutboundClientCrypt {
    /// Return a new (empty) OutboundClientCrypt.
    #[cfg_attr(feature = "bench", visibility::make(pub))]
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
    #[cfg_attr(feature = "bench", visibility::make(pub))]
    pub(crate) fn encrypt(
        &mut self,
        cmd: ChanCmd,
        cell: &mut RelayCellBody,
        hop: HopNum,
    ) -> Result<SendmeTag> {
        let hop: usize = hop.into();
        if hop >= self.layers.len() {
            return Err(Error::NoSuchHop);
        }

        let mut layers = self.layers.iter_mut().take(hop + 1).rev();
        let first_layer = layers.next().ok_or(Error::NoSuchHop)?;
        let tag = first_layer.originate_for(cmd, cell);
        for layer in layers {
            layer.encrypt_outbound(cmd, cell);
        }
        Ok(tag)
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
    #[cfg_attr(feature = "bench", visibility::make(pub))]
    pub(crate) fn new() -> Self {
        InboundClientCrypt { layers: Vec::new() }
    }
    /// Decrypt an incoming cell that is coming to the client.
    ///
    /// On success, return which hop was the originator of the cell.
    // TODO(nickm): Use a real type for the tag, not just `&[u8]`.
    #[cfg_attr(feature = "bench", visibility::make(pub))]
    pub(crate) fn decrypt(
        &mut self,
        cmd: ChanCmd,
        cell: &mut RelayCellBody,
    ) -> Result<(HopNum, SendmeTag)> {
        for (hopnum, layer) in self.layers.iter_mut().enumerate() {
            if let Some(tag) = layer.decrypt_inbound(cmd, cell) {
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
pub(crate) type Tor1RelayCrypto =
    tor1::CryptStatePair<tor_llcrypto::cipher::aes::Aes128Ctr, tor_llcrypto::d::Sha1>;

/// Standard Tor relay crypto, as instantiated for the HSv3 protocol.
///
/// (The use of SHA3 is ridiculously overkill.)
#[cfg(feature = "hs-common")]
pub(crate) type Tor1Hsv3RelayCrypto =
    tor1::CryptStatePair<tor_llcrypto::cipher::aes::Aes256Ctr, tor_llcrypto::d::Sha3_256>;

/// Counter galois onion relay crypto.
//
// We use `aes` directly here instead of tor_llcrypto::aes, which may or may not be OpenSSL:
// the OpenSSL implementations have bad performance when it comes to re-keying
// or changing IVs.
#[cfg(feature = "counter-galois-onion")]
pub(crate) type CgoRelayCrypto = cgo::CryptStatePair<aes::Aes128, aes::Aes128Enc>;

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
    use rand::{RngCore, seq::IndexedRandom as _};
    use tor_basic_utils::{RngExt as _, test_rng::testing_rng};
    use tor_bytes::SecretBuf;
    use tor_cell::relaycell::RelayCellFormat;

    pub(crate) fn add_layers(
        cc_out: &mut OutboundClientCrypt,
        cc_in: &mut InboundClientCrypt,
        pair: Tor1RelayCrypto,
    ) {
        let (outbound, inbound, _) = pair.split_client_layer();
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

        let (mut r1f, mut r1b, _) = Tor1RelayCrypto::construct(KGen::new(seed1))
            .unwrap()
            .split_relay_layer();
        let (mut r2f, mut r2b, _) = Tor1RelayCrypto::construct(KGen::new(seed2))
            .unwrap()
            .split_relay_layer();
        let (mut r3f, mut r3b, _) = Tor1RelayCrypto::construct(KGen::new(seed3))
            .unwrap()
            .split_relay_layer();
        let cmd = ChanCmd::RELAY;

        let mut rng = testing_rng();
        for _ in 1..300 {
            // outbound cell
            let mut cell = Box::new([0_u8; 509]);
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig);
            cell.copy_from_slice(&cell_orig);
            let mut cell = cell.into();
            let _tag = cc_out.encrypt(cmd, &mut cell, 2.into()).unwrap();
            assert_ne!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);
            assert!(r1f.decrypt_outbound(cmd, &mut cell).is_none());
            assert!(r2f.decrypt_outbound(cmd, &mut cell).is_none());
            assert!(r3f.decrypt_outbound(cmd, &mut cell).is_some());

            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // inbound cell
            let mut cell = Box::new([0_u8; 509]);
            let mut cell_orig = [0_u8; 509];
            rng.fill_bytes(&mut cell_orig);
            cell.copy_from_slice(&cell_orig);
            let mut cell = cell.into();

            r3b.originate(cmd, &mut cell);
            r2b.encrypt_inbound(cmd, &mut cell);
            r1b.encrypt_inbound(cmd, &mut cell);
            let (layer, _tag) = cc_in.decrypt(cmd, &mut cell).unwrap();
            assert_eq!(layer, 2.into());
            assert_eq!(&cell.as_ref()[9..], &cell_orig.as_ref()[9..]);

            // TODO: Test tag somehow.
        }

        // Try a failure: sending a cell to a nonexistent hop.
        {
            let mut cell = Box::new([0_u8; 509]).into();
            let err = cc_out.encrypt(cmd, &mut cell, 10.into());
            assert!(matches!(err, Err(Error::NoSuchHop)));
        }

        // Try a failure: A junk cell with no correct auth from any layer.
        {
            let mut cell = Box::new([0_u8; 509]).into();
            let err = cc_in.decrypt(cmd, &mut cell);
            assert!(matches!(err, Err(Error::BadCellAuth)));
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

    /// Helper: Clear every field in the tor1 `cell` that is reserved for cryptography by relay cell
    /// format `version.
    ///
    /// We do this so that we can be sure that the _other_ fields have all been transmitted correctly.
    fn clean_cell_fields(cell: &mut RelayCellBody, format: RelayCellFormat) {
        use super::tor1;
        match format {
            RelayCellFormat::V0 => {
                cell.0[tor1::RECOGNIZED_RANGE].fill(0);
                cell.0[tor1::DIGEST_RANGE].fill(0);
            }
            RelayCellFormat::V1 => {
                cell.0[0..16].fill(0);
            }
            _ => {
                panic!("Unrecognized format!");
            }
        }
    }

    /// Helper: Test a single-hop message, forward from the client.
    fn test_fwd_one_hop<CS, RS, CF, CB, RF, RB>(format: RelayCellFormat)
    where
        CS: CryptInit + ClientLayer<CF, CB>,
        RS: CryptInit + RelayLayer<RF, RB>,
        CF: OutboundClientLayer,
        CB: InboundClientLayer,
        RF: OutboundRelayLayer,
        RB: InboundRelayLayer,
    {
        let mut rng = testing_rng();
        assert_eq!(CS::seed_len(), RS::seed_len());
        let mut seed = vec![0; CS::seed_len()];
        rng.fill_bytes(&mut seed[..]);
        let (mut client, _, _) = CS::initialize(&seed).unwrap().split_client_layer();
        let (mut relay, _, _) = RS::initialize(&seed).unwrap().split_relay_layer();

        for _ in 0..5 {
            let mut cell = RelayCellBody(Box::new([0_u8; 509]));
            rng.fill_bytes(&mut cell.0[..]);
            clean_cell_fields(&mut cell, format);
            let msg_orig = cell.clone();

            let ctag = client.originate_for(ChanCmd::RELAY, &mut cell);
            assert_ne!(cell.0[16..], msg_orig.0[16..]);
            let rtag = relay.decrypt_outbound(ChanCmd::RELAY, &mut cell);
            clean_cell_fields(&mut cell, format);
            assert_eq!(cell.0[..], msg_orig.0[..]);
            assert_eq!(rtag, Some(ctag));
        }
    }

    /// Helper: Test a single-hop message, backwards towards the client.
    fn test_rev_one_hop<CS, RS, CF, CB, RF, RB>(format: RelayCellFormat)
    where
        CS: CryptInit + ClientLayer<CF, CB>,
        RS: CryptInit + RelayLayer<RF, RB>,
        CF: OutboundClientLayer,
        CB: InboundClientLayer,
        RF: OutboundRelayLayer,
        RB: InboundRelayLayer,
    {
        let mut rng = testing_rng();
        assert_eq!(CS::seed_len(), RS::seed_len());
        let mut seed = vec![0; CS::seed_len()];
        rng.fill_bytes(&mut seed[..]);
        let (_, mut client, _) = CS::initialize(&seed).unwrap().split_client_layer();
        let (_, mut relay, _) = RS::initialize(&seed).unwrap().split_relay_layer();

        for _ in 0..5 {
            let mut cell = RelayCellBody(Box::new([0_u8; 509]));
            rng.fill_bytes(&mut cell.0[..]);
            clean_cell_fields(&mut cell, format);
            let msg_orig = cell.clone();

            let rtag = relay.originate(ChanCmd::RELAY, &mut cell);
            assert_ne!(cell.0[16..], msg_orig.0[16..]);
            let ctag = client.decrypt_inbound(ChanCmd::RELAY, &mut cell);
            clean_cell_fields(&mut cell, format);
            assert_eq!(cell.0[..], msg_orig.0[..]);
            assert_eq!(ctag, Some(rtag));
        }
    }

    fn test_fwd_three_hops_leaky<CS, RS, CF, CB, RF, RB>(format: RelayCellFormat)
    where
        CS: CryptInit + ClientLayer<CF, CB>,
        RS: CryptInit + RelayLayer<RF, RB>,
        CF: OutboundClientLayer + Send + 'static,
        CB: InboundClientLayer,
        RF: OutboundRelayLayer,
        RB: InboundRelayLayer,
    {
        let mut rng = testing_rng();
        assert_eq!(CS::seed_len(), RS::seed_len());
        let mut client = OutboundClientCrypt::new();
        let mut relays = Vec::new();
        for _ in 0..3 {
            let mut seed = vec![0; CS::seed_len()];
            rng.fill_bytes(&mut seed[..]);
            let (client_layer, _, _) = CS::initialize(&seed).unwrap().split_client_layer();
            let (relay_layer, _, _) = RS::initialize(&seed).unwrap().split_relay_layer();
            client.add_layer(Box::new(client_layer));
            relays.push(relay_layer);
        }

        'cell_loop: for _ in 0..32 {
            let mut cell = RelayCellBody(Box::new([0_u8; 509]));
            rng.fill_bytes(&mut cell.0[..]);
            clean_cell_fields(&mut cell, format);
            let msg_orig = cell.clone();
            let cmd = *[ChanCmd::RELAY, ChanCmd::RELAY_EARLY]
                .choose(&mut rng)
                .unwrap();
            let hop: u8 = rng.gen_range_checked(0_u8..=2).unwrap();

            let ctag = client.encrypt(cmd, &mut cell, hop.into()).unwrap();

            for r_idx in 0..=hop {
                let rtag = relays[r_idx as usize].decrypt_outbound(cmd, &mut cell);
                if let Some(rtag) = rtag {
                    clean_cell_fields(&mut cell, format);
                    assert_eq!(cell.0[..], msg_orig.0[..]);
                    assert_eq!(rtag, ctag);
                    continue 'cell_loop;
                }
            }
            panic!("None of the relays thought that this cell was recognized!");
        }
    }

    fn test_rev_three_hops_leaky<CS, RS, CF, CB, RF, RB>(format: RelayCellFormat)
    where
        CS: CryptInit + ClientLayer<CF, CB>,
        RS: CryptInit + RelayLayer<RF, RB>,
        CF: OutboundClientLayer,
        CB: InboundClientLayer + Send + 'static,
        RF: OutboundRelayLayer,
        RB: InboundRelayLayer,
    {
        let mut rng = testing_rng();
        assert_eq!(CS::seed_len(), RS::seed_len());
        let mut client = InboundClientCrypt::new();
        let mut relays = Vec::new();
        for _ in 0..3 {
            let mut seed = vec![0; CS::seed_len()];
            rng.fill_bytes(&mut seed[..]);
            let (_, client_layer, _) = CS::initialize(&seed).unwrap().split_client_layer();
            let (_, relay_layer, _) = RS::initialize(&seed).unwrap().split_relay_layer();
            client.add_layer(Box::new(client_layer));
            relays.push(relay_layer);
        }

        for _ in 0..32 {
            let mut cell = RelayCellBody(Box::new([0_u8; 509]));
            rng.fill_bytes(&mut cell.0[..]);
            clean_cell_fields(&mut cell, format);
            let msg_orig = cell.clone();
            let cmd = *[ChanCmd::RELAY, ChanCmd::RELAY_EARLY]
                .choose(&mut rng)
                .unwrap();
            let hop: u8 = rng.gen_range_checked(0_u8..=2).unwrap();

            let rtag = relays[hop as usize].originate(cmd, &mut cell);
            for r_idx in (0..hop.into()).rev() {
                relays[r_idx as usize].encrypt_inbound(cmd, &mut cell);
            }

            let (observed_hop, ctag) = client.decrypt(cmd, &mut cell).unwrap();
            assert_eq!(observed_hop, hop.into());
            clean_cell_fields(&mut cell, format);
            assert_eq!(cell.0[..], msg_orig.0[..]);
            assert_eq!(ctag, rtag);
        }
    }

    macro_rules! integration_tests { { $modname:ident($fmt:expr, $ctype:ty, $rtype:ty) } => {
        mod $modname {
            use super::*;
            #[test]
            fn test_fwd_one_hop() {
                super::test_fwd_one_hop::<$ctype, $rtype, _, _, _, _>($fmt);
            }
            #[test]
            fn test_rev_one_hop() {
                super::test_rev_one_hop::<$ctype, $rtype, _, _, _, _>($fmt);
            }
            #[test]
            fn test_fwd_three_hops_leaky() {
                super::test_fwd_three_hops_leaky::<$ctype, $rtype, _, _, _, _>($fmt);
            }
            #[test]
            fn test_rev_three_hops_leaky() {
                super::test_rev_three_hops_leaky::<$ctype, $rtype, _, _, _, _>($fmt);
            }
        }
    }}

    integration_tests! { tor1(RelayCellFormat::V0, Tor1RelayCrypto, Tor1RelayCrypto) }
    #[cfg(feature = "hs-common")]
    integration_tests! { tor1_hs(RelayCellFormat::V0, Tor1Hsv3RelayCrypto, Tor1Hsv3RelayCrypto) }

    #[cfg(feature = "counter-galois-onion")]
    integration_tests! {
        cgo_aes128(RelayCellFormat::V1,
            cgo::CryptStatePair<aes::Aes128Dec, aes::Aes128Enc>,// client
            cgo::CryptStatePair<aes::Aes128Enc, aes::Aes128Enc> // relay
        )
    }
    #[cfg(feature = "counter-galois-onion")]
    integration_tests! {
        cgo_aes256(RelayCellFormat::V1,
            cgo::CryptStatePair<aes::Aes256Dec, aes::Aes256Enc>,// client
            cgo::CryptStatePair<aes::Aes256Enc, aes::Aes256Enc> // relay
        )
    }
}
