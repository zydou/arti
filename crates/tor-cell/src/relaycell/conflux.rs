//! Encoding and decoding for relay messages related to conflux.

use super::msg::{Body, empty_body};

use amplify::Getters;
use caret::caret_int;
use derive_deftly::Deftly;
use rand::{CryptoRng, Rng, RngCore};

use tor_bytes::{EncodeResult, Error, Readable, Reader, Result, Writeable, Writer};
use tor_llcrypto::util::ct::CtByteArray;
use tor_memquota::derive_deftly_template_HasMemoryCost;

/// The supported CONFLUX_LINK version.
const CONFLUX_LINK_VERSION: u8 = 1;

/// The length of the nonce from a v1 CONFLUX_LINK message, in bytes.
const V1_LINK_NONCE_LEN: usize = 32;

/// Helper macro for implementing wrapper types over [`Link`]
macro_rules! impl_link_wrapper {
    ($wrapper:ty) => {
        impl $wrapper {
            /// Get the version of this message.
            pub fn version(&self) -> u8 {
                self.0.version
            }

            /// Get the [`V1LinkPayload`] of this message.
            pub fn payload(&self) -> &V1LinkPayload {
                &self.0.payload
            }
        }
    };
}

/// A `CONFLUX_LINK` message.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct ConfluxLink(Link);

impl ConfluxLink {
    /// Create a new v1 `CONFLUX_LINK` message.
    pub fn new(payload: V1LinkPayload) -> Self {
        let link = Link {
            version: CONFLUX_LINK_VERSION,
            payload,
        };

        Self(link)
    }
}

impl_link_wrapper!(ConfluxLink);

impl Body for ConfluxLink {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Link::decode_from_reader(r).map(Self)
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

/// A `CONFLUX_LINKED` message.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub struct ConfluxLinked(Link);

impl ConfluxLinked {
    /// Create a new v1 `CONFLUX_LINKED` message.
    pub fn new(payload: V1LinkPayload) -> Self {
        let link = Link {
            version: CONFLUX_LINK_VERSION,
            payload,
        };

        Self(link)
    }
}

impl_link_wrapper!(ConfluxLinked);

impl Body for ConfluxLinked {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Link::decode_from_reader(r).map(Self)
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

/// A message body shared by [`ConfluxLink`] and [`ConfluxLinked`].
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(HasMemoryCost)]
struct Link {
    /// The circuit linking mechanism version.
    ///
    /// Currently, 0x1 is the only recognized version.
    version: u8,
    /// The v1 payload.
    ///
    // TODO: this will need to be an enum over all supported payload versions,
    // if we ever move on from v1.
    payload: V1LinkPayload,
}

/// The nonce type of a [`V1LinkPayload`].
#[derive(Debug, Clone, Copy, Deftly, PartialEq, Eq)]
#[derive_deftly(HasMemoryCost)]
pub struct V1Nonce(CtByteArray<V1_LINK_NONCE_LEN>);

impl V1Nonce {
    /// Create a random `V1Nonce` to put in a LINK cell.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> V1Nonce {
        let mut nonce = [0_u8; V1_LINK_NONCE_LEN];
        rng.fill(&mut nonce[..]);
        Self(nonce.into())
    }
}

impl Readable for V1Nonce {
    fn take_from(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(Readable::take_from(r)?))
    }
}

impl Writeable for V1Nonce {
    fn write_onto<W: Writer + ?Sized>(&self, w: &mut W) -> EncodeResult<()> {
        self.0.write_onto(w)
    }
}

/// The v1 payload of a v1 [`ConfluxLink`] or [`ConfluxLinked`] message.
#[derive(Debug, Clone, Deftly, Getters)]
#[derive_deftly(HasMemoryCost)]
pub struct V1LinkPayload {
    /// Random 256-bit secret, for associating two circuits together.
    nonce: V1Nonce,
    /// The last sequence number sent.
    last_seqno_sent: u64,
    /// The last sequence number received.
    last_seqno_recv: u64,
    /// The desired UX properties.
    desired_ux: V1DesiredUx,
}

impl V1LinkPayload {
    /// Create a new `V1LinkPayload`.
    pub fn new(nonce: V1Nonce, desired_ux: V1DesiredUx) -> Self {
        Self {
            nonce,
            // NOTE: the two sequence number fields are 0 on the initial link.
            // We need to support setting these for reattachment/resumption
            // (see [CONFLUX_SET_MANAGEMENT] and [RESUMPTION]).
            last_seqno_sent: 0,
            last_seqno_recv: 0,
            desired_ux,
        }
    }

    /// Set the last sequence number sent.
    pub fn set_last_seqno_sent(&mut self, seqno: u64) {
        self.last_seqno_sent = seqno;
    }

    /// Set the last sequence number received.
    pub fn set_last_seqno_recv(&mut self, seqno: u64) {
        self.last_seqno_recv = seqno;
    }
}

caret_int! {
    /// The UX properties specified in a `V1LinkPayload`.
    #[derive(Deftly)]
    #[derive_deftly(HasMemoryCost)]
    pub struct V1DesiredUx(u8) {
        /// The sender has no preference.
        NO_OPINION = 0x0,
        /// Use MinRTT scheduling.
        MIN_LATENCY = 0x1,
        /// The low memory version of MIN_LATENCY.
        LOW_MEM_LATENCY = 0x2,
        /// Use LowRTT Scheduling.
        HIGH_THROUGHPUT = 0x3,
        /// The low memory version of HIGH_THROUGHPUT.
        LOW_MEM_THROUGHPUT = 0x4,
    }
}

impl Body for Link {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.take_u8()?;
        if version != CONFLUX_LINK_VERSION {
            return Err(Error::InvalidMessage(
                "Unrecognized CONFLUX_LINK/CONFLUX_LINKED version.".into(),
            ));
        }

        let payload = V1LinkPayload::decode_from_reader(r)?;

        Ok(Self { version, payload })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.version)?;
        self.payload.encode_onto(w)?;
        Ok(())
    }
}

impl Body for V1LinkPayload {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let nonce = r.extract()?;
        let last_seqno_sent = r.take_u64()?;
        let last_seqno_recv = r.take_u64()?;
        let desired_ux = r.take_u8()?.into();

        Ok(V1LinkPayload {
            nonce,
            last_seqno_sent,
            last_seqno_recv,
            desired_ux,
        })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        let V1LinkPayload {
            nonce,
            last_seqno_sent,
            last_seqno_recv,
            desired_ux,
        } = self;

        w.write(&nonce)?;
        w.write_u64(last_seqno_sent);
        w.write_u64(last_seqno_recv);
        w.write_u8(desired_ux.into());

        Ok(())
    }
}

/// A `CONFLUX_SWITCH` message, sent from a sending endpoint when switching leg
/// in an already linked circuit construction.
#[derive(Clone, Debug, Deftly, Getters)]
#[derive_deftly(HasMemoryCost)]
pub struct ConfluxSwitch {
    /// The relative sequence number.
    #[getter(as_copy)]
    seqno: u32,
}

impl ConfluxSwitch {
    /// Create a new v1 `CONFLUX_SWITCH` message.
    pub fn new(seqno: u32) -> Self {
        Self { seqno }
    }
}

impl Body for ConfluxSwitch {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let seqno = r.take_u32()?;
        Ok(Self { seqno })
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.seqno)?;
        Ok(())
    }
}

empty_body! {
    /// A `CONFLUX_LINKED_ACK` message.
    pub struct ConfluxLinkedAck {}
}
