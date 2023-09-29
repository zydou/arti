//! Types related to binding messages to specific circuits

#[cfg(feature = "hs-service")]
use tor_hscrypto::ops::HsMacKey;
use zeroize::Zeroizing;

/// Number of bytes of circuit binding material negotiated per circuit hop.
pub(crate) const CIRC_BINDING_LEN: usize = 20;

/// Cryptographic information used to bind a message to a specific circuit.
///
/// This information is used in some of our protocols (currently only the onion
/// services protocol) to prove that a given message was referring to a specific
/// hop on a specific circuit, and was not replayed from another circuit.
///
/// In `tor-spec` and `rend-spec`, this value is called `KH`.
#[derive(Clone)]
pub struct CircuitBinding(
    // We use a Box here to avoid  moves that would bypass the zeroize-on-drop
    // semantics.
    //
    // (This is not super-critical, since the impact of leaking one of these
    // keys is slight, but it's best not to leak them at all.)
    Box<Zeroizing<[u8; CIRC_BINDING_LEN]>>,
);

impl From<[u8; CIRC_BINDING_LEN]> for CircuitBinding {
    fn from(value: [u8; CIRC_BINDING_LEN]) -> Self {
        Self(Box::new(Zeroizing::new(value)))
    }
}

impl TryFrom<&[u8]> for CircuitBinding {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: &[u8; CIRC_BINDING_LEN] = &value
            .try_into()
            .or(Err(Self::Error::InvalidKDFOutputLength))?;
        Ok(Self::from(*value))
    }
}

impl CircuitBinding {
    /// Return a view of this key suitable for computing the MAC function used
    /// to authenticate onion services' ESTABLISH_INTRODUCE messages.
    ///
    /// Note that this is not a general-purpose MAC; please avoid adding new
    /// users of it.  See notes on [`hs_mac`](tor_hscrypto::ops::hs_mac) for
    /// more information.
    #[cfg(feature = "hs-service")]
    pub fn hs_mac(&self) -> HsMacKey<'_> {
        HsMacKey::from(self.dangerously_into_bytes())
    }

    /// Return a view of this key as a byte-slice.
    ///
    /// This is potentially dangerous, since we don't want to expose this
    /// information: We only want to use it as a MAC key.
    #[cfg(feature = "hs-service")]
    fn dangerously_into_bytes(&self) -> &[u8] {
        &(**self.0)[..]
    }
}
