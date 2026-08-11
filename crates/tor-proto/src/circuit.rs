//! Circuit-related types and helpers.
//!
//! This code is shared between the client and relay implementations.

pub(crate) mod cell_sender;
pub(crate) mod celltypes;
pub(crate) mod circ_sender;
pub(crate) mod circhop;
pub(crate) mod create;
pub(crate) mod padding;
pub(crate) mod reactor;
pub(crate) mod syncview;
pub(crate) mod unique_id;

pub use crate::memquota::StreamAccount;
pub use syncview::CircHopSyncView;
pub use unique_id::UniqId;

use crate::ccparams::CongestionControlParams;
use crate::stream::flow_ctrl::params::FlowCtrlParameters;
use tor_cell::relaycell::extend::SubprotocolRequest;
use tor_error::ErrorKind;
use tor_protover::Protocols;

pub(crate) use circ_sender::{CircuitRxReceiver, CircuitRxSender};

/// Estimated upper bound for the likely number of hops.
pub(crate) const HOPS: usize = 6;

/// Description of the network's current rules for building circuits.
///
/// This type describes rules derived from the consensus,
/// and possibly amended by our own configuration.
///
/// Typically, this type created once for an entire circuit,
/// and any special per-hop information is derived
/// from each hop as a CircTarget.
/// Note however that callers _may_ provide different `CircParameters`
/// for different hops within a circuit if they have some reason to do so,
/// so we do not enforce that every hop in a circuit has the same `CircParameters`.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    pub extend_by_ed25519_id: bool,
    /// Congestion control parameters for this circuit.
    pub ccontrol: CongestionControlParams,

    /// Flow control parameters to use for all streams on this circuit.
    // While flow control is a stream property and not a circuit property,
    // and it may seem better to pass the flow control parameters to for example `begin_stream()`,
    // it's included in [`CircParameters`] for the following reasons:
    //
    // - When endpoints (exits + hs) receive new stream requests, they need the flow control
    //   parameters immediately. It would be easy to pass flow control parameters when creating a
    //   stream, but it's not as easy to get flow control parameters when receiving a new stream
    //   request, unless those parameters are already available to the circuit (like
    //   `CircParameters` are).
    // - It's unclear if new streams on existing circuits should switch to new flow control
    //   parameters if the consensus changes. This behaviour doesn't appear to be specified. It
    //   might also leak information to the circuit's endpoint about when we downloaded new
    //   directory documents. So it seems best to stick with the same flow control parameters for
    //   the lifetime of the circuit.
    // - It doesn't belong in [`StreamParameters`] as `StreamParameters` is a set of preferences
    //   with defaults, and consensus parameters aren't preferences and don't have defaults.
    //   (Technically they have defaults, but `StreamParameters` isn't the place to set them.)
    pub flow_ctrl: FlowCtrlParameters,

    /// Maximum number of permitted incoming relay cells for each hop.
    ///
    /// If we would receive more relay cells than this from a single hop,
    /// we close the circuit with [`ExcessInboundCells`](crate::Error::ExcessInboundCells).
    ///
    /// If this value is None, then there is no limit to the number of inbound cells.
    ///
    /// Known limitation: If this value if `u32::MAX`,
    /// then a limit of `u32::MAX - 1` is enforced.
    pub n_incoming_cells_permitted: Option<u32>,

    /// Maximum number of permitted outgoing relay cells for each hop.
    ///
    /// If we would try to send more relay cells than this from a single hop,
    /// we close the circuit with [`ExcessOutboundCells`](crate::Error::ExcessOutboundCells).
    /// It is the circuit-user's responsibility to make sure that this does not happen.
    ///
    /// This setting is used to ensure that we do not violate a limit
    /// imposed by `n_incoming_cells_permitted`
    /// on the other side of a circuit.
    ///
    /// If this value is None, then there is no limit to the number of outbound cells.
    ///
    /// Known limitation: If this value if `u32::MAX`,
    /// then a limit of `u32::MAX - 1` is enforced.
    pub n_outgoing_cells_permitted: Option<u32>,
}

tor_protover::subprotocol_restricted_set! {
    /// The enabled/disabled status of subprotocols that are allowed to be requested through a
    /// subprotocol request during a circuit handshake.
    ///
    /// The allowed subprotocols are defined in:
    /// <https://spec.torproject.org/tor-spec/create-created-cells.html#subproto-request>
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct HandshakeSubprotocols {
        RELAY_CRYPT_CGO,
    }
}

impl HandshakeSubprotocols {
    /// Build a [`HandshakeSubprotocols`] from a [`SubprotocolRequest`]
    /// provided during a circuit handshake.
    ///
    /// If the `SubprotocolRequest` contains subprotocols that aren't
    /// allowed to be requested through a subprotocol request,
    /// this returns an error containing the original `SubprotocolRequest`.
    //
    // It would be nice to return a list of only the invalid subprotocols,
    // but it seems a bit expensive to compute on the error path when we probably
    // want to fail quickly.
    pub(crate) fn try_from_request(
        protos: SubprotocolRequest,
    ) -> Result<Self, InvalidHandshakeSubprotocolError> {
        use std::sync::LazyLock;
        static ALL: LazyLock<Protocols> =
            LazyLock::new(|| Protocols::from(HandshakeSubprotocols::ALL));

        if !protos.contains_only(&ALL) {
            return Err(InvalidHandshakeSubprotocolError(protos));
        }

        Ok(Self {
            relay_crypt_cgo: protos.contains(tor_protover::named::RELAY_CRYPT_CGO),
        })
    }
}

/// The subprotocol request had subprotocols that are not all supported in circuit handshakes.
///
/// Contains the requested subprotocols (both valid and invalid).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("Request included subprotocols that we do not support in circuit handshakes: {0:?}")]
pub(crate) struct InvalidHandshakeSubprotocolError(SubprotocolRequest);

impl tor_error::HasKind for InvalidHandshakeSubprotocolError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::TorProtocolViolation
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[cfg(feature = "relay")]
    use crate::relay::{CircNetParameters, CongestionControlNetParams};

    pub(crate) use super::circ_sender::test::fake_mpsc;

    /// Return a new [`CircNetParameters`] using default values for unit tests. They are based on
    /// consensus defaults but should not be considered to be accurate from the one used on the
    /// production network.
    #[cfg(feature = "relay")]
    pub(crate) fn new_circ_net_params() -> CircNetParameters {
        CircNetParameters {
            cc: CongestionControlNetParams::defaults_for_tests(),
        }
    }

    #[test]
    fn handshake_subprotocols() {
        let empty_iter: [tor_protover::NumberedSubver; 0] = [];
        let request = SubprotocolRequest::from_iter(empty_iter);
        assert_eq!(
            HandshakeSubprotocols::try_from_request(request),
            Ok(HandshakeSubprotocols {
                relay_crypt_cgo: false,
            }),
        );

        let request = SubprotocolRequest::from_iter([tor_protover::named::RELAY_CRYPT_CGO]);
        assert_eq!(
            HandshakeSubprotocols::try_from_request(request),
            Ok(HandshakeSubprotocols {
                relay_crypt_cgo: true,
            }),
        );

        let request =
            SubprotocolRequest::from_iter([tor_protover::named::RELAY_NEGOTIATE_SUBPROTO]);
        assert!(HandshakeSubprotocols::try_from_request(request).is_err());

        let request = SubprotocolRequest::from_iter([
            tor_protover::named::RELAY_NEGOTIATE_SUBPROTO,
            tor_protover::named::RELAY_CRYPT_CGO,
        ]);
        assert!(HandshakeSubprotocols::try_from_request(request).is_err());
    }
}
