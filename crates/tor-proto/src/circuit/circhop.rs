//! Module exposing structures relating to a reactor's view of a circuit hop.

// TODO(relay): don't import from the client module
use crate::client::circuit::handshake::RelayCryptLayerProtocol;

use crate::Result;
use crate::ccparams::CongestionControlParams;
use crate::circuit::CircParameters;
use crate::stream::flow_ctrl::params::FlowCtrlParameters;

use tor_cell::relaycell::RelayCellFormat;
use tor_cell::relaycell::extend::{CcRequest, CircRequestExt};
use tor_protover::named;

use cfg_if::cfg_if;

/// Type of negotiation that we'll be performing as we establish a hop.
///
/// Determines what flavor of extensions we can send and receive, which in turn
/// limits the hop settings we can negotiate.
///
// TODO-CGO: This is likely to be refactored when we finally add support for
// HsV3+CGO, which will require refactoring
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum HopNegotiationType {
    /// We're using a handshake in which extension-based negotiation cannot occur.
    None,
    /// We're using the HsV3-ntor handshake, in which the client can send extensions,
    /// but the server cannot.
    ///
    /// As a special case, the default relay encryption protocol is the hsv3
    /// variant of Tor1.
    //
    // We would call this "HalfDuplex" or something, but we do not expect to add
    // any more handshakes of this type.
    HsV3,
    /// We're using a handshake in which both client and relay can send extensions.
    Full,
}

/// The settings we use for single hop of a circuit.
///
/// Unlike [`CircParameters`], this type is crate-internal.
/// We construct it based on our settings from the circuit,
/// and from the hop's actual capabilities.
/// Then, we negotiate with the hop as part of circuit
/// creation/extension to determine the actual settings that will be in use.
/// Finally, we use those settings to construct the negotiated circuit hop.
//
// TODO: Relays should probably derive an instance of this type too, as
// part of the circuit creation handshake.
#[derive(Clone, Debug)]
pub(crate) struct HopSettings {
    /// The negotiated congestion control settings for this hop .
    pub(crate) ccontrol: CongestionControlParams,

    /// Flow control parameters that will be used for streams on this hop.
    pub(crate) flow_ctrl_params: FlowCtrlParameters,

    /// Maximum number of permitted incoming relay cells for this hop.
    pub(crate) n_incoming_cells_permitted: Option<u32>,

    /// Maximum number of permitted outgoing relay cells for this hop.
    pub(crate) n_outgoing_cells_permitted: Option<u32>,

    /// The relay cell encryption algorithm and cell format for this hop.
    relay_crypt_protocol: RelayCryptLayerProtocol,
}

impl HopSettings {
    /// Construct a new `HopSettings` based on `params` (a set of circuit parameters)
    /// and `caps` (a set of protocol capabilities for a circuit target).
    ///
    /// The resulting settings will represent what the client would prefer to negotiate
    /// (determined by `params`),
    /// as modified by what the target relay is believed to support (represented by `caps`).
    ///
    /// This represents the `HopSettings` in a pre-negotiation state:
    /// the circuit negotiation process will modify it.
    #[allow(clippy::unnecessary_wraps)] // likely to become fallible in the future.
    pub(crate) fn from_params_and_caps(
        hoptype: HopNegotiationType,
        params: &CircParameters,
        caps: &tor_protover::Protocols,
    ) -> Result<Self> {
        let mut ccontrol = params.ccontrol.clone();
        match ccontrol.alg() {
            crate::ccparams::Algorithm::FixedWindow(_) => {}
            crate::ccparams::Algorithm::Vegas(_) => {
                // If the target doesn't support FLOWCTRL_CC, we can't use Vegas.
                if !caps.supports_named_subver(named::FLOWCTRL_CC) {
                    ccontrol.use_fallback_alg();
                }
            }
        };
        if hoptype == HopNegotiationType::None {
            ccontrol.use_fallback_alg();
        } else if hoptype == HopNegotiationType::HsV3 {
            // TODO #2037, TODO-CGO: We need a way to send congestion control extensions
            // in this case too.  But since we aren't sending them, we
            // should use the fallback algorithm.
            ccontrol.use_fallback_alg();
        }
        let ccontrol = ccontrol; // drop mut

        // Negotiate CGO if it is supported, if CC is also supported,
        // and if CGO is available on this relay.
        let relay_crypt_protocol = match hoptype {
            HopNegotiationType::None => RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0),
            HopNegotiationType::HsV3 => {
                // TODO-CGO: Support CGO when available.
                cfg_if! {
                    if #[cfg(feature = "hs-common")] {
                        RelayCryptLayerProtocol::HsV3(RelayCellFormat::V0)
                    } else {
                        return Err(
                            tor_error::internal!("Unexpectedly tried to negotiate HsV3 without support!").into(),
                        );
                    }
                }
            }
            HopNegotiationType::Full => {
                cfg_if! {
                    if #[cfg(all(feature = "flowctl-cc", feature = "counter-galois-onion"))] {
                        #[allow(clippy::overly_complex_bool_expr)]
                        if  ccontrol.alg().compatible_with_cgo()
                            && caps.supports_named_subver(named::RELAY_NEGOTIATE_SUBPROTO)
                            && caps.supports_named_subver(named::RELAY_CRYPT_CGO)
                        {
                            RelayCryptLayerProtocol::Cgo
                        } else {
                            RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                        }
                    } else {
                        RelayCryptLayerProtocol::Tor1(RelayCellFormat::V0)
                    }
                }
            }
        };

        Ok(Self {
            ccontrol,
            flow_ctrl_params: params.flow_ctrl.clone(),
            relay_crypt_protocol,
            n_incoming_cells_permitted: params.n_incoming_cells_permitted,
            n_outgoing_cells_permitted: params.n_outgoing_cells_permitted,
        })
    }

    /// Return the negotiated relay crypto protocol.
    pub(crate) fn relay_crypt_protocol(&self) -> RelayCryptLayerProtocol {
        self.relay_crypt_protocol
    }

    /// Return the client circuit-creation extensions that we should use in order to negotiate
    /// these circuit hop parameters.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn circuit_request_extensions(&self) -> Result<Vec<CircRequestExt>> {
        // allow 'unused_mut' because of the combinations of `cfg` conditions below
        #[allow(unused_mut)]
        let mut client_extensions = Vec::new();

        #[allow(unused, unused_mut)]
        let mut cc_extension_set = false;

        if self.ccontrol.is_enabled() {
            cfg_if::cfg_if! {
                if #[cfg(feature = "flowctl-cc")] {
                    client_extensions.push(CircRequestExt::CcRequest(CcRequest::default()));
                    cc_extension_set = true;
                } else {
                    return Err(
                        tor_error::internal!(
                            "Congestion control is enabled on this circuit, but 'flowctl-cc' feature is not enabled"
                        )
                        .into()
                    );
                }
            }
        }

        // See whether we need to send a list of required protocol capabilities.
        // These aren't "negotiated" per se; they're simply demanded.
        // The relay will refuse the circuit if it doesn't support all of them,
        // and if any of them isn't supported in the SubprotocolRequest extension.
        //
        // (In other words, don't add capabilities here just because you want the
        // relay to have them! They must be explicitly listed as supported for use
        // with this extension. For the current list, see
        // https://spec.torproject.org/tor-spec/create-created-cells.html#subproto-request)
        //
        #[allow(unused_mut)]
        let mut required_protocol_capabilities: Vec<tor_protover::NamedSubver> = Vec::new();

        #[cfg(feature = "counter-galois-onion")]
        if matches!(self.relay_crypt_protocol(), RelayCryptLayerProtocol::Cgo) {
            if !cc_extension_set {
                return Err(tor_error::internal!("Tried to negotiate CGO without CC.").into());
            }
            required_protocol_capabilities.push(tor_protover::named::RELAY_CRYPT_CGO);
        }

        if !required_protocol_capabilities.is_empty() {
            client_extensions.push(CircRequestExt::SubprotocolRequest(
                required_protocol_capabilities.into_iter().collect(),
            ));
        }

        Ok(client_extensions)
    }
}

#[cfg(test)]
impl std::default::Default for CircParameters {
    fn default() -> Self {
        Self {
            extend_by_ed25519_id: true,
            ccontrol: crate::congestion::test_utils::params::build_cc_fixed_params(),
            flow_ctrl: FlowCtrlParameters::defaults_for_tests(),
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}

impl CircParameters {
    /// Constructor
    pub fn new(
        extend_by_ed25519_id: bool,
        ccontrol: CongestionControlParams,
        flow_ctrl: FlowCtrlParameters,
    ) -> Self {
        Self {
            extend_by_ed25519_id,
            ccontrol,
            flow_ctrl,
            n_incoming_cells_permitted: None,
            n_outgoing_cells_permitted: None,
        }
    }
}
