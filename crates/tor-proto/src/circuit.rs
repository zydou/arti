//! Circuit-related types and helpers.
//!
//! This code is shared between the client and relay implementations.

pub(crate) mod cell_sender;
pub(crate) mod celltypes;
pub(crate) mod circhop;
pub(crate) mod syncview;
pub(crate) mod unique_id;

pub use crate::memquota::StreamAccount;
pub use syncview::CircSyncView;
pub use unique_id::UniqId;

use crate::ccparams::CongestionControlParams;
use crate::stream::flow_ctrl::params::FlowCtrlParameters;

use tor_cell::chancell::msg::AnyChanMsg;
use tor_memquota::mq_queue::{self, MpscSpec};

/// The following two MPSCs take any channel message as the receiving end can be either a client or
/// a relay circuit reactor. The reactor itself will convert into its restricted message set. On
/// error, the circuit will shutdown as it will be considered a protocol violation.
///
/// MPSC queue for inbound data on its way from channel to circuit, sender
pub(crate) type CircuitRxSender = mq_queue::Sender<AnyChanMsg, MpscSpec>;
/// MPSC queue for inbound data on its way from channel to circuit, receiver
pub(crate) type CircuitRxReceiver = mq_queue::Receiver<AnyChanMsg, MpscSpec>;

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
