//! Module exposing structures relating to the reactor's view of a circuit's hops.
//!
//! TODO(DEDUP): this will eventually replace [crate::client::reactor::circuit::circhop].

use crate::circuit::HOPS;
use crate::circuit::circhop::{CircHopInbound, HopSettings};
use crate::circuit::reactor::stream::CtrlMsg;
use crate::congestion::CongestionControl;
use crate::{HopNum, Result};
use std::sync::{Arc, Mutex};

use futures::channel::mpsc;

use tor_cell::relaycell::RelayCellDecoder;
use tor_error::{Bug, internal};

use std::result::Result as StdResult;

/// Per-hop state.
pub(crate) struct CircHop {
    /// A sender for sending relay messages to this hop's stream reactor.
    ///
    /// Set to `None` if we haven't yet spawned a stream reactor for this hop.
    pub(crate) tx: Option<mpsc::Sender<CtrlMsg>>,
    /// The congestion control state.
    ///
    /// This is shared with `CircHopOutbound`.
    ///
    // TODO(DEDUP): the Arc is not actually needed in the new generic circuit reactor
    // (it only exists because CircHopOutbound/CircHop needs it).
    pub(crate) ccontrol: Arc<Mutex<CongestionControl>>,
    /// The inbound hop state of this hop.
    pub(crate) inbound: CircHopInbound,
    /// Settings negotiated with this hop.
    pub(crate) settings: HopSettings,
}

impl CircHop {
    /// Create a new [`CircHop`] from the specified settings.
    fn new(settings: HopSettings) -> Self {
        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let inbound = CircHopInbound::new(RelayCellDecoder::new(relay_format), &settings);
        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));

        Self {
            inbound,
            ccontrol,
            settings,
            tx: None,
        }
    }
}

/// Represents the reactor's view of a circuit's hops.
pub(crate) enum CircHopList {
    /// A relay's view of the circuit hop it represents.
    Relay(CircHop),
    /// A client's view of the circuit hops.
    Client(Vec<CircHop>),
}

impl CircHopList {
    /// Create a new [`CircHopList`] for a relay circuit.
    pub(crate) fn new_relay(settings: HopSettings) -> Self {
        Self::Relay(CircHop::new(settings))
    }

    /// Create a new [`CircHopList`] for a client circuit.
    pub(crate) fn new_client() -> Self {
        Self::Client(Vec::with_capacity(HOPS))
    }

    /// Return a reference to the hop corresponding to `hopnum`, if there is one.
    ///
    /// Relays pass `None` for the `hopnum`.
    pub(crate) fn get(&self, hop: Option<HopNum>) -> StdResult<&CircHop, Bug> {
        use CircHopList::*;

        let res = match (self, hop) {
            (Relay(circhop), None) => Some(circhop),
            (Client(hops), Some(hop)) => hops.get(usize::from(hop)),
            (Relay(_), Some(_)) => None,
            (Client(_), None) => None,
        };

        res.ok_or_else(|| internal!("tried to use non-existent hop {hop:?}?!"))
    }

    /// Return a mutable reference to the hop corresponding to `hopnum`, if there is one.
    ///
    /// Relays pass `None` for the `hopnum`.
    pub(crate) fn get_mut(&mut self, hop: Option<HopNum>) -> StdResult<&mut CircHop, Bug> {
        use CircHopList::*;

        let res = match (self, hop) {
            (Relay(circhop), None) => Some(circhop),
            (Client(hops), Some(hop)) => hops.get_mut(usize::from(hop)),
            (Relay(_), Some(_)) => None,
            (Client(_), None) => None,
        };

        res.ok_or_else(|| internal!("tried to use non-existent hop {hop:?}?!"))
    }

    /// Push a new hop to our hop list.
    ///
    /// Prepares a cc object for the hop, but does not spawn a stream reactor.
    ///
    /// Will return an error if the circuit already has [`u8::MAX`] hops.
    pub(crate) fn add_hop(&mut self, settings: HopSettings) -> Result<()> {
        match self {
            CircHopList::Relay(_) => {
                Err(internal!("tried to add another hop to a relay CircHopList?!").into())
            }
            CircHopList::Client(hops) => {
                let hop_num = hops.len();
                debug_assert_eq!(hop_num, usize::from(Self::num_hops(hops)));

                // There are several places in the code that assume that a `usize` hop number
                // can be cast or converted to a `u8` hop number,
                // so this check is important to prevent panics or incorrect behaviour.
                if hop_num == usize::from(u8::MAX) {
                    return Err(
                        internal!("cannot add more hops to a circuit with `u8::MAX` hops").into(),
                    );
                }

                hops.push(CircHop::new(settings));

                Ok(())
            }
        }
    }

    /// The number of hops in this circuit.
    fn num_hops(hops: &[CircHop]) -> u8 {
        // `Self::add_hop` checks to make sure that we never have more than `u8::MAX` hops,
        // so `self.hops.len()` should be safe to cast to a `u8`.
        // If that assumption is violated,
        // we choose to panic rather than silently use the wrong hop due to an `as` cast.
        hops.len()
            .try_into()
            .expect("`hops.len()` has more than `u8::MAX` hops")
    }
}
