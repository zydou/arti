//! Module exposing structures relating to the reactor's view of a circuit's hops.
//!
//! TODO(DEDUP): this will eventually replace [crate::client::reactor::circuit::circhop].

use crate::circuit::HOPS;
use crate::circuit::circhop::{CircHopInbound, HopSettings};
use crate::circuit::reactor::stream::StreamMsg;
use crate::congestion::CongestionControl;
use crate::{HopNum, Result};
use std::sync::{Arc, Mutex};

use futures::channel::mpsc;
use smallvec::SmallVec;

use tor_cell::relaycell::RelayCellDecoder;
use tor_error::internal;

/// Per-hop state.
pub(crate) struct CircHop {
    /// A sender for sending relay messages to this hop's stream reactor.
    ///
    /// Set to `None` if we haven't yet spawned a stream reactor for this hop.
    pub(crate) tx: Option<mpsc::Sender<StreamMsg>>,
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

/// Represents the reactor's view of a circuit's hops.
#[derive(Default)]
pub(crate) struct CircHopList {
    /// The list of hops.
    ///
    /// Relays have only one.
    /// Clients have one entry per circuit hop.
    hops: SmallVec<[CircHop; HOPS]>,
}

impl CircHopList {
    /// Return a reference to the hop corresponding to `hopnum`, if there is one.
    ///
    /// Relays pass `None` for the `hopnum`.
    pub(crate) fn get(&self, hop: Option<HopNum>) -> Option<&CircHop> {
        self.hops.get(Self::index(hop))
    }

    /// Return a mutable reference to the hop corresponding to `hopnum`, if there is one.
    ///
    /// Relays pass `None` for the `hopnum`.
    pub(crate) fn get_mut(&mut self, hop: Option<HopNum>) -> Option<&mut CircHop> {
        self.hops.get_mut(Self::index(hop))
    }

    /// Push a new hop to our hop list.
    ///
    /// Prepares a cc object for the hop, but does not spawn a stream reactor.
    ///
    /// Will return an error if the circuit already has [`u8::MAX`] hops.
    pub(crate) fn add_hop(&mut self, settings: HopSettings) -> Result<()> {
        let hop_num = self.hops.len();
        debug_assert_eq!(hop_num, usize::from(self.num_hops()));

        // There are several places in the code that assume that a `usize` hop number
        // can be cast or converted to a `u8` hop number,
        // so this check is important to prevent panics or incorrect behaviour.
        if hop_num == usize::from(u8::MAX) {
            return Err(internal!("cannot add more hops to a circuit with `u8::MAX` hops").into());
        }

        let relay_format = settings.relay_crypt_protocol().relay_cell_format();
        let inbound = CircHopInbound::new(RelayCellDecoder::new(relay_format), &settings);
        let ccontrol = Arc::new(Mutex::new(CongestionControl::new(&settings.ccontrol)));

        self.hops.push(CircHop {
            inbound,
            ccontrol,
            settings,
            tx: None,
        });

        Ok(())
    }

    /// The number of hops in this circuit.
    fn num_hops(&self) -> u8 {
        // `Self::add_hop` checks to make sure that we never have more than `u8::MAX` hops,
        // so `self.hops.len()` should be safe to cast to a `u8`.
        // If that assumption is violated,
        // we choose to panic rather than silently use the wrong hop due to an `as` cast.
        self.hops
            .len()
            .try_into()
            .expect("`hops.len()` has more than `u8::MAX` hops")
    }

    /// Return the index of the specified `hop`.
    ///
    /// Returns 0 if the `hop` is `None`.
    fn index(hop: Option<HopNum>) -> usize {
        // unwrap_or_default(), because for relays, hop is None,
        // and we just want to use the first slot of the vec
        hop.map(usize::from).unwrap_or_default()
    }
}
