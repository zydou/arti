//! Unique identifiers for circuits.

use std::fmt::{Display, Formatter};

/// Process-unique identifier for a circuit.
///
/// We could use channel_id.circid here, but the circid can be reused
/// over time.  This won't ever repeat on a 64-bit architecture, and
/// is super-unlikely to repeat on a 32-bit architecture.  (If
/// we're about to return a repeat value, we assert instead.)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct UniqId {
    /// Channel that this circuit is on.
    chan: usize,
    /// ID for the circuit on the channel
    circ: usize,
}

impl UniqId {
    /// Construct a new circuit UniqId from its parts
    pub(crate) fn new(chan: usize, circ: usize) -> Self {
        UniqId { chan, circ }
    }

    /// A helper for displaying the process-unique identifiers of this circuit.
    ///
    /// Unlike the [`Display`] implementation, this does not display a `Circ` prefix.
    pub fn display_chan_circ(&self) -> impl Display + '_ {
        DisplayChanCirc(self)
    }
}

impl Display for UniqId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circ {}", self.display_chan_circ())
    }
}

/// A helper for displaying the process-unique identifiers of this circuit.
struct DisplayChanCirc<'a>(&'a UniqId);

impl<'a> Display for DisplayChanCirc<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.0.chan, self.0.circ)
    }
}
