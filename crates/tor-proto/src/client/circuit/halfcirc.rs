//! A "receive-only" view of a circuit, as a placeholder for circuits
//! that have closed.

use crate::{Error, Result};

/// A HalfCirc represents the receive-only aspects of a circuit, for
/// use to represent closed circuits and make sure that only
/// acceptable data is received there.
// TODO: This should probably have an expiration time too.
#[derive(Debug, Clone)]
pub(crate) struct HalfCirc {
    /// How many RELAY cells will we accept on this circuit before we
    /// conclude that somebody is violating the protocols?
    allow_relay_cells: u16,
}

impl HalfCirc {
    /// Create a new HalfCirc that will allow `total_windows` RELAY cells.
    pub(crate) fn new(total_windows: u16) -> Self {
        HalfCirc {
            allow_relay_cells: total_windows,
        }
    }

    /// Try receiving a relay cell on this circuit. Give an error if there
    /// have been too many such cells to believe.
    pub(crate) fn receive_cell(&mut self) -> Result<()> {
        if let Some(n) = self.allow_relay_cells.checked_sub(1) {
            self.allow_relay_cells = n;
            Ok(())
        } else {
            Err(Error::ChanProto(
                "Too many cells received on destroyed circuit".into(),
            ))
        }
    }
}
