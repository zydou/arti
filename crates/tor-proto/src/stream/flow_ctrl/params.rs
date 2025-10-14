//! Consensus parameters for stream flow control.

/// Parameters from the consensus that are required for stream flow control.
// We want an exhaustive struct with public fields here. If we add a field here, it's probably
// because we need it. A builder pattern would mean that the user's code would fail at runtime if
// they didn't provide a parameter, rather than at compile time. There is also no `Default` for this
// struct as the defaults belong in `NetParameters`, so a non-exhaustive struct would not be able to
// be constructed.
#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_structs)]
pub struct FlowCtrlParameters {
    /// See `tor_netdir::params::NetParameters::cc_xoff_client`.
    // This conversion rate is copied from c-tor (see `flow_control_new_consensus_params()`).
    // TODO: This const conversion rate becomes part of the public API, but it shouldn't be. The
    // alternative is a bunch of boilerplate code to hide it, so just leaving for now since
    // tor-proto is not stable.
    pub cc_xoff_client: CellCount<{ tor_cell::relaycell::PAYLOAD_MAX_SIZE_ALL as u32 }>,
    /// See `tor_netdir::params::NetParameters::cc_xoff_exit`.
    // This conversion rate is copied from c-tor (see `flow_control_new_consensus_params()`).
    pub cc_xoff_exit: CellCount<{ tor_cell::relaycell::PAYLOAD_MAX_SIZE_ALL as u32 }>,
    /// See `tor_netdir::params::NetParameters::cc_xon_rate`.
    // This conversion rate is copied from c-tor (see `flow_control_new_consensus_params()`).
    pub cc_xon_rate: CellCount<{ tor_cell::relaycell::PAYLOAD_MAX_SIZE_ANY as u32 }>,
    /// See `tor_netdir::params::NetParameters::cc_xon_change_pct`.
    pub cc_xon_change_pct: u32,
    /// See `tor_netdir::params::NetParameters::cc_xon_ewma_cnt`.
    pub cc_xon_ewma_cnt: u32,
}

impl FlowCtrlParameters {
    #[cfg(test)]
    pub(crate) fn defaults_for_tests() -> Self {
        // These have been copied from the current consensus, but may be out of date.
        Self {
            cc_xoff_client: CellCount::new(500),
            cc_xoff_exit: CellCount::new(500),
            cc_xon_rate: CellCount::new(500),
            cc_xon_change_pct: 25,
            cc_xon_ewma_cnt: 2,
        }
    }
}

/// A cell count that can be converted into a byte count using a constant conversion rate.
///
/// The const generic is the conversion multiplier when converting from cells to bytes.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CellCount<const BYTES_PER_CELL: u32>(u32);

impl<const BYTES_PER_CELL: u32> CellCount<BYTES_PER_CELL> {
    /// A new [`CellCount`].
    pub const fn new(cells: u32) -> Self {
        Self(cells)
    }

    /// The [`CellCount`] as the number of cells.
    ///
    /// This is the value that [`CellCount`] was originally constructed with.
    pub const fn as_cells(&self) -> u32 {
        self.0
    }

    /// The number of payload bytes corresponding to this [`CellCount`].
    ///
    /// This is a constant multiple of the cell count,
    /// and is the conversion we use for the consensus parameters.
    /// For example `cc_xoff_client` which says:
    ///
    /// > Specifies the outbuf length, in relay cell multiples
    pub const fn as_bytes(&self) -> u64 {
        // u32 to u64 cast
        let cells = self.0 as u64;

        cells
            // u32 to u64 cast
            .checked_mul(BYTES_PER_CELL as u64)
            .expect("u32 * u32 should fit within a u64")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn compare_to_ctor_values() {
        let params = FlowCtrlParameters {
            cc_xoff_client: CellCount::new(1),
            cc_xoff_exit: CellCount::new(1),
            cc_xon_rate: CellCount::new(1),
            cc_xon_change_pct: 1,
            cc_xon_ewma_cnt: 1,
        };

        // If any of these assertions fail in the future,
        // it means that the value no longer matches with C-tor
        // `RELAY_PAYLOAD_SIZE_MIN`/`RELAY_PAYLOAD_SIZE_MAX`.
        // If this happens we should re-evaluate the status of things and see if we should hard-code
        // this to be the same as C-tor, or remove this check.

        /// `RELAY_PAYLOAD_SIZE_MIN` from c-tor
        const C_TOR_RELAY_PAYLOAD_SIZE_MIN: u64 = 509 - (16 + 1 + 2 + 2);
        /// `RELAY_PAYLOAD_SIZE_MAX` from c-tor
        const C_TOR_RELAY_PAYLOAD_SIZE_MAX: u64 = 509 - (1 + 2 + 2 + 4 + 2);

        assert_eq!(
            params.cc_xoff_client.as_bytes(),
            C_TOR_RELAY_PAYLOAD_SIZE_MIN,
        );
        assert_eq!(params.cc_xoff_exit.as_bytes(), C_TOR_RELAY_PAYLOAD_SIZE_MIN);
        assert_eq!(params.cc_xon_rate.as_bytes(), C_TOR_RELAY_PAYLOAD_SIZE_MAX);
    }
}
