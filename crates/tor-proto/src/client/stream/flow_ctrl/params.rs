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
    pub cc_xoff_client: u32,
    /// See `tor_netdir::params::NetParameters::cc_xoff_exit`.
    pub cc_xoff_exit: u32,
    /// See `tor_netdir::params::NetParameters::cc_xon_rate`.
    pub cc_xon_rate: u32,
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
            cc_xoff_client: 500,
            cc_xoff_exit: 500,
            cc_xon_rate: 500,
            cc_xon_change_pct: 25,
            cc_xon_ewma_cnt: 2,
        }
    }
}

/// A cell count that can be converted into a byte count using a constant conversion rate.
///
/// The const generic is the conversion multiplier when converting from cells to bytes.
#[derive(Clone, Debug)]
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
