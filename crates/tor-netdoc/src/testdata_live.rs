//! Test data, downloaded from the live network, and filtered to reduce its size

use derive_deftly::{Deftly, define_derive_deftly};

#[macro_use]
#[path = "../testdata-live/selected_relays.rs"]
mod selected_relays;

/// Three test data file contents', one per variety
#[derive(Clone, Debug, Deftly)]
#[derive_deftly(PerVariety)]
#[non_exhaustive]
pub struct PerVariety {
    /// Plain consensus
    #[deftly(variety_file = "consensus")]
    pub plain: &'static str,

    /// Microdescriptor consensus
    #[deftly(variety_file = "consensus-microdesc")]
    pub md: &'static str,

    /// Vote
    #[deftly(variety_file = "authority")]
    pub vote: &'static str,
}

/// Test data for one (selected) relay
#[derive(Clone, Debug, Deftly)]
#[non_exhaustive]
pub struct PerRelay {
    /// Nickname
    pub nick: &'static str,

    /// Data for this relay
    pub data: PerVariety,
}

define_derive_deftly! {
    use ForSelectedRelays;

    /// Define the constants for each network status variety
    ///
    /// Driven by the fields in [`PerVariety`].
    ///
    /// Makes use of `ForSelectedRelays`, which is an X-macro[*] maintained
    /// by the `testdata-live` script.  That avoids this file having to have knowledge
    /// of the nicknames of the relays.  (There is nothing in std for listing directories
    /// at compile time.)
    ///
    /// \[*] In derive-deftly, user-defined expansions don't have arguments,
    /// but each  `$define`s have dynamic scope, so they can be used as named arguments.
    PerVariety expect items, beta_deftly:

    ${define DIR "../testdata-live"}
    ${define VARIETY_FILE $"${fmeta(variety_file) as str}"}

    /// Network status documents
    pub const NETSTATUS: PerVariety = PerVariety{ $(
        $fname: include_str!($"$DIR/$VARIETY_FILE"),
    ) };

    // "DO" function (for `ForSelectedRelays`, X-macro maintained by testdata-live-download).
    //
    // $RELAY_NICK is defined (in the dynamic scope) by `ForSelectedRelays`;
    // $WHICH_RELAY_DATA is defined at each of the two call sites of $FOR_SELECTED_RELAYS.
    ${define DO_SELECTED_RELAY {
        PerRelay {
            nick: $"$RELAY_NICK",
            data: PerVariety { $(
                $fname: include_str!($"$DIR/$VARIETY_FILE--$WHICH_RELAY_DATA--$RELAY_NICK"),
            ) },
        },
    }}

    /// Relays' routerstatus entries (excerpts from each corresponding network status)
    pub const RELAY_ROUTERSTATUSES: &[PerRelay] = &[
        ${define WHICH_RELAY_DATA "entry"}
        $FOR_SELECTED_RELAYS
    ];

    /// Relays' router descriptors and microdescriptors
    pub const RELAY_DESCRIPTORS: &[PerRelay] = &[
        ${define WHICH_RELAY_DATA "desc"}
        $FOR_SELECTED_RELAYS
    ];
}
use derive_deftly_template_PerVariety;
