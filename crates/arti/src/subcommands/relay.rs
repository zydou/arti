//! The `relay` subcommand.

use clap::{ArgMatches, Parser};
use tor_rtcompat::Runtime;

use crate::{ArtiConfig, Result};

/// The relay subcommands the arti CLI will be augmented with.
#[derive(Debug, Parser)]
pub(crate) enum RelaySubcommands {
    /// Run Arti in relay mode acting as a relay of the Tor network.
    Relay(Relay),
}

#[derive(Debug, Parser)]
pub(crate) struct Relay {}

/// Run the `relay` subcommand.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run<R: Runtime>(
    _runtime: R,
    _matches: &ArgMatches,
    _config: &ArtiConfig,
) -> Result<()> {
    // TODO: Actually implement the launch of a relay.
    todo!()
}
