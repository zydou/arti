//! The `proxy` subcommand.

use arti_client::TorClientConfig;
use clap::ArgMatches;

use crate::{ArtiConfig, ConfigurationSources, Result, Runtime};

/// Run the `proxy` subcommand.
pub(crate) fn run<R: Runtime>(
    _runtime: R,
    _proxy_matches: &ArgMatches,
    _cfg_sources: ConfigurationSources,
    _config: ArtiConfig,
    _client_config: TorClientConfig,
) -> Result<()> {
    todo!()
}
