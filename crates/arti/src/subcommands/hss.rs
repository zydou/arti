//! The `hss` subcommand.

use arti_client::TorClientConfig;
use clap::ArgMatches;

use crate::{ArtiConfig, Result, TorClient};

/// Run the `hss` subcommand.
pub(crate) fn run(
    hss_matches: &ArgMatches,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let nickname = hss_matches
        .get_one::<String>("nickname")
        .expect("non-optional nickname flag not specified?!");

    if let Some(_onion_name_matches) = hss_matches.subcommand_matches("onion-name") {
        let nickname = tor_hsservice::HsNickname::try_from(nickname.clone())?;
        let Some(svc_config) = config
            .onion_services
            .iter()
            .find(|(n, _)| **n == nickname)
            .map(|(_, cfg)| cfg.svc_cfg.clone())
        else {
            println!("Service {nickname} is not configured");
            return Ok(());
        };

        // TODO: PreferredRuntime was arbitrarily chosen and is entirely unused
        // (we have to specify a concrete type for the runtime when calling
        // TorClient::create_onion_service).
        //
        // Maybe this suggests TorClient is not the right place for
        // create_onion_service()
        let onion_svc = TorClient::<tor_rtcompat::PreferredRuntime>::create_onion_service(
            client_config,
            svc_config,
        )?;

        // TODO: instead of the printlns here, we should have a formatter type that
        // decides how to display the output
        if let Some(onion) = onion_svc.onion_name() {
            println!("{onion}");
        } else {
            println!("Service {nickname} does not exist, or does not have an K_hsid yet");
        }
    }

    Ok(())
}
