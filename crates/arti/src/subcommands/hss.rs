//! The `hss` subcommand.

use anyhow::anyhow;
use arti_client::TorClientConfig;
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use tor_hsservice::{HsId, HsNickname, OnionService};

use crate::{ArtiConfig, Result, TorClient};

/// The hss subcommands the arti CLI will be augmented with.
#[derive(Parser, Debug)]
pub(crate) enum HssSubcommands {
    /// Run state management commands for an Arti hidden service.
    Hss(Hss),
}

#[derive(Debug, Parser)]
pub(crate) struct Hss {
    /// Arguments shared by all hss subcommands.
    #[command(flatten)]
    common: CommonArgs,

    /// Return the identity key for the specified service.
    #[command(subcommand)]
    command: HssSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum HssSubcommand {
    /// Print the .onion address of a hidden service
    OnionName,
}

/// The arguments shared by all [`HssSubcommand`]s.
#[derive(Debug, Clone, Args)]
pub(crate) struct CommonArgs {
    /// The nickname of the service
    #[arg(long)]
    nickname: HsNickname,
}

/// Run the `hss` subcommand.
pub(crate) fn run(
    hss_matches: &ArgMatches,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let hss = Hss::from_arg_matches(hss_matches).expect("Could not parse hss subcommand");

    match hss.command {
        HssSubcommand::OnionName => onion_name(&hss.common, config, client_config),
    }
}

/// Create the OnionService configured with `nickname`.
fn create_svc(
    nickname: &HsNickname,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<OnionService> {
    let Some(svc_config) = config
        .onion_services
        .iter()
        .find(|(n, _)| *n == nickname)
        .map(|(_, cfg)| cfg.svc_cfg.clone())
    else {
        return Err(anyhow!("Service {nickname} is not configured"));
    };

    // TODO: PreferredRuntime was arbitrarily chosen and is entirely unused
    // (we have to specify a concrete type for the runtime when calling
    // TorClient::create_onion_service).
    //
    // Maybe this suggests TorClient is not the right place for
    // create_onion_service()
    Ok(
        TorClient::<tor_rtcompat::PreferredRuntime>::create_onion_service(
            client_config,
            svc_config,
        )?,
    )
}

/// Display the onion address, if any, of the specified service.
fn display_onion_name(nickname: &HsNickname, hsid: Option<HsId>) -> Result<()> {
    // TODO: instead of the printlns here, we should have a formatter type that
    // decides how to display the output
    if let Some(onion) = hsid {
        println!("{onion}");
    } else {
        return Err(anyhow!(
            "Service {nickname} does not exist, or does not have an K_hsid yet"
        ));
    }

    Ok(())
}

/// Run the `hss onion-name` subcommand.
fn onion_name(
    args: &CommonArgs,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let onion_svc = create_svc(&args.nickname, config, client_config)?;
    let hsid = onion_svc.onion_name();
    display_onion_name(&args.nickname, hsid)?;

    Ok(())
}
