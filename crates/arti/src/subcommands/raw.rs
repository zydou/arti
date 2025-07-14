//! Low-level, plumbing subcommands.

use std::str::FromStr;

use anyhow::Result;
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};

use arti_client::{InertTorClient, TorClient, TorClientConfig};
use tor_keymgr::KeystoreId;
use tor_rtcompat::Runtime;

/// The `keys-raw` subcommands the arti CLI will be augmented with.
#[derive(Debug, Parser)]
pub(crate) enum RawSubcommands {
    /// Run plumbing key management commands.
    #[command(subcommand)]
    KeysRaw(RawSubcommand),
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum RawSubcommand {
    /// Remove keystore entry by path.
    RemoveByPath(RemoveByPathArgs),
}

/// The arguments of the [`RemoveByPath`](RawSubcommand::RemoveByPath) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct RemoveByPathArgs {
    /// The relative path of the keystore entry to remove.
    ///
    /// The path of an entry can be obtained from the field "Location" of the output
    /// of `arti keys list`.
    path: String,

    /// Identifier of the keystore to remove the entry from.
    /// If omitted, the primary store will be used ("arti").
    #[arg(short, long, default_value_t = String::from("arti"))]
    keystore_id: String,
}

/// Run the `keys-raw` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    keys_matches: &ArgMatches,
    config: &TorClientConfig,
) -> Result<()> {
    let subcommand =
        RawSubcommand::from_arg_matches(keys_matches).expect("Could not parse keys subcommand");
    let client = TorClient::with_runtime(runtime)
        .config(config.clone())
        .create_inert()?;

    match subcommand {
        RawSubcommand::RemoveByPath(args) => run_raw_remove(&args, &client),
    }
}

/// Run `key raw-remove-by-path` subcommand.
fn run_raw_remove(args: &RemoveByPathArgs, client: &InertTorClient) -> Result<()> {
    let keymgr = client.keymgr()?;
    let keystore_id = KeystoreId::from_str(&args.keystore_id)?;
    keymgr.remove_unchecked(&args.path, &keystore_id)?;

    Ok(())
}
