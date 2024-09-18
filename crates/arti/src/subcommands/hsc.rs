//! The `hsc` subcommand.

use crate::{Result, TorClient};

use anyhow::{anyhow, Context};
use arti_client::{HsClientDescEncKey, HsId, InertTorClient, KeystoreSelector, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand, ValueEnum};
use tor_rtcompat::Runtime;

use std::fs::OpenOptions;
use std::io;

/// The hsc subcommands the arti CLI will be augmented with.
#[derive(Parser, Debug)]
pub(crate) enum HscSubcommands {
    /// Run state management commands for an Arti hidden service client.
    #[command(subcommand)]
    Hsc(HscSubcommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum HscSubcommand {
    /// Prepare a service discovery key for connecting
    /// to a service running in restricted discovery mode.
    #[command(arg_required_else_help = true)]
    GetKey(GetKeyArgs),
}

/// A type of key
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
enum KeyType {
    /// A service discovery key for connecting to a service
    /// running in restricted discovery mode.
    #[default]
    ServiceDiscovery,
}

/// The arguments of the [`GetKey`](HscSubcommand::GetKey)
/// subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct GetKeyArgs {
    /// The type of key to retrieve.
    #[arg(
        long,
        default_value_t = KeyType::ServiceDiscovery,
        value_enum
    )]
    key_type: KeyType,

    // TODO: these arguments won't all apply to every KeyType.
    // We should find a way to define argument groups for each KeyType.
    /// The .onion address of the hidden service
    #[arg(long)]
    onion_name: HsId,

    /// Write the public key to FILE. Use - to write to stdout
    #[arg(long, name = "FILE")]
    output: String,

    /// Whether to overwrite the output file if it already exists
    #[arg(long)]
    overwrite: bool,

    /// Whether to generate the key if it is missing
    #[arg(
        long,
        default_value_t = GenerateKey::IfNeeded,
        value_enum
    )]
    generate: GenerateKey,
    // TODO: add an option for selecting the keystore to generate the keypair in
}

/// Whether to generate the key if missing.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
enum GenerateKey {
    /// Do not generate the key.
    No,
    /// Generate the key if it's missing.
    #[default]
    IfNeeded,
}

/// Run the `hsc` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    hsc_matches: &ArgMatches,
    config: &TorClientConfig,
) -> Result<()> {
    let subcommand =
        HscSubcommand::from_arg_matches(hsc_matches).expect("Could not parse hsc subcommand");
    let client = TorClient::with_runtime(runtime)
        .config(config.clone())
        .create_inert()?;

    match subcommand {
        HscSubcommand::GetKey(args) => prepare_service_discovery_key(&args, client),
    }
}

/// Run the `hsc prepare-stealth-mode-key` subcommand.
fn prepare_service_discovery_key(
    args: &GetKeyArgs,
    client: InertTorClient,
) -> Result<()> {
    let key = match args.generate {
        GenerateKey::IfNeeded => {
            // TODO: consider using get_or_generate in generate_service_discovery_key
            client
                .get_service_discovery_key(args.onion_name)?
                .map(Ok)
                .unwrap_or_else(|| {
                    client
                        .generate_service_discovery_key(KeystoreSelector::Default, args.onion_name)
                })?
        }
        GenerateKey::No => match client.get_service_discovery_key(args.onion_name)? {
            Some(key) => key,
            None => {
                return Err(anyhow!(
                        "Service discovery key not found. Rerun with --generate=if-needed to generate a new service discovery keypair"
                    ));
            }
        },
    };

    // Output the public key to the specified file, or to stdout.
    match args.output.as_str() {
        "-" => write_public_key(io::stdout(), &key)?,
        filename => {
            let res = OpenOptions::new()
                .create(true)
                .create_new(!args.overwrite)
                .write(true)
                .truncate(true)
                .open(filename)
                .and_then(|f| write_public_key(f, &key));

            if let Err(e) = res {
                match e.kind() {
                    io::ErrorKind::AlreadyExists => {
                        return Err(anyhow!("{filename} already exists. Move it, or rerun with --overwrite to overwrite it"));
                    }
                    _ => {
                        // TODO maybe handle some other ErrorKinds
                        return Err(e)
                            .with_context(|| format!("could not write public key to {filename}"));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Write the public part of `key` to `f`.
fn write_public_key(mut f: impl io::Write, key: &HsClientDescEncKey) -> io::Result<()> {
    write!(f, "{}", key)?;
    Ok(())
}
