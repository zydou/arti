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
    /// (Deprecated: use `arti hsc key get` instead)
    ///
    // TODO: use a clap deprecation attribute when clap supports it:
    // <https://github.com/clap-rs/clap/issues/3321>
    #[command(arg_required_else_help = true)]
    GetKey(GetKeyArgs),
    /// Key management subcommands.
    #[command(subcommand)]
    Key(KeySubcommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeySubcommand {
    /// Get or generate a hidden service client key
    /// Deprecated. Use key get instead.
    #[command(arg_required_else_help = true)]
    Get(GetKeyArgs),
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
    /// Arguments shared by all hsc subcommands.
    #[command(flatten)]
    common: CommonArgs,

    /// Arguments for configuring keygen.
    #[command(flatten)]
    keygen: KeygenArgs,

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

/// The common arguments of the key subcommands.
#[derive(Debug, Clone, Args)]
pub(crate) struct CommonArgs {
    /// The type of key to rotate.
    #[arg(
        long,
        default_value_t = KeyType::ServiceDiscovery,
        value_enum
    )]
    key_type: KeyType,

    /// The .onion address of the hidden service
    #[arg(long)]
    onion_name: HsId,
}

/// The common arguments of the key subcommands.
#[derive(Debug, Clone, Args)]
pub(crate) struct KeygenArgs {
    /// Write the public key to FILE. Use - to write to stdout
    #[arg(long, name = "FILE")]
    output: String,

    /// Whether to overwrite the output file if it already exists
    #[arg(long)]
    overwrite: bool,
}

/// Run the `hsc` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    hsc_matches: &ArgMatches,
    config: &TorClientConfig,
) -> Result<()> {
    use KeyType::*;

    let subcommand =
        HscSubcommand::from_arg_matches(hsc_matches).expect("Could not parse hsc subcommand");
    let client = TorClient::with_runtime(runtime)
        .config(config.clone())
        .create_inert()?;

    match subcommand {
        HscSubcommand::GetKey(args) => {
            eprintln!(
                "warning: using deprecated command 'arti hsc key-get` (hint: use 'arti hsc key get' instead)"
            );
            match args.common.key_type {
                ServiceDiscovery => prepare_service_discovery_key(&args, &client),
            }
        }
        HscSubcommand::Key(subcommand) => run_key(subcommand, &client),
    }
}

/// Run the `hsc key` subcommand
fn run_key(subcommand: KeySubcommand, client: &InertTorClient) -> Result<()> {
    match subcommand {
        KeySubcommand::Get(args) => prepare_service_discovery_key(&args, client),
    }
}

/// Run the `hsc prepare-stealth-mode-key` subcommand.
fn prepare_service_discovery_key(args: &GetKeyArgs, client: &InertTorClient) -> Result<()> {
    let key = match args.generate {
        GenerateKey::IfNeeded => {
            // TODO: consider using get_or_generate in generate_service_discovery_key
            client
                .get_service_discovery_key(args.common.onion_name)?
                .map(Ok)
                .unwrap_or_else(|| {
                    client.generate_service_discovery_key(
                        KeystoreSelector::Default,
                        args.common.onion_name,
                    )
                })?
        }
        GenerateKey::No => match client.get_service_discovery_key(args.common.onion_name)? {
            Some(key) => key,
            None => {
                return Err(anyhow!(
                        "Service discovery key not found. Rerun with --generate=if-needed to generate a new service discovery keypair"
                    ));
            }
        },
    };

    display_service_disocvery_key(&args.keygen, &key)
}

/// Display the public part of a service discovery key.
//
// TODO: have a more principled implementation for displaying messages, etc.
// For example, it would be nice to centralize the logic for writing to stdout/file,
// and to add a flag for choosing the output format (human-readable or json)
fn display_service_disocvery_key(args: &KeygenArgs, key: &HsClientDescEncKey) -> Result<()> {
    // Output the public key to the specified file, or to stdout.
    match args.output.as_str() {
        "-" => write_public_key(io::stdout(), key)?,
        filename => {
            let res = OpenOptions::new()
                .create(true)
                .create_new(!args.overwrite)
                .write(true)
                .truncate(true)
                .open(filename)
                .and_then(|f| write_public_key(f, key));

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
