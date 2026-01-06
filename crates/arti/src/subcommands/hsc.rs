//! The `hsc` subcommand.

use crate::subcommands::prompt;
use crate::{Result, TorClient};

use anyhow::{Context, anyhow};
use arti_client::{HsClientDescEncKey, HsId, InertTorClient, KeystoreSelector, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand, ValueEnum};
use safelog::DisplayRedacted;
use tor_rtcompat::Runtime;
#[cfg(feature = "onion-service-cli-extra")]
use {
    std::collections::{HashMap, hash_map::Entry},
    tor_hsclient::HsClientDescEncKeypairSpecifier,
    tor_hscrypto::pk::HsClientDescEncKeypair,
    tor_keymgr::{CTorPath, KeyPath, KeystoreEntry, KeystoreEntryResult, KeystoreId},
};

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::str::FromStr;

/// The hsc subcommands the arti CLI will be augmented with.
#[derive(Parser, Debug)]
pub(crate) enum HscSubcommands {
    /// Run state management commands for an Arti hidden service client.
    #[command(subcommand)]
    Hsc(HscSubcommand),
}

/// The `hsc` subcommand.
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

    /// Migrate service discovery keys from a registered CTor keystore to the primary
    /// keystore
    #[cfg(feature = "onion-service-cli-extra")]
    #[command(name = "ctor-migrate")]
    CTorMigrate(CTorMigrateArgs),
}

/// The `hsc-key` subcommand.
#[derive(Debug, Subcommand)]
pub(crate) enum KeySubcommand {
    /// Get or generate a hidden service client key
    #[command(arg_required_else_help = true)]
    Get(GetKeyArgs),

    /// Rotate a hidden service client key
    #[command(arg_required_else_help = true)]
    Rotate(RotateKeyArgs),

    /// Remove a hidden service client key
    #[command(arg_required_else_help = true)]
    Remove(RemoveKeyArgs),
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
    /// The type of the key.
    #[arg(
        long,
        default_value_t = KeyType::ServiceDiscovery,
        value_enum
    )]
    key_type: KeyType,

    /// With this flag active no prompt will be shown
    /// and no confirmation will be asked
    #[arg(long, short, default_value_t = false)]
    batch: bool,
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

/// The arguments of the [`Rotate`](KeySubcommand::Rotate) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct RotateKeyArgs {
    /// Arguments shared by all hsc subcommands.
    #[command(flatten)]
    common: CommonArgs,

    /// Arguments for configuring keygen.
    #[command(flatten)]
    keygen: KeygenArgs,
}

/// The arguments of the [`Remove`](KeySubcommand::Remove) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct RemoveKeyArgs {
    /// Arguments shared by all hsc subcommands.
    #[command(flatten)]
    common: CommonArgs,
}

/// The arguments of the [`CTorMigrate`](HscSubcommand::CTorMigrate) subcommand.
#[derive(Debug, Clone, Args)]
#[cfg(feature = "onion-service-cli-extra")]
pub(crate) struct CTorMigrateArgs {
    /// With this flag active no prompt will be shown
    /// and no confirmation will be asked.
    #[arg(long, short, default_value_t = false)]
    batch: bool,

    /// The ID of the keystore that should be migrated.
    // TODO: The command should detect if the ID provided belongs to a CTor keystore and return an
    // error if it does not.
    #[arg(long, short)]
    from: KeystoreId,
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
        #[cfg(feature = "onion-service-cli-extra")]
        HscSubcommand::CTorMigrate(args) => migrate_ctor_keys(&args, &client),
    }
}

/// Run the `hsc key` subcommand
fn run_key(subcommand: KeySubcommand, client: &InertTorClient) -> Result<()> {
    match subcommand {
        KeySubcommand::Get(args) => prepare_service_discovery_key(&args, client),
        KeySubcommand::Rotate(args) => rotate_service_discovery_key(&args, client),
        KeySubcommand::Remove(args) => remove_service_discovery_key(&args, client),
    }
}

/// Run the `hsc prepare-stealth-mode-key` subcommand.
fn prepare_service_discovery_key(args: &GetKeyArgs, client: &InertTorClient) -> Result<()> {
    let addr = get_onion_address(&args.common)?;
    let key = match args.generate {
        GenerateKey::IfNeeded => {
            // TODO: consider using get_or_generate in generate_service_discovery_key
            client
                .get_service_discovery_key(addr)?
                .map(Ok)
                .unwrap_or_else(|| {
                    client.generate_service_discovery_key(KeystoreSelector::Primary, addr)
                })?
        }
        GenerateKey::No => match client.get_service_discovery_key(addr)? {
            Some(key) => key,
            None => {
                return Err(anyhow!(
                    "Service discovery key not found. Rerun with --generate=if-needed to generate a new service discovery keypair"
                ));
            }
        },
    };

    display_service_discovery_key(&args.keygen, &key)
}

/// Display the public part of a service discovery key.
//
// TODO: have a more principled implementation for displaying messages, etc.
// For example, it would be nice to centralize the logic for writing to stdout/file,
// and to add a flag for choosing the output format (human-readable or json)
fn display_service_discovery_key(args: &KeygenArgs, key: &HsClientDescEncKey) -> Result<()> {
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
                        return Err(anyhow!(
                            "{filename} already exists. Move it, or rerun with --overwrite to overwrite it"
                        ));
                    }
                    _ => {
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
    writeln!(f, "{}", key)?;
    Ok(())
}

/// Run the `hsc rotate-key` subcommand.
fn rotate_service_discovery_key(args: &RotateKeyArgs, client: &InertTorClient) -> Result<()> {
    let addr = get_onion_address(&args.common)?;
    let msg = format!(
        "rotate client restricted discovery key for {}?",
        addr.display_unredacted()
    );
    if !args.common.batch && !prompt(&msg)? {
        return Ok(());
    }

    let key = client.rotate_service_discovery_key(KeystoreSelector::default(), addr)?;

    display_service_discovery_key(&args.keygen, &key)
}

/// Run the `hsc remove-key` subcommand.
fn remove_service_discovery_key(args: &RemoveKeyArgs, client: &InertTorClient) -> Result<()> {
    let addr = get_onion_address(&args.common)?;
    let msg = format!(
        "remove client restricted discovery key for {}?",
        addr.display_unredacted()
    );
    if !args.common.batch && !prompt(&msg)? {
        return Ok(());
    }

    let _key = client.remove_service_discovery_key(KeystoreSelector::default(), addr)?;

    Ok(())
}

/// Run the `hsc ctor-migrate` subcommand.
#[cfg(feature = "onion-service-cli-extra")]
fn migrate_ctor_keys(args: &CTorMigrateArgs, client: &InertTorClient) -> Result<()> {
    let keymgr = client.keymgr()?;
    let ctor_client_entries = read_ctor_keys(&keymgr.list_by_id(&args.from)?, args)?;

    // TODO: Simplify this logic when addressing issue #1359.
    // See [!3390 (comment 3288090)](https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3390#note_3288090).
    let arti_keystore_id = KeystoreId::from_str("arti")
        .map_err(|_| anyhow!("Default arti keystore ID is not valid?!"))?;
    for (hsid, entry) in ctor_client_entries {
        if let Ok(Some(key)) = keymgr.get_entry::<HsClientDescEncKeypair>(&entry) {
            let key_exists = keymgr
                .get_from::<HsClientDescEncKeypair>(
                    &HsClientDescEncKeypairSpecifier::new(hsid),
                    &arti_keystore_id,
                )?
                .is_some();
            let proceed = if args.batch || !key_exists {
                true
            } else {
                let p = format!(
                    "Found key in the primary keystore for service {}, do you want to replace it? ",
                    hsid.display_redacted()
                );
                prompt(&p)?
            };
            if proceed {
                let res = keymgr.insert(
                    key,
                    &HsClientDescEncKeypairSpecifier::new(hsid),
                    (&arti_keystore_id).into(),
                    true,
                );
                if let Err(e) = res {
                    eprintln!(
                        "Failed to insert key for service {}: {e}",
                        hsid.display_redacted()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Prompt the user for an onion address.
fn get_onion_address(args: &CommonArgs) -> Result<HsId, anyhow::Error> {
    let mut addr = String::new();
    if !args.batch {
        print!("Enter an onion address: ");
        io::stdout().flush().map_err(|e| anyhow!(e))?;
    };
    io::stdin().read_line(&mut addr).map_err(|e| anyhow!(e))?;

    HsId::from_str(addr.trim_end()).map_err(|e| anyhow!(e))
}

/// Helper function for `migrate_ctor_keys`.
///
/// Parses and returns the client keys from the CTor keystore identified by `--from` CLI flag.
/// Detects if there is a clash (different keys for the same hidden service within
/// the CTor keystore).
/// Such a situation is invalid, as each service must have a unique key.
/// If a clash is found, an error is returned.
/// If no clashes are detected, returns a `HashMap` of keystore entries, keyed
/// by hidden service identifier.
#[cfg(feature = "onion-service-cli-extra")]
fn read_ctor_keys<'a>(
    entries: &[KeystoreEntryResult<KeystoreEntry<'a>>],
    args: &CTorMigrateArgs,
) -> Result<HashMap<HsId, KeystoreEntry<'a>>> {
    let mut ctor_client_entries = HashMap::new();
    for entry in entries.iter().flatten() {
        if let KeyPath::CTor(CTorPath::HsClientDescEncKeypair { hs_id }) = entry.key_path() {
            match ctor_client_entries.entry(*hs_id) {
                Entry::Occupied(_) => {
                    return Err(anyhow!(
                        "Invalid C Tor keystore (multiple keys exist for service {})",
                        hs_id.display_redacted()
                    ));
                }
                Entry::Vacant(v) => {
                    v.insert(entry.clone());
                }
            }
        };
    }

    if ctor_client_entries.is_empty() {
        return Err(anyhow!(
            "No CTor client keys found in keystore {}",
            args.from,
        ));
    }

    Ok(ctor_client_entries)
}
