//! The `keys` subcommand.
// TODO: The output of these subcommands needs improvement. Also, some of the `display_` functions
// are repetitive and redundant.

use std::ops::Deref;
use std::str::FromStr;

use anyhow::Result;

use arti_client::{InertTorClient, TorClient, TorClientBuilder, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use safelog::DisplayRedacted;
use tor_keymgr::{
    CTorPath, KeyMgr, KeyPath, KeystoreEntry, KeystoreEntryResult, KeystoreId,
    UnrecognizedEntryError,
};
use tor_rtcompat::Runtime;

use crate::{ArtiConfig, subcommands::prompt};

#[cfg(feature = "onion-service-service")]
use tor_hsservice::OnionService;

/// Length of a line, used for formatting
// TODO: use COLUMNS instead of an arbitrary LINE_LEN
const LINE_LEN: usize = 80;

/// The `keys` subcommands the arti CLI will be augmented with.
#[derive(Debug, Parser)]
pub(crate) enum KeysSubcommands {
    /// Run keystore management commands.
    #[command(subcommand)]
    Keys(KeysSubcommand),
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum KeysSubcommand {
    /// List keys and certificates.
    ///
    /// Note: The output fields "Location" and "Keystore ID" represent,
    /// respectively, the raw identifier of an entry (e.g. <ARTI_PATH>.<ENTRY_TYPE>
    /// for `ArtiNativeKeystore`), and the identifier of the keystore that
    /// contains the entry.
    List(ListArgs),

    /// List keystores.
    ListKeystores,

    /// Validate the integrity of keystores.
    ///
    /// Detects and reports unrecognized entries and paths, as well as
    /// malformed or expired keys.
    ///
    /// Such entries will be removed if this command is invoked with `--sweep`.
    CheckIntegrity(CheckIntegrityArgs),
}

/// The arguments of the [`List`](KeysSubcommand::List) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct ListArgs {
    /// Identifier of the keystore.
    ///
    /// If omitted, keys and certificates
    /// from all the keystores will be returned.
    #[arg(short, long)]
    keystore_id: Option<String>,
}

/// The arguments of the [`CheckIntegrity`](KeysSubcommand::CheckIntegrity) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct CheckIntegrityArgs {
    /// Identifier of the keystore.
    ///
    /// If omitted, keys and certificates
    /// from all the keystores will be checked.
    #[arg(short, long)]
    keystore_id: Option<KeystoreId>,

    /// Remove the detected invalid keystore entries.
    #[arg(long, short, default_value_t = false)]
    sweep: bool,

    /// With this flag active no prompt will be shown
    /// and no confirmation will be asked.
    // TODO: Rephrase this and the `batch` flags of the
    // other commands in the present tense.
    #[arg(long, short, default_value_t = false)]
    batch: bool,
}

/// Run the `keys` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    keys_matches: &ArgMatches,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let subcommand =
        KeysSubcommand::from_arg_matches(keys_matches).expect("Could not parse keys subcommand");
    let rt = runtime.clone();
    let client_builder = TorClient::with_runtime(runtime).config(client_config.clone());

    match subcommand {
        KeysSubcommand::List(args) => run_list_keys(&args, &client_builder.create_inert()?),
        KeysSubcommand::ListKeystores => run_list_keystores(&client_builder.create_inert()?),
        KeysSubcommand::CheckIntegrity(args) => {
            run_check_integrity(&args, &client_builder, &rt, config, client_config)
        }
    }
}

/// Print information about a keystore entry.
fn display_entry(entry: &KeystoreEntry, keymgr: &KeyMgr) {
    match entry.key_path() {
        KeyPath::Arti(_) => display_arti_entry(entry, keymgr),
        KeyPath::CTor(path) => display_ctor_entry(entry, path),
        unrecognized => {
            eprintln!(
                "WARNING: unexpected `tor_keymgr::KeyPath` variant encountered: {:?}",
                unrecognized
            );
        }
    }
    println!("\n {}", "-".repeat(LINE_LEN));
}

/// Print information about an unrecognized keystore entry.
fn display_unrecognized_entry(entry: &UnrecognizedEntryError) {
    let raw_entry = entry.entry();
    println!(" Unrecognized entry");
    #[allow(clippy::single_match)]
    match raw_entry.raw_id() {
        tor_keymgr::RawEntryId::Path(p) => {
            println!(" Keystore ID: {}", raw_entry.keystore_id());
            println!(" Location: {}", p.to_string_lossy());
            println!(" Error: {}", entry.error());
        }
        // NOTE: For the time being Arti only supports
        // on-disk keystores, but more supported medium
        // will be added.
        other => {
            panic!("Unhandled enum variant: {:?}", other);
        }
    }
    println!("\n {}\n", "-".repeat(LINE_LEN));
}

/// Run the `keys list` subcommand.
fn run_list_keys(args: &ListArgs, client: &InertTorClient) -> Result<()> {
    let keymgr = client.keymgr()?;
    // TODO: in the future we could group entries by their type
    // (recognized, unrecognized and unrecognized path).
    // That way we don't need to print "Unrecognized path",
    // "Unrecognized" entry etc. for each unrecognized entry.
    match &args.keystore_id {
        Some(s) => {
            let id = KeystoreId::from_str(s)?;
            let empty_err_msg = format!("Currently there are no entries in the keystore {}.", s);
            display_keystore_entries(
                &keymgr.list_by_id(&id)?,
                keymgr,
                "Keystore entries",
                &empty_err_msg,
            );
        }
        None => {
            display_keystore_entries(
                &keymgr.list()?,
                keymgr,
                "Keystore entries",
                "Currently there are no entries in any of the keystores.",
            );
        }
    }
    Ok(())
}

/// Run `keys list-keystores` subcommand.
fn run_list_keystores(client: &InertTorClient) -> Result<()> {
    let keymgr = client.keymgr()?;
    let entries = keymgr.list_keystores();

    if entries.is_empty() {
        println!("Currently there are no keystores available.");
    } else {
        println!(" Keystores:\n");
        for entry in entries {
            // TODO: We need something similar to [`KeyPathInfo`](tor_keymgr::KeyPathInfo)
            // for `KeystoreId`
            println!(" - {:?}\n", entry.as_ref());
        }
    }

    Ok(())
}

/// Run `keys check-integrity` subcommand.
fn run_check_integrity<R: Runtime>(
    args: &CheckIntegrityArgs,
    builder: &TorClientBuilder<R>,
    runtime: &R,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let inert_client = builder.create_inert()?;
    let client = runtime.reenter_block_on(builder.create_bootstrapped())?;

    // TODO: `TorClient` should have a `KeyMgr` accessor.
    let keymgr = inert_client.keymgr()?;

    let entries = match &args.keystore_id {
        Some(id) => keymgr.list_by_id(id)?,
        None => keymgr.list()?,
    };

    let mut invalid_entries = entries
        .into_iter()
        .filter(|entry| match entry {
            Ok(e) => keymgr.validate_entry_integrity(e).is_err(),
            Err(_) => true,
        })
        .collect::<Vec<_>>();

    display_invalid_keystore_entries(&invalid_entries, keymgr, "Invalid keystore entries");

    cfg_if::cfg_if! {
        if #[cfg(feature = "onion-service-service")] {
            let services = create_all_services(config, client_config)?;
            let expired_entries = get_expired_keys(&services, &client)?;
            display_invalid_keystore_entries(
                &expired_entries,
                keymgr,
                "Expired keystore entries"
            );

            invalid_entries.extend(expired_entries)
        }
    }

    if invalid_entries.is_empty() {
        println!("OK.");
        return Ok(());
    }

    maybe_remove_invalid_entries(args, &invalid_entries, keymgr)?;

    Ok(())
}

/// Helper function of `run_check_integrity`, reduces cognitive complexity.
// TODO: code duplication with `display_keystore_entries`.
fn display_invalid_keystore_entries(
    entries: &[KeystoreEntryResult<KeystoreEntry>],
    keymgr: &KeyMgr,
    header: &str,
) {
    if entries.is_empty() {
        return;
    }
    println!(" ===== {} =====\n\n", header);
    for entry in entries {
        match entry {
            Ok(entry) => {
                display_entry(entry, keymgr);
            }
            Err(entry) => {
                display_unrecognized_entry(entry);
            }
        }
    }
}

/// Helper function of `run_list_keys`, reduces cognitive complexity.
fn display_keystore_entries(
    entries: &[KeystoreEntryResult<KeystoreEntry>],
    keymgr: &KeyMgr,
    header: &str,
    empty_err_msg: &str,
) {
    if entries.is_empty() {
        println!("{empty_err_msg}");
        return;
    }
    println!(" ===== {} =====\n\n", header);
    for entry in entries {
        match entry {
            Ok(entry) => {
                display_entry(entry, keymgr);
            }
            Err(entry) => {
                display_unrecognized_entry(entry);
            }
        }
    }
}

/// Displays an Arti native keystore entry.
fn display_arti_entry(entry: &KeystoreEntry, keymgr: &KeyMgr) {
    let raw_entry = entry.raw_entry();
    match keymgr.describe(entry.key_path()) {
        Ok(e) => {
            println!(" Keystore ID: {}", entry.keystore_id());
            println!(" Role: {}", e.role());
            println!(" Summary: {}", e.summary());
            println!(" KeystoreItemType: {:?}", entry.key_type());
            println!(" Location: {}", raw_entry.raw_id());
            let extra_info = e.extra_info();
            println!(" Extra info:");
            for (key, value) in extra_info {
                println!(" - {key}: {value}");
            }
        }
        Err(_) => {
            println!(" Unrecognized path {}", raw_entry.raw_id());
        }
    }
}

/// Displays a CTor keystore entry.
///
/// This function outputs the details of a CTor keystore entry, distinguishing
/// between client and service keys based on [`CTorPath`].
fn display_ctor_entry(entry: &KeystoreEntry, path: &CTorPath) {
    let raw_entry = entry.raw_entry();
    match path {
        CTorPath::ClientHsDescEncKey(id) => {
            println!(" CTor client key");
            println!(" Hidden service ID: {}", id.display_unredacted());
        }
        CTorPath::Service { nickname, path: _ } => {
            println!(" CTor service key");
            println!(" Hidden service nickname: {}", nickname);
        }
        unrecognized => {
            eprintln!(
                "WARNING: unexpected `tor_keymgr::CTorPath` variant encountered: {:?}",
                unrecognized
            );
            return;
        }
    }
    println!(" Keystore ID: {}", entry.keystore_id());
    println!(" KeystoreItemType: {:?}", entry.key_type());
    println!(" Location: {}", raw_entry.raw_id());
}

/// Helper function for `run_check_integrity`.
///
/// Creates an [`OnionService`] for each configured hidden service.
#[cfg(feature = "onion-service-service")]
fn create_all_services(
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<Vec<OnionService>> {
    let mut services = Vec::new();
    for (_, cfg) in config.onion_services.iter() {
        services.push(
            TorClient::<tor_rtcompat::PreferredRuntime>::create_onion_service(
                client_config,
                cfg.svc_cfg.clone(),
            )?,
        );
    }
    Ok(services)
}

/// Helper function for `run_check_integrity`.
///
/// Gathers all expired keys from the provided hidden services.
#[cfg(feature = "onion-service-service")]
fn get_expired_keys<'a, R: Runtime>(
    services: &'a Vec<OnionService>,
    client: &TorClient<R>,
) -> Result<Vec<KeystoreEntryResult<KeystoreEntry<'a>>>> {
    let netdir = client.dirmgr().timely_netdir()?;

    let mut expired_keys = Vec::new();
    for service in services {
        expired_keys.append(
            &mut service
                .list_expired_keys(&netdir)?
                .into_iter()
                .map(Ok)
                .collect(),
        );
    }
    Ok(expired_keys)
}

/// Helper function for `run_check_integrity`.
///
/// Removes invalid keystore entries.
/// Prints an error message if one or more entries fail to be removed.
/// Returns `Err` if an I/O error occurs.
fn maybe_remove_invalid_entries(
    args: &CheckIntegrityArgs,
    entries: &[KeystoreEntryResult<KeystoreEntry<'_>>],
    keymgr: &KeyMgr,
) -> Result<()> {
    if entries.is_empty() || !args.sweep {
        return Ok(());
    }

    let should_remove = args.batch || prompt("Remove all invalid entries?")?;

    if !should_remove {
        return Ok(());
    }

    for res in entries.iter() {
        let raw_entry = match res {
            Ok(e) => &e.raw_entry(),
            Err(e) => e.entry().deref(),
        };

        if keymgr
            .remove_unchecked(&raw_entry.raw_id().to_string(), raw_entry.keystore_id())
            .is_err()
        {
            eprintln!("Failed to remove entry at location: {}", raw_entry.raw_id());
        }
    }

    Ok(())
}
