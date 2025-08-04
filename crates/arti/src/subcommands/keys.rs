//! The `keys` subcommand.

use std::str::FromStr;

use anyhow::Result;

use arti_client::{InertTorClient, TorClient, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use safelog::DisplayRedacted;
use tor_keymgr::{
    CTorPath, KeyMgr, KeyPath, KeystoreEntry, KeystoreEntryResult, KeystoreId,
    UnrecognizedEntryError,
};
use tor_rtcompat::Runtime;

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
}

/// The arguments of the [`List`](KeysSubcommand::List) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct ListArgs {
    /// Identifier of the keystore.
    /// If omitted, keys and certificates
    /// from all the keystores will be returned.
    #[arg(short, long)]
    keystore_id: Option<String>,
}

/// Run the `keys` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    keys_matches: &ArgMatches,
    config: &TorClientConfig,
) -> Result<()> {
    let subcommand =
        KeysSubcommand::from_arg_matches(keys_matches).expect("Could not parse keys subcommand");
    let client = TorClient::with_runtime(runtime)
        .config(config.clone())
        .create_inert()?;

    match subcommand {
        KeysSubcommand::List(args) => run_list_keys(&args, &client),
        KeysSubcommand::ListKeystores => run_list_keystores(&client),
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

    println!("\n {}\n", "-".repeat(LINE_LEN));
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
            display_keystore_entries(keymgr.list_by_id(&id)?, keymgr, &empty_err_msg);
        }
        None => {
            let entries = keymgr.list()?;
            display_keystore_entries(
                entries,
                keymgr,
                "Currently there are no entries in any of the keystores.",
            );
        }
    }
    Ok(())
}

/// Run `key list-keystores` subcommand.
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

/// Helper function of `run_list_keys`, reduces cognitive complexity.
fn display_keystore_entries(
    entries: Vec<KeystoreEntryResult<KeystoreEntry>>,
    keymgr: &KeyMgr,
    empty_err_msg: &str,
) {
    if entries.is_empty() {
        println!("{empty_err_msg}");
    }
    println!(" ===== Keystore entries =====\n\n");
    for entry in entries {
        match entry {
            Ok(entry) => {
                display_entry(&entry, keymgr);
            }
            Err(entry) => {
                display_unrecognized_entry(&entry);
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
