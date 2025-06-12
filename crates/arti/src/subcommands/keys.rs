//! The `key` subcommand.

use std::str::FromStr;

use anyhow::Result;

use arti_client::{InertTorClient, TorClient, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand};
use tor_key_forge::KeystoreItemType;
use tor_keymgr::{KeyMgr, KeyPath, KeystoreEntryResult, KeystoreId, UnrecognizedEntryError};
use tor_rtcompat::Runtime;

/// Length of a line, used for formatting
// TODO: use COLUMNS instead of an arbitrary LINE_LEN
const LINE_LEN: usize = 80;

/// The `keys` subcommands the arti CLI will be augmented with.
#[derive(Debug, Parser)]
pub(crate) enum KeysSubcommands {
    /// Return the identity key for the specified service.
    #[command(subcommand)]
    Keys(KeysSubcommand),
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum KeysSubcommand {
    /// List keys and certificates.
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
fn display_entry(path: &KeyPath, ty: &KeystoreItemType, keymgr: &KeyMgr) {
    match keymgr.describe(path) {
        Ok(entry) => {
            println!(" Role: {}", entry.role());
            println!(" Summary: {}", entry.summary());
            println!(" KeystoreItemType: {:?}", ty);
            let extra_info = entry.extra_info();
            println!(" Extra info:");
            for (key, value) in extra_info {
                println!(" - {key}: {value}");
            }
        }
        Err(err) => {
            println!(" {}", err);
        }
    }
    println!("\n {}\n", "-".repeat(LINE_LEN));
}

/// Print information about an unrecognized keystore entry.
fn display_unrecognized_entry(entry: &UnrecognizedEntryError) {
    println!(" Unrecognized entry");
    #[allow(clippy::single_match)]
    match entry.entry() {
        tor_keymgr::UnrecognizedEntryId::Path(p) => {
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
            let entries = keymgr.list_by_id(&id)?.into_iter().map(|res| match res {
                Ok((path, ty)) => Ok((path, ty, &id)),
                Err(unrecognized_entry) => Err(unrecognized_entry),
            });
            let empty_err_msg = format!("Currently there are no entries in the keystore {}.", s);
            display_keystore_entries(entries, keymgr, &empty_err_msg);
        }
        None => {
            let entries = keymgr.list()?.into_iter().map(|res| match res {
                Ok(entry) => Ok((
                    entry.key_path().to_owned(),
                    entry.key_type().to_owned(),
                    entry.keystore_id(),
                )),
                Err(unrecognized_entry) => Err(unrecognized_entry),
            });
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
fn display_keystore_entries<'a>(
    entries: impl std::iter::ExactSizeIterator<
        Item = KeystoreEntryResult<(KeyPath, KeystoreItemType, &'a KeystoreId)>,
    >,
    keymgr: &KeyMgr,
    empty_err_msg: &str,
) {
    if entries.len() == 0 {
        println!("{}", empty_err_msg);
        return;
    }
    println!(" ===== Keytore entries =====\n\n");
    for entry in entries {
        match entry {
            Ok((path, ty, keystore_id)) => {
                println!(" Keystore ID: {}", keystore_id.as_ref());
                display_entry(&path, &ty, keymgr);
            }
            Err(entry) => {
                display_unrecognized_entry(&entry);
            }
        }
    }
}
