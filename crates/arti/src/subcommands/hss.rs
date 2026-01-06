//! The `hss` subcommand.

#[cfg(feature = "onion-service-cli-extra")]
use {
    crate::subcommands::prompt,
    std::str::FromStr,
    tor_hscrypto::pk::HsIdKeypair,
    tor_hsservice::HsIdKeypairSpecifier,
    tor_keymgr::{KeyMgr, KeystoreEntry, KeystoreId},
};

use anyhow::anyhow;
use arti_client::{InertTorClient, TorClientConfig};
use clap::{ArgMatches, Args, FromArgMatches, Parser, Subcommand, ValueEnum};
use safelog::DisplayRedacted;
use tor_hsservice::{HsId, HsNickname, OnionService};
use tor_rtcompat::Runtime;

use crate::{ArtiConfig, Result, TorClient};

/// The hss subcommands the arti CLI will be augmented with.
#[derive(Parser, Debug)]
pub(crate) enum HssSubcommands {
    /// Run state management commands for an Arti hidden service.
    Hss(Hss),
}

/// The `hss` subcommand and args.
#[derive(Debug, Parser)]
pub(crate) struct Hss {
    /// Arguments shared by all hss subcommands.
    #[command(flatten)]
    common: CommonArgs,

    /// The `hss` subcommand to run.
    #[command(subcommand)]
    command: HssSubcommand,
}

/// The `hss` subcommand.
#[derive(Subcommand, Debug, Clone)]
pub(crate) enum HssSubcommand {
    /// Print the .onion address of a hidden service
    OnionAddress(OnionAddressArgs),

    /// (Deprecated) Print the .onion address of a hidden service
    #[command(hide = true)] // This hides the command from the help message
    OnionName(OnionAddressArgs),

    /// Migrate the identity key of a specified hidden service from a
    /// CTor-compatible keystore to the native Arti keystore.
    ///
    /// If the service with the specified nickname
    /// already has some keys in the Arti keystore,
    /// they will be deleted as part of the migration,
    /// its identity key being replaced with the identity
    /// key obtained from the C Tor keystore.
    ///
    /// Authorized restricted discovery keys (authorized_clients)
    /// will not be migrated as part of this process.
    ///
    /// Important: This tool should only be used when no other process
    /// is accessing either keystore.
    #[cfg(feature = "onion-service-cli-extra")]
    #[command(name = "ctor-migrate")]
    CTorMigrate(CTorMigrateArgs),
}

/// The arguments of the [`OnionAddress`](HssSubcommand::OnionAddress) subcommand.
#[derive(Debug, Clone, Args)]
pub(crate) struct OnionAddressArgs {
    /// Whether to generate the key if it is missing
    #[arg(
        long,
        default_value_t = GenerateKey::No,
        value_enum
    )]
    generate: GenerateKey,
}

/// The arguments of the [`CTorMigrate`](HssSubcommand::CTorMigrate) subcommand.
#[derive(Debug, Clone, Args)]
#[cfg(feature = "onion-service-cli-extra")]
pub(crate) struct CTorMigrateArgs {
    /// With this flag active no prompt will be shown
    /// and no confirmation will be asked
    #[arg(long, short, default_value_t = false)]
    batch: bool,
}

/// Whether to generate the key if missing.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
enum GenerateKey {
    /// Do not generate the key.
    #[default]
    No,
    /// Generate the key if it's missing.
    IfNeeded,
}

/// A type of key
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum KeyType {
    /// The identity key of the service
    OnionAddress,
}

/// The arguments shared by all [`HssSubcommand`]s.
#[derive(Debug, Clone, Args)]
pub(crate) struct CommonArgs {
    /// The nickname of the service
    #[arg(short, long)]
    nickname: HsNickname,
}

/// Run the `hss` subcommand.
pub(crate) fn run<R: Runtime>(
    runtime: R,
    hss_matches: &ArgMatches,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let hss = Hss::from_arg_matches(hss_matches).expect("Could not parse hss subcommand");

    match hss.command {
        HssSubcommand::OnionAddress(args) => {
            run_onion_address(&hss.common, &args, config, client_config)
        }
        #[cfg(feature = "onion-service-cli-extra")]
        HssSubcommand::CTorMigrate(args) => run_migrate(runtime, client_config, &args, &hss.common),
        HssSubcommand::OnionName(args) => {
            eprintln!(
                "warning: using deprecated command 'onion-name', (hint: use 'onion-address' instead)"
            );
            run_onion_address(&hss.common, &args, config, client_config)
        }
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
fn display_onion_address(nickname: &HsNickname, hsid: Option<HsId>) -> Result<()> {
    // TODO: instead of the printlns here, we should have a formatter type that
    // decides how to display the output
    if let Some(onion) = hsid {
        println!("{}", onion.display_unredacted());
    } else {
        return Err(anyhow!(
            "Service {nickname} does not exist, or does not have an K_hsid yet"
        ));
    }

    Ok(())
}

/// Run the `hss onion-address` subcommand.
fn onion_address(
    args: &CommonArgs,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let onion_svc = create_svc(&args.nickname, config, client_config)?;
    let hsid = onion_svc.onion_address();
    display_onion_address(&args.nickname, hsid)?;

    Ok(())
}

/// Run the `hss onion-address` subcommand.
fn get_or_generate_onion_address(
    args: &CommonArgs,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    let svc = create_svc(&args.nickname, config, client_config)?;
    let hsid = svc.onion_address();
    match hsid {
        Some(hsid) => display_onion_address(&args.nickname, Some(hsid)),
        None => {
            let selector = Default::default();
            let hsid = svc.generate_identity_key(selector)?;
            display_onion_address(&args.nickname, Some(hsid))
        }
    }
}

/// Run the `hss onion-address` subcommand.
fn run_onion_address(
    args: &CommonArgs,
    get_key_args: &OnionAddressArgs,
    config: &ArtiConfig,
    client_config: &TorClientConfig,
) -> Result<()> {
    match get_key_args.generate {
        GenerateKey::No => onion_address(args, config, client_config),
        GenerateKey::IfNeeded => get_or_generate_onion_address(args, config, client_config),
    }
}

/// Run the `hss ctor-migrate` subcommand.
#[cfg(feature = "onion-service-cli-extra")]
fn run_migrate<R: Runtime>(
    runtime: R,
    client_config: &TorClientConfig,
    migrate_args: &CTorMigrateArgs,
    args: &CommonArgs,
) -> Result<()> {
    let ctor_keystore_id = find_ctor_keystore(client_config, args)?;

    let inert_client = TorClient::with_runtime(runtime)
        .config(client_config.clone())
        .create_inert()?;

    migrate_ctor_keys(migrate_args, args, &inert_client, &ctor_keystore_id)
}

/// Migrate the keys of the specified C Tor service to the Arti keystore.
///
/// Performs key migration for the service identified by the [`HsNickname`] provided
/// via `--nickname`, copying keys from the CTor keystore configured for the service
/// to the default Arti native keystore.
///
/// If the service with the specified nickname had some keys in the Arti keystore
/// prior to the migration, those keys will be removed.
///
/// If `args.batch` is false, the user will be prompted for the deletion of
/// the existing entries from the original Arti keystore.
#[cfg(feature = "onion-service-cli-extra")]
fn migrate_ctor_keys(
    migrate_args: &CTorMigrateArgs,
    args: &CommonArgs,
    client: &InertTorClient,
    ctor_keystore_id: &KeystoreId,
) -> Result<()> {
    let keymgr = client.keymgr()?;
    let nickname = &args.nickname;
    let id_key_spec = HsIdKeypairSpecifier::new(nickname.clone());
    // If no CTor identity key is found the migration can't continue.
    let ctor_id_key = keymgr
        .get_from::<HsIdKeypair>(&id_key_spec, ctor_keystore_id)?
        .ok_or_else(|| anyhow!("No identity key found in the provided C Tor keystore."))?;

    let arti_pat = tor_keymgr::KeyPathPattern::Arti(format!("hss/{}/**/*", nickname));
    let arti_entries = keymgr.list_matching(&arti_pat)?;

    // NOTE: Currently, there can only be one `ArtiNativeKeystore` with a hard-coded
    // `KeystoreId`, which is used as the `primary_keystore`.
    let arti_keystore_id = KeystoreId::from_str("arti")
        .map_err(|_| anyhow!("Default arti keystore ID is not valid?!"))?;

    let is_empty = arti_entries.is_empty();

    if !is_empty {
        let arti_id_entry_opt = arti_entries.iter().find(|k| {
            // TODO: this relies on the stringly-typed info.role()
            // to find the identity key. We should consider exporting
            // HsIdKeypairSpecifierPattern from tor-hsservice,
            // and using it here.
            keymgr
                .describe(k.key_path())
                .is_some_and(|info| info.role() == "ks_hs_id")
        });
        if let Some(arti_id_entry) = arti_id_entry_opt {
            let arti_id_key: HsIdKeypair = match keymgr.get_entry(arti_id_entry)? {
                Some(aik) => aik,
                None => {
                    return Err(anyhow!(
                        "Identity key disappeared during migration (is another process using the keystore?)"
                    ));
                }
            };
            if arti_id_key.as_ref().public() == ctor_id_key.as_ref().public() {
                return Err(anyhow!("Service {nickname} was already migrated."));
            }
        }
    }

    if is_empty || migrate_args.batch || prompt(&build_prompt(&arti_entries))? {
        remove_arti_entries(keymgr, &arti_entries);
        keymgr.insert(ctor_id_key, &id_key_spec, (&arti_keystore_id).into(), true)?;
    } else {
        println!("Aborted.");
    }

    Ok(())
}

/// Checks if the service identified by the [`HsNickname`] provided by the user
/// is configured with any of the recognized CTor keystores.
///
/// Returns different errors messages to indicate specific failure conditions if the
/// procedure cannot continue, `Ok(())` otherwise.
#[cfg(feature = "onion-service-cli-extra")]
fn find_ctor_keystore(client_config: &TorClientConfig, args: &CommonArgs) -> Result<KeystoreId> {
    let keystore_config = client_config.keystore();
    let ctor_services = keystore_config.ctor().services();
    if ctor_services.is_empty() {
        return Err(anyhow!("No CTor keystore are configured."));
    }

    let Some((_, service_config)) = ctor_services
        .iter()
        .find(|(hs_nick, _)| *hs_nick == &args.nickname)
    else {
        return Err(anyhow!(
            "The service identified using `--nickname {}` is not configured with any recognized CTor keystore.",
            &args.nickname,
        ));
    };

    Ok(service_config.id().clone())
}

/// Helper function for `migrate_ctor_keys`.
/// Removes all the Arti keystore entries provided.
/// Prints an error for each failed removal attempt.
#[cfg(feature = "onion-service-cli-extra")]
fn remove_arti_entries(keymgr: &KeyMgr, arti_entries: &Vec<KeystoreEntry<'_>>) {
    for entry in arti_entries {
        if let Err(e) = keymgr.remove_entry(entry) {
            eprintln!("Failed to remove entry {} ({e})", entry.key_path(),);
        }
    }
}

/// Helper function for `migrate_ctor_keys`.
/// Builds a prompt that will be passed to the [`prompt`] function.
#[cfg(feature = "onion-service-cli-extra")]
fn build_prompt(entries: &Vec<KeystoreEntry<'_>>) -> String {
    let mut p = "WARNING: the following keys will be deleted\n".to_string();
    for k in entries.iter() {
        p.push('\t');
        p.push_str(&k.key_path().to_string());
        p.push('\n');
    }
    p.push('\n');
    p.push_str("Proceed anyway?");
    p
}
