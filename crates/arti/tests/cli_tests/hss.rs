//! Integration test suite for Arti hss.
//!
//! Testing certain `hss` subcommands involves deleting and creating files, which requires the use
//! of a temporary directory. Due to this and other considerations, the `assert_cmd` crate is used to
//! test these subcommands instead of the preferred `trycmd` crate (see [README](../README.md)).
//!
//! ## Note on the test data
//!
//! Test data for this suite is stored in the `hss-extra/hss.in/local` directory. The structure is as follows:
//!
//! ```
//! local
//! ├── ctor-keystore
//! │   ├── hostname
//! │   ├── hs_ed25519_public_key
//! │   └── hs_ed25519_secret_key
//! └── state-dir
//!     └── keystore
//!         ├── hss
//!         │   └── allium-cepa
//!         │       ├── ipts
//!         │       │   ├── k_hss_ntor+2a6054c3432b880b76cf379f66daf1a34c88693efed5e85bd90507a1fea231d7.x25519_private
//!         │       │   ├── k_hss_ntor+84a3a863484ff521081ee8e6e48a6129d0c83bef89fe294a5dda6f782b43dec8.x25519_private
//!         │       │   ├── k_hss_ntor+ce8514e2fe016e4705b064f2226a7628f4226e9a15d28607112e4eac3b3a012f.x25519_private
//!         │       │   ├── k_sid+2a6054c3432b880b76cf379f66daf1a34c88693efed5e85bd90507a1fea231d7.ed25519_private
//!         │       │   ├── k_sid+84a3a863484ff521081ee8e6e48a6129d0c83bef89fe294a5dda6f782b43dec8.ed25519_private
//!         │       │   └── k_sid+ce8514e2fe016e4705b064f2226a7628f4226e9a15d28607112e4eac3b3a012f.ed25519_private
//!         │       ├── ks_hs_blind_id+20326_1440_43200.ed25519_expanded_private
//!         │       ├── ks_hs_blind_id+20327_1440_43200.ed25519_expanded_private
//!         │       ├── ks_hs_id.ed25519_expanded_private
//!         │       └── unrecognized-entry
//!         ├── unrecognized-path
//!         └── unrecognized-path-dir
//!             └── unrecognized-path
//! ```
//!
//! Where:
//!
//! - `local/ctor-keystore` is a fully populated CTor keystore.
//! - `local/state-dir` is an example Arti state directory, partially populated.
//!   This directory typically corresponds to `~/.local/share/arti`. For the
//!   purposes of testing, it contains only `local/state-dir/keystore`.
//! - `local/state-dir/hss/allium-cepa` is a partially populated keystore for the hidden service
//!   `allium-cepa`. It includes a long-term identity key and several derived keys.
//!   For testing purposes, all derived keys may be empty files. Their presence ensures
//!   they are correctly removed during migration.
//! - `unrecognized-path` and `unrecognized-entry` are included to verify that
//!   the migration process does not remove them. Form more information about unrecognized entries
//!   and paths see [keys list documention](../../../../doc/keys.md).

use crate::hss::util::{
    ARTI_KEYSTORE_POPULATION, CFG_CTOR_PATH, CFG_PATH, CTorMigrateCmd, EXPECTED_ID_KEY_PATH,
    EXPECTED_UNRECOGNIZED_KEYSTORE_ENTRY, HSS_DIR_PATH, IPTS_DIR_PATH, KEYSTORE_DIR_PATH,
    OnionAddressCmdBuilder, SERVICE_DIR_PATH, UNRECOGNIZED_PATH_1, UNRECOGNIZED_PATH_2,
    UNRECOGNIZED_PATH_2_DIR,
};

mod util;

#[test]
fn migration_succeeds_with_empty_arti_keystore() {
    let cmd = CTorMigrateCmd::new();
    assert!(cmd.is_state_dir_empty());
    assert!(cmd.output().unwrap().status.success());
    assert!(cmd.state_dir_contains_only(&[
        EXPECTED_ID_KEY_PATH,
        KEYSTORE_DIR_PATH,
        HSS_DIR_PATH,
        SERVICE_DIR_PATH
    ]));
}

#[test]
fn migration_succeeds_with_full_arti_keystore_and_batch_enabled() {
    let migrate_cmd = CTorMigrateCmd::new();
    assert!(migrate_cmd.is_state_dir_empty());

    // Since the state directory is currently empty and the configuration provides
    // a functional CTor keystore, `ctor_keystore_onion_address` holds the onion
    // address associated with the CTor keystore's identity key.
    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_CTOR_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let ctor_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    migrate_cmd.populate_state_dir();

    // With the state directory populated and the configuration (lacking a CTor keystore) overridden by a
    // command-line flag that provides a functional, fully populated Arti native keystore, the resulting
    // onion address is derived from the Arti keystore's identity key.
    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let arti_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    // The two onion-addresses are different.
    assert_ne!(ctor_keystore_onion_address, arti_keystore_onion_address);

    assert!(migrate_cmd.state_dir_contains_only(ARTI_KEYSTORE_POPULATION));
    assert!(migrate_cmd.output().unwrap().status.success());
    // `ctor-migrate` substitutes the long-term ID key, removes all other recognized entries,
    // and leaves unrecognized entries and paths unchanged.
    assert!(migrate_cmd.state_dir_contains_only(&[
        EXPECTED_ID_KEY_PATH,
        KEYSTORE_DIR_PATH,
        HSS_DIR_PATH,
        SERVICE_DIR_PATH,
        EXPECTED_UNRECOGNIZED_KEYSTORE_ENTRY,
        IPTS_DIR_PATH,
        UNRECOGNIZED_PATH_1,
        UNRECOGNIZED_PATH_2_DIR,
        UNRECOGNIZED_PATH_2
    ]));

    // The migration has completed: the CTor identity key has been converted into an
    // Arti native identity key. Since no CTor keystore is provided in the config at
    // `CFG_PATH`, the resulting onion address is obtained from the Arti native
    // keystore, which now holds the same identity key as the original CTor keystore.
    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let arti_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    // The onion addresses are now the same because they are derived from the same
    // identity key, which exists in different formats across the two keystores.
    assert_eq!(ctor_keystore_onion_address, arti_keystore_onion_address)
}

#[test]
fn ctor_migrate_is_idempotent() {
    let cmd = CTorMigrateCmd::new();
    assert!(cmd.is_state_dir_empty());
    assert!(cmd.output().unwrap().status.success());
    assert!(cmd.state_dir_contains_only(&[
        EXPECTED_ID_KEY_PATH,
        KEYSTORE_DIR_PATH,
        HSS_DIR_PATH,
        SERVICE_DIR_PATH
    ]));
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(cmd.output().unwrap().stderr).unwrap();
    assert!(error.contains("error: Service allium-cepa was already migrated."))
}

#[test]
fn ctor_migrate_fails_when_applied_to_unregistered_service() {
    let mut cmd = CTorMigrateCmd::new();
    assert!(cmd.is_state_dir_empty());
    cmd.set_nickname("unregistered".to_string());
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(cmd.output().unwrap().stderr).unwrap();
    assert!(error.contains("error: The service identified using `--nickname unregistered` is not configured with any recognized CTor keystore."))
}

#[test]
fn ctor_migrate_fails_without_registered_ctor_keystore() {
    let mut cmd = CTorMigrateCmd::new();
    assert!(cmd.is_state_dir_empty());
    cmd.set_config(CFG_PATH.to_string());
    let output = cmd.output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(cmd.output().unwrap().stderr).unwrap();
    assert!(error.contains("error: No CTor keystore are configured."))
}

#[test]
fn ctor_migrate_aborts_correctly_without_batch_flag() {
    let mut migrate_cmd = CTorMigrateCmd::new();
    assert!(migrate_cmd.is_state_dir_empty());

    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_CTOR_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let ctor_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    migrate_cmd.populate_state_dir();

    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let arti_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    assert_ne!(ctor_keystore_onion_address, arti_keystore_onion_address);

    migrate_cmd.set_stdin("no".to_string());

    assert!(migrate_cmd.state_dir_contains_only(ARTI_KEYSTORE_POPULATION));
    let output = migrate_cmd.output().unwrap();
    assert!(output.status.success());

    // The migration didn't happen, old files haven't been removed.
    assert!(migrate_cmd.state_dir_contains_only(ARTI_KEYSTORE_POPULATION));

    let onion_address_cmd = OnionAddressCmdBuilder::default()
        .config_path(CFG_PATH.to_string())
        .state_directory(Some(
            migrate_cmd.state_dir_path().to_string_lossy().to_string(),
        ))
        .build()
        .unwrap();
    let arti_keystore_onion_address =
        String::from_utf8(onion_address_cmd.output().unwrap().stdout).unwrap();

    // The identity keys in the Arti and CTor keystores differ, resulting in
    // different onion addresses.
    assert_ne!(ctor_keystore_onion_address, arti_keystore_onion_address);

    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Aborted.")
    )
}
