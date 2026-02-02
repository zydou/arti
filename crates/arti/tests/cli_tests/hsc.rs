mod ctor_migrate_util;
mod key_util;

use crate::hsc::ctor_migrate_util::{
    CTOR_KEYSTORE_ID, CTOR_KEYSTORE1_PATH, CTOR_KEYSTORE2_PATH, CTOR_KEYSTORE3_PATH,
    CTOR_KEYSTORE4_PATH, CTOR_KEYSTORE5_PATH, CTorMigrateCmd, ONION_ADDR_SERVICE_1,
    ONION_ADDR_SERVICE_2,
};

use crate::hsc::key_util::{ADDR_LEN, ArtiHscKeyCmd, ONION_ADDR, build_hsc_key_cmd};

#[test]
fn gen_key() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let state_dir = state_dir.path();
    let mut cmd = build_hsc_key_cmd(ArtiHscKeyCmd::Get, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("descriptor:x25519:")
    );

    let keystore_path = state_dir
        .join("keystore/client")
        .join(&ONION_ADDR[..ADDR_LEN]);
    // Assert new private key has been generated
    assert_eq!(
        keystore_path
            .read_dir()
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .file_name(),
        "ks_hsc_desc_enc.x25519_private"
    );
}

#[test]
fn generate_then_rotate() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let state_dir = state_dir.path();
    let mut cmd = build_hsc_key_cmd(ArtiHscKeyCmd::Get, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let descriptor = String::from_utf8(output.stdout).unwrap();
    assert!(descriptor.contains("descriptor:x25519:"));

    let mut cmd = build_hsc_key_cmd(ArtiHscKeyCmd::Rotate, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let rotated_descriptor = String::from_utf8(output.stdout).unwrap();
    assert!(rotated_descriptor.contains("descriptor:x25519:"));

    // Assert key has been rotated
    assert_ne!(descriptor, rotated_descriptor);

    let keystore_path = state_dir
        .join("keystore/client")
        .join(&ONION_ADDR[..ADDR_LEN]);
    // Assert new private key has been generated
    assert_eq!(
        keystore_path
            .read_dir()
            .unwrap()
            .flatten()
            .next()
            .unwrap()
            .file_name(),
        "ks_hsc_desc_enc.x25519_private"
    );
}

#[test]
fn generate_then_remove() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let state_dir = state_dir.path();
    let mut cmd = build_hsc_key_cmd(ArtiHscKeyCmd::Get, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("descriptor:x25519:")
    );

    let mut cmd = build_hsc_key_cmd(ArtiHscKeyCmd::Remove, state_dir);
    cmd.write_stdin(ONION_ADDR);
    cmd.assert().success();

    let keystore_path = state_dir
        .join("keystore/client")
        .join(&ONION_ADDR[..ADDR_LEN]);
    let entries = keystore_path.read_dir().unwrap().flatten();
    // Assert key has been removed
    assert_eq!(entries.count(), 0);
}

/// Tests whether `ctor-migrate` can successfully migrate a valid C Tor client keystore
/// to an Arti keystore that does not already have discovery keys for the services
/// the C Tor client is configured with.
#[test]
fn simple_ctor_migration() {
    let migrate_cmd = CTorMigrateCmd::new();

    let assert_key_is_missing = |svc: &str| {
        let err = migrate_cmd.keystore_contains_client_key(svc).unwrap_err();
        assert!(err.to_string().contains(
          "arti: error: Service discovery key not found. Rerun with --generate=if-needed to generate a new service discovery keypair"
       ));
    };

    // The client keystore doesn't have keys for either of the two services before the migration
    assert_key_is_missing(ONION_ADDR_SERVICE_1);
    assert_key_is_missing(ONION_ADDR_SERVICE_2);

    let output = migrate_cmd.output(CTOR_KEYSTORE1_PATH).unwrap();
    assert!(output.status.success());
    assert!(
        migrate_cmd
            .keystore_contains_client_key(ONION_ADDR_SERVICE_1)
            .is_ok()
    );
    assert!(
        migrate_cmd
            .keystore_contains_client_key(ONION_ADDR_SERVICE_2)
            .is_ok()
    );
}

/// Tests whether `ctor-migrate` fails if multiple client keys for the same service are present in
/// the C Tor keystore. A C Tor keystore must not contain multiple client keys for the same
/// service.
#[test]
fn migrate_duplicate_ctor_entries() {
    let migrate_cmd = CTorMigrateCmd::new();
    let output = migrate_cmd.output(CTOR_KEYSTORE2_PATH).unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Invalid C Tor keystore (multiple keys exist for service")
    );
}

/// Tests whether `ctor-migrate` succeeds when client keys for the same service are present in both
/// the Arti primary keystore and in the C Tor keystore being migrated. It also verifies that the
/// keys in the Arti primary keystore differ from the original ones after migration.
#[test]
fn forced_migration_overwrites_arti_keys() {
    let migrate_cmd = CTorMigrateCmd::new();
    migrate_cmd.populate_state_dir();
    // Ensure the keystore is now populated with the expected keys
    let output_service_1_prev = migrate_cmd
        .keystore_contains_client_key(ONION_ADDR_SERVICE_1)
        .unwrap();
    let output_service_2_prev = migrate_cmd
        .keystore_contains_client_key(ONION_ADDR_SERVICE_2)
        .unwrap();

    assert!(
        migrate_cmd
            .output(CTOR_KEYSTORE1_PATH)
            .unwrap()
            .status
            .success()
    );

    // Check whether the current keys are different from the original ones
    let output_service_1_current = migrate_cmd
        .keystore_contains_client_key(ONION_ADDR_SERVICE_1)
        .unwrap();
    let output_service_2_current = migrate_cmd
        .keystore_contains_client_key(ONION_ADDR_SERVICE_2)
        .unwrap();
    assert_ne!(output_service_1_prev, output_service_1_current);
    assert_ne!(output_service_2_prev, output_service_2_current);
}

/// Tests that `ctor-migrate` fails when there are no valid entries in the
/// registered C Tor keystore, then test `ctor-migrate` fails when there
/// are no valid keys in the registered C Tor keystore.
#[test]
fn migrate_invalid_ctor_keystore() {
    let assert_cmd_fails = |path: &str| {
        let migrate_cmd = CTorMigrateCmd::new();

        let output = migrate_cmd.output(path).unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("No CTor client keys found in keystore"));
        assert!(error.contains(CTOR_KEYSTORE_ID));
    };

    // NOTE: with CTOR_KEYSTORE3_PATH the keystore has a valid entry containing an invalid key.
    // With CTOR_KEYSTORE4_PATH the keystore has an invalid entry containing a valid key.
    // Both cases should fail.
    assert_cmd_fails(CTOR_KEYSTORE3_PATH);
    assert_cmd_fails(CTOR_KEYSTORE4_PATH);
}

/// Tests whether `ctor-migrate` succeeds when both valid and invalid entries are present in the
/// registered C Tor keystore.
#[test]
fn migrate_skips_invalid_ctor_entries() {
    let migrate_cmd = CTorMigrateCmd::new();

    let output = migrate_cmd.output(CTOR_KEYSTORE5_PATH).unwrap();
    assert!(output.status.success());

    assert!(
        migrate_cmd
            .keystore_contains_client_key(ONION_ADDR_SERVICE_1)
            .is_ok()
    );
}
