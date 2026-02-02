//! Helpers for testing the `arti hsc ctor-migrate` subcommand.
//!
//! ## Note on the test data
//!
//! Test data for this suite is stored in the `hsc-extra/hsc.in/local` directory. The structure is
//! as follows:
//!
//! ```
//! local
//! ├── ctor-keystore1
//! │   ├── service1.auth_private
//! │   └── service2.auth_private
//! ├── ctor-keystore2
//! │   ├── service1.auth_private
//! │   ├── service2.auth_private
//! │   └── service2_replica.auth_private
//! ├── ctor-keystore3
//! │   └── invalid_key.auth_private
//! ├── ctor-keystore4
//! │   └── invalid_entry
//! ├── ctor-keystore5
//! │   ├── invalid_entry
//! │   ├── service1.auth_private
//! │   └── service2.auth_private
//! └── state-dir
//!     └── keystore
//!         └── client
//!             ├── 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid
//!             │   └── ks_hsc_desc_enc.x25519_private
//!             └── rh5d6reakhpvuxe2t3next6um6iiq4jf43m7gmdrphfhopfpnoglzcyd
//!                 └── ks_hsc_desc_enc.x25519_private
//! ```
//!
//! Where:
//!
//! - `ctor-keystore1` is a valid keystore containing restricted service discovery keys for
//!   service 1 and service 2.
//! - `ctor-keystore2` is an invalid keystore containing restricted service discovery keys for service 1
//!   and service 2, along with a redundant key for service 2.
//! - `ctor-keystore3` is a valid keystore containing an invalid key.
//! - `ctor-keystore4` is a valid keystore containing an invalid entry.
//! - `ctor-keystore5` is a valid keystore containing restricted service discovery keys for service 1
//!   and service 2, along with a an invalid entry.
//!   service 1 and service 2, along with a redundant key for service 2.
//! - `service*.auth_private` are valid restricted service discovery keys.
//! - `service<N>_replica.auth_private` is a redundant copy of `service<N>.auth_private`. This file
//!   exists because a C Tor keystore is considered invalid if it contains more than one restricted
//!   discovery key for the same service.
//! - `invalid_key.auth_private` is a valid keystore entry containing an invalid restricted service
//!   discovery key, it could be an empty file.
//! - `invalid_entry` is an invalid keystore entry (i.e. it has an unrecognized path) that contains
//!   a valid restricted service discovery key.
//! - `state-dir` is a state directory populated by an Arti native keystore, containing restricted
//!   service discovery keys for the services at:
//!   `rh5d6reakhpvuxe2t3next6um6iiq4jf43m7gmdrphfhopfpnoglzcyd.onion` (service1) and
//!   `2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion` (service2).
//!
//! The C Tor Keystores have been generated using the script
//! `maint/keygen-client-auth-test/generate`.
//!
//! NOTE: Although both C Tor keystores and the Arti native keystore hold keys for the same services,
//! the keys in the Arti native keystore differ from those in the C Tor keystores in both data and
//! format.
//! Different C Tor keystores contain identical keys.

use std::{
    path::{Path, PathBuf},
    process::Output,
    str::FromStr,
};

use anyhow::anyhow;
use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;
use toml::{Table, Value};

use crate::util::{clone_dir, create_state_dir_entry};

/// Path to a test specific configuration for `arti hsc ctor-migrate`.
pub(super) const CFG_PATH_CTOR_MIGRATE: &str = "./tests/testcases/hsc-extra/conf/hsc.toml";
/// The onion address for service 1.
pub(super) const ONION_ADDR_SERVICE_1: &str =
    "rh5d6reakhpvuxe2t3next6um6iiq4jf43m7gmdrphfhopfpnoglzcyd.onion";

/// The onion address for service 2.
pub(super) const ONION_ADDR_SERVICE_2: &str =
    "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

/// Path to a C Tor keystore with restricted service discovery keys for service 1
/// and service 2.
pub(super) const CTOR_KEYSTORE1_PATH: &str =
    "./tests/testcases/hsc-extra/hsc.in/local/ctor-keystore1";

/// Path to a C Tor keystore with restricted service discovery keys for service 1
/// and service 2, along with a redundant key for service 2.
///
/// This keystore is invalid because of the duplicated key.
pub(super) const CTOR_KEYSTORE2_PATH: &str =
    "./tests/testcases/hsc-extra/hsc.in/local/ctor-keystore2";

/// Path to a C Tor keystore with an invalid key.
pub(super) const CTOR_KEYSTORE3_PATH: &str =
    "./tests/testcases/hsc-extra/hsc.in/local/ctor-keystore3";

/// Path to a C Tor keystore with an invalid entry.
pub(super) const CTOR_KEYSTORE4_PATH: &str =
    "./tests/testcases/hsc-extra/hsc.in/local/ctor-keystore4";

/// Path to a C Tor keystore with restricted service discovery keys for service 1
/// and service 2, along with a an invalid entry.
pub(super) const CTOR_KEYSTORE5_PATH: &str =
    "./tests/testcases/hsc-extra/hsc.in/local/ctor-keystore5";

/// Path to a state directory containing a fully populated Arti native keystore.
///
/// The keystore contains two vaild restricted service discovery keys.
pub(super) const KEYSTORE_PATH: &str = "./tests/testcases/hsc-extra/hsc.in/local/state-dir";

/// ID that will be assigned to the C Tor keystore in every test for `hsc ctor-migrate`.
pub(super) const CTOR_KEYSTORE_ID: &str = "ctor";

/// A struct that represents the subcommand `hsc ctor-migrate`.
pub(super) struct CTorMigrateCmd {
    /// The temporary directory representing the state directory.
    ///
    /// NOTE: Although this field is not used directly, it must be retained to prevent the
    /// temporary directory from being dropped prematurely.
    #[allow(dead_code)]
    state_dir: TempDir,
    /// The file path to the state directory.
    state_dir_path: PathBuf,
}

impl CTorMigrateCmd {
    pub(super) fn new() -> Self {
        let state_dir = TempDir::new().unwrap();
        let state_dir_path = state_dir.path().to_path_buf();
        Self {
            state_dir,
            state_dir_path,
        }
    }

    /// Execute the command and return its output as an [`Output`].
    ///
    /// `ctor_keystore` is the path to the C Tor keystore that will be migrated.
    // TODO: Give a more descriptive and intuitive name to this method.
    pub(super) fn output(&self, ctor_keystore: impl AsRef<Path>) -> std::io::Result<Output> {
        let mut cmd = cargo_bin_cmd!("arti");
        let state_dir = create_state_dir_entry(self.state_dir_path.to_string_lossy().as_ref());
        // NOTE: C Tor keystores are added to the configuration via the `-o` flag,
        // not through the configuration file. This allows the C Tor keystore to be
        // easily excluded when testing with other endpoints, such as in [`Self::keystore_contains_client_key`],
        // without changing the configuration file.
        let ctor_keystore_path =
            create_ctor_client_keystore_opt(ctor_keystore.as_ref().to_str().unwrap());
        cmd.args([
            "--config",
            CFG_PATH_CTOR_MIGRATE,
            "hsc",
            "-o",
            &state_dir,
            "-o",
            &ctor_keystore_path,
            "ctor-migrate",
            "--from",
            CTOR_KEYSTORE_ID,
            "--batch",
        ]);
        cmd.output()
    }

    /// Use the `hsc key get` endpoint to test whether `addr` has a corresponding
    /// service-discovery key in the primary Arti keystore.
    ///
    /// Returns the command output if successful.
    pub(super) fn keystore_contains_client_key(&self, addr: &str) -> Result<String, anyhow::Error> {
        let opts = create_state_dir_entry(self.state_dir_path.to_string_lossy().as_ref());
        let mut cmd = cargo_bin_cmd!("arti");
        cmd.args([
            "-c",
            CFG_PATH_CTOR_MIGRATE,
            "-o",
            &opts,
            "hsc",
            "key",
            "get",
            "--batch",
            "--key-type=service-discovery",
            "--output",
            "-",
            "--generate",
            "no",
        ]);
        cmd.write_stdin(addr);
        let output = cmd.output()?;
        if output.status.success() {
            Ok(String::from_utf8(output.stdout)?)
        } else {
            Err(anyhow!(String::from_utf8(output.stderr)?))
        }
    }

    /// Populates the temporary state directory with the files from the test state directory.
    pub(super) fn populate_state_dir(&self) {
        let keystore_path = PathBuf::from_str(KEYSTORE_PATH).unwrap();
        clone_dir(&keystore_path, &self.state_dir_path).unwrap();
    }
}

/// Generates a value suitable for use with the `-o` flag to specify Arti's configured
/// C Tor client keystores.
///
/// Given a path to the C Tor client keystore, this function returns a formatted string
/// in the form `storage.keystore.ctor.clients='[{id = "ctor", path = "<PATH>"}]'`,
/// which can be passed directly as an `-o <VALUE>` argument.
///
/// NOTE: This function will become obsolete or require refactoring once #2132 is resolved.
pub(super) fn create_ctor_client_keystore_opt(ctor_keystore_path: &str) -> String {
    let mut client = Table::new();
    client.insert("id".to_string(), Value::String("ctor".to_string()));
    client.insert(
        "path".to_string(),
        Value::String(ctor_keystore_path.to_string()),
    );

    let mut keystore = Table::new();
    keystore.insert(
        "clients".to_string(),
        Value::Array(vec![Value::Table(client)]),
    );

    let mut ctor = Table::new();
    ctor.insert("ctor".to_string(), Value::Table(keystore));

    let mut storage = Table::new();
    storage.insert("keystore".to_string(), Value::Table(ctor));

    let mut table = Table::new();
    table.insert("storage".to_string(), Value::Table(storage));

    toml::to_string(&table).unwrap()
}
