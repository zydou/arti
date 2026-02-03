use std::{path::PathBuf, process::Output, str::FromStr};

use assert_cmd::cargo::cargo_bin_cmd;
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::util::{clone_dir, create_state_dir_entry};

/// Path to a test specific configuration that provides a full Arti native keystore.
pub(super) const CFG_PATH: &str = "./tests/testcases/hss-extra/conf/hss.toml";

/// Path to a test specific configuration that provides a full Arti native keystore and a full CTor
/// keystore.
pub(super) const CFG_CTOR_PATH: &str = "./tests/testcases/hss-extra/conf/hss-ctor.toml";

/// Path to a fully populated Arti native keystore.
const KEYSTORE_PATH: &str = "./tests/testcases/hss-extra/hss.in/local/state-dir";

/// Path to the long-term ID key, relative to the state directory.
pub(super) const EXPECTED_ID_KEY_PATH: &str =
    "keystore/hss/allium-cepa/ks_hs_id.ed25519_expanded_private";

/// Path to the keystore directory, relative to the state directory.
pub(super) const KEYSTORE_DIR_PATH: &str = "keystore";

/// Path to the keystore directory, relative to the state directory.
pub(super) const HSS_DIR_PATH: &str = "keystore/hss";

/// Path to the keystore directory, relative to the state directory.
pub(super) const SERVICE_DIR_PATH: &str = "keystore/hss/allium-cepa";

/// Path to an unrecognized keystore entry, relative to the state directory.
pub(super) const EXPECTED_UNRECOGNIZED_KEYSTORE_ENTRY: &str =
    "keystore/hss/allium-cepa/unrecognized-entry";

/// Path to ipts directory, relative to the state directory.
pub(super) const IPTS_DIR_PATH: &str = "keystore/hss/allium-cepa/ipts";

/// A part of an unrecognized path, relative to the state directory.
pub(super) const UNRECOGNIZED_PATH_1: &str = "keystore/unrecognized-path";

/// A part of an unrecognized path, relative to the state directory.
pub(super) const UNRECOGNIZED_PATH_2_DIR: &str = "keystore/unrecognized-path-dir";

/// Unrecognized path, relative to the state directory.
pub(super) const UNRECOGNIZED_PATH_2: &str = "keystore/unrecognized-path-dir/unrecognized-path";

/// A collection of every path present in the default state directory.
pub(super) const ARTI_KEYSTORE_POPULATION: &[&str] = &[
    KEYSTORE_DIR_PATH,
    HSS_DIR_PATH,
    SERVICE_DIR_PATH,
    EXPECTED_ID_KEY_PATH,
    EXPECTED_UNRECOGNIZED_KEYSTORE_ENTRY,
    "keystore/hss/allium-cepa/ks_hs_blind_id+20326_1440_43200.ed25519_expanded_private",
    "keystore/hss/allium-cepa/ks_hs_blind_id+20327_1440_43200.ed25519_expanded_private",
    IPTS_DIR_PATH,
    "keystore/hss/allium-cepa/ipts/k_sid+ce8514e2fe016e4705b064f2226a7628f4226e9a15d28607112e4eac3b3a012f.ed25519_private",
    "keystore/hss/allium-cepa/ipts/k_sid+2a6054c3432b880b76cf379f66daf1a34c88693efed5e85bd90507a1fea231d7.ed25519_private",
    "keystore/hss/allium-cepa/ipts/k_sid+84a3a863484ff521081ee8e6e48a6129d0c83bef89fe294a5dda6f782b43dec8.ed25519_private",
    "keystore/hss/allium-cepa/ipts/k_hss_ntor+ce8514e2fe016e4705b064f2226a7628f4226e9a15d28607112e4eac3b3a012f.x25519_private",
    "keystore/hss/allium-cepa/ipts/k_hss_ntor+84a3a863484ff521081ee8e6e48a6129d0c83bef89fe294a5dda6f782b43dec8.x25519_private",
    "keystore/hss/allium-cepa/ipts/k_hss_ntor+2a6054c3432b880b76cf379f66daf1a34c88693efed5e85bd90507a1fea231d7.x25519_private",
    UNRECOGNIZED_PATH_1,
    UNRECOGNIZED_PATH_2_DIR,
    UNRECOGNIZED_PATH_2,
];

/// A struct that represents the subcommand `hss ctor-migrate`.
#[derive(Debug, amplify::Getters)]
pub(super) struct CTorMigrateCmd {
    /// The temporary directory representing the state directory.
    ///
    /// NOTE: Although this field is not used directly, it must be retained to prevent the
    /// temporary directory from being dropped prematurely.
    #[allow(dead_code)]
    #[getter(skip)]
    state_dir: TempDir,
    /// The file path to the state directory.
    state_dir_path: PathBuf,
    /// Nickname of the service to be migrated, defaults to `"allium-cepa"`.
    #[getter(skip)]
    nickname: String,
    /// Configuration to the configuration file that will be used, defaults
    /// to `CFG_CTOR_PATH`.
    #[getter(skip)]
    config: String,
    /// Input text passed to the command via STDIN. If `None`, no input is provided.
    #[getter(skip)]
    stdin: Option<String>,
}

impl CTorMigrateCmd {
    /// A fresh instance of `CTorMigrateCmd`.
    pub(super) fn new() -> Self {
        let state_dir = TempDir::new().unwrap();
        let state_dir_path = state_dir.path().to_path_buf();
        Self {
            state_dir,
            state_dir_path,
            nickname: "allium-cepa".to_string(),
            config: CFG_CTOR_PATH.to_string(),
            stdin: None,
        }
    }

    /// Execute the command and return its output as an [`Output`].
    pub(super) fn output(&self) -> std::io::Result<Output> {
        let mut cmd = cargo_bin_cmd!("arti");

        let opt = create_state_dir_entry(self.state_dir_path.to_string_lossy().as_ref());
        cmd.args([
            "--config",
            &self.config,
            "-o",
            &opt,
            "hss",
            "--nickname",
            &self.nickname,
            "ctor-migrate",
        ]);

        if let Some(content) = &self.stdin {
            cmd.write_stdin(content.as_bytes());
        } else {
            cmd.arg("--batch");
        }

        cmd.output()
    }

    /// Populates the temporary state directory with the files from the default state directory.
    pub(super) fn populate_state_dir(&self) {
        let keystore_path = PathBuf::from_str(KEYSTORE_PATH).unwrap();
        clone_dir(&keystore_path, &self.state_dir_path).unwrap();
    }

    /// Check whether the state directory is empty.
    pub(super) fn is_state_dir_empty(&self) -> bool {
        self.state_dir_entries().is_empty()
    }

    /// Check whether the state directory contains only the provided entries.
    pub(super) fn state_dir_contains_only(&self, expected_entries: &[&str]) -> bool {
        let state_dir_entries = self.state_dir_entries();
        let entries: Vec<_> = state_dir_entries
            .iter()
            .map(|res| {
                let entry = res.as_ref().unwrap();
                entry.path().to_string_lossy().to_string()
            })
            .collect();
        if entries.len() != expected_entries.len() {
            return false;
        }
        for entry in expected_entries {
            let path = format!(
                "{}/{}",
                self.state_dir_path.to_string_lossy().as_ref(),
                entry
            );
            if !entries.contains(&path) {
                return false;
            }
        }
        true
    }

    /// Returns a vector containing all entries in the state directory.
    ///
    /// Each element is a `Result`, with `Err` indicating an I/O error encountered
    /// while reading an entry.
    fn state_dir_entries(&self) -> Vec<Result<walkdir::DirEntry, walkdir::Error>> {
        WalkDir::new(&self.state_dir_path)
            // Skip `&self.state_dir_path`.
            .min_depth(1)
            .into_iter()
            .collect()
    }

    /// Setter for the field `nickname`
    pub(super) fn set_nickname(&mut self, nickname: String) {
        self.nickname = nickname;
    }

    /// Setter for the field `config`
    pub(super) fn set_config(&mut self, config: String) {
        self.config = config;
    }

    /// Setter for the field `stdin`
    pub(super) fn set_stdin(&mut self, content: String) {
        self.stdin = Some(content);
    }
}

/// A struct that represents the subcommand `hss --nickname allium-cepa onion-address`.
#[derive(Debug, Clone, Default, Eq, PartialEq, derive_builder::Builder)]
pub(super) struct OnionAddressCmd {
    /// Path to the configuration file supplied as the value of the `-c` flag.
    config_path: String,
    /// Optional path to a state directory.
    /// If `Some`, passed as the value to the `-o` flag.
    #[builder(default)]
    state_directory: Option<String>,
}

impl OnionAddressCmd {
    /// Execute the command and return its output as an [`Output`].
    pub(super) fn output(&self) -> std::io::Result<Output> {
        let mut cmd = cargo_bin_cmd!("arti");
        cmd.args(["--config", &self.config_path]);
        if let Some(state_directory) = &self.state_directory {
            let opt = create_state_dir_entry(state_directory);
            cmd.args(["-o", &opt]);
        }
        cmd.args(["hss", "--nickname", "allium-cepa", "onion-address"]);

        cmd.output()
    }
}
