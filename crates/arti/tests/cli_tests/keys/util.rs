use std::process::Output;

use assert_cmd::Command;

/// Path to a test specific configuration.
const CFG_PATH: &str = "./tests/testcases/keys/keys.in/keys.toml";

/// Path to a test specific configuration that includes a CTor keystore
const CFG_PATH_WITH_CTOR: &str = "./tests/testcases/keys/conf/keys.toml";

/// A client of an `ArtiNativeKeystore`
const CLIENT_KEY: &str = " Keystore ID: arti
 Role: ks_hsc_desc_enc
 Summary: Descriptor decryption key
 KeystoreItemType: X25519StaticKeypair
 Location: client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private
 Extra info:
 - hs_id: […]tad.onion
";

/// An unrecognized entry of an `ArtiNativeKeystore`
const UNRECOGNIZED_ENTRY: &str = " Unrecognized entry
 Keystore ID: arti
 Location: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
 Error: Key has invalid path: hss/allium-cepa/Ks_hs_id.ed25519_expanded_private
";

/// The long term identity of an `ArtiNativeKeystore`
const ID_KEY: &str = " Keystore ID: arti
 Role: ks_hs_id
 Summary: Long-term identity keypair
 KeystoreItemType: Ed25519ExpandedKeypair
 Location: hss/allium-cepa/ks_hs_id.ed25519_expanded_private
 Extra info:
 - nickname: allium-cepa
";

/// An unrecognized path in an `ArtiNativeKeystore`
const UNRECOGNIZED_PATH: &str =
    " Unrecognized path herba-spontanea/ks_hs_id.ed25519_expanded_private";

/// The secret key of an `CTorServiceKeystore`
const CTOR_SECRET: &str = " CTor service key
 Hidden service nickname: allium-cepa
 Keystore ID: ctor
 KeystoreItemType: Ed25519ExpandedKeypair
 Location: hs_ed25519_secret_key
";

/// The public key of a `CTorServiceKeystore`
const CTOR_PUBLIC: &str = " CTor service key
 Hidden service nickname: allium-cepa
 Keystore ID: ctor
 KeystoreItemType: Ed25519PublicKey
 Location: hs_ed25519_public_key
";

/// The hostname file of a `CTorServiceKeystore`
const CTOR_HOSTNAME: &str = " Unrecognized entry
 Keystore ID: ctor
 Location: hostname
 Error: Key hostname is malformed
";

/// An unrecognized entry in a `CTorServiceKeystore`
const CTOR_UNRECOGNIZED_ENTRY: &str = " Unrecognized entry
 Keystore ID: ctor
 Location: hs_herba_spontanea
 Error: Key hs_herba_spontanea is malformed
";

/// The output relative to all the keys present in the test `ArtiNativeKeystore`.
pub const LIST_OUTPUT_ARTI: &[&str] = &[CLIENT_KEY, UNRECOGNIZED_ENTRY, ID_KEY, UNRECOGNIZED_PATH];

/// The the output relative to all the keys present
/// in the test `CTorServiceKeystore`.
///
// TODO: The hostname file of the ctor keystore is not
// currently handled correctly and is erroneously represented
// as an unrecognized entry. This should be fixed.
pub const LIST_OUTPUT_CTOR: &[&str] = &[
    CTOR_HOSTNAME,
    CTOR_SECRET,
    CTOR_PUBLIC,
    CTOR_UNRECOGNIZED_ENTRY,
];

/// A struct that represents the subcommand `keys list`.
#[derive(Debug, Clone, Default, Eq, PartialEq, derive_builder::Builder)]
pub struct KeysListCmd {
    /// Use [`with_arti`] to include a populated `ArtiNativeKeystore`.
    #[builder(default)]
    with_arti: bool,
    /// Use [`with_ctor`] to include a populated `CTorServiceKeystore`.
    #[builder(default)]
    with_ctor: bool,
    /// Use [`keystore`] to pass a `-k <KEYSTORE_ID>` flag to the command.
    #[builder(default)]
    keystore: Option<String>,
}

impl KeysListCmd {
    /// Execute the command and return its output as an [`Output`].
    pub fn output(&self) -> std::io::Result<Output> {
        let mut cmd = Command::cargo_bin("arti").unwrap();
        if self.with_ctor {
            cmd.args(["-c", CFG_PATH_WITH_CTOR]);
        } else {
            cmd.args(["-c", CFG_PATH]);
        }
        // When [`with_arti`] is set to false, the default configured state directory,
        // which holds an Arti-native keystore with both valid and invalid entries,
        // will be replaced by a new, temporary, empty directory.
        let state_dir;
        if !self.with_arti {
            state_dir = tempfile::TempDir::new().unwrap();
            let state_dir_path = state_dir.path().to_path_buf();
            let state_dir_path = state_dir_path.to_str().unwrap();

            let opt = Self::create_state_dir_entry(state_dir_path);

            cmd.args(["-o", &opt]);
        }

        cmd.args(["keys", "list"]);

        if let Some(keystore_id) = &self.keystore {
            cmd.args(["-k", keystore_id]);
        }

        cmd.output()
    }

    /// Generates a value suitable for use with the `-o` flag to specify Arti's state directory.
    ///
    /// Given a path to the state directory, this function returns a formatted string
    /// in the form `storage.state_dir="<path>"`, which can be passed directly as an
    /// `-o <VALUE>` argument.
    ///
    /// NOTE: This function will become obsolete or require refactoring once #2132 is resolved.
    fn create_state_dir_entry(state_dir_path: &str) -> String {
        let table: toml::Table = [("state_dir".to_string(), state_dir_path.into())]
            .into_iter()
            .collect();
        let table: toml::Table = [("storage".to_string(), table.into())]
            .into_iter()
            .collect();
        toml::to_string(&table).unwrap()
    }
}

/// A struct that represents the subcommand `keys list-keystores`.
#[derive(Debug, Clone, Default, Eq, PartialEq, derive_builder::Builder)]
pub struct KeysListKeystoreCmd {
    /// Use [`with_ctor`] to include a `CTorServiceKeystore` in the configuration.
    #[builder(default)]
    with_ctor: bool,
}

impl KeysListKeystoreCmd {
    /// Execute the command and return its output as an [`Output`].
    pub fn output(&self) -> std::io::Result<Output> {
        let mut cmd = Command::cargo_bin("arti").unwrap();
        if self.with_ctor {
            cmd.args(["-c", CFG_PATH_WITH_CTOR]);
        } else {
            cmd.args(["-c", CFG_PATH]);
        }

        cmd.args(["keys", "list-keystores"]);

        cmd.output()
    }
}

/// Due to the "destroy" policy in `keys.toml`, in some of the
/// tests stderr is not empty; instead, it contains a log message.
/// This function asserts that only this message is present in
/// the stderr channel.
pub fn assert_log_message(output: Output) {
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "arti:\u{1b}[33m WARN\u{1b}[0m \u{1b}[2mtor_hsrproxy::config\u{1b}[0m\u{1b}[2m:\u{1b}[0m Onion service is not configured to accept any connections.\n"
    );
}
