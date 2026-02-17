//! Helpers for testing the `arti hsc key` subcommand.

use std::{path::PathBuf, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;

use crate::util::create_state_dir_entry;

/// A test onion address.
pub(super) const ONION_ADDR: &str =
    "fpqqmiwzqiv63jczrshh4qcmlxw6gujcai3arobq23wikt7hk7ojadid.onion";
/// Length of the onion address without ".onion" suffix.
pub(super) const ADDR_LEN: usize = 56;
/// Path to a test specific configuration for `arti hsc key`.
const CFG_PATH_KEY: &str = "./tests/testcases/hsc-common/conf/hsc.toml";

/// An `arti hsc key` subcommand.
#[derive(Debug, Clone, Copy, Eq, PartialEq, derive_more::Display)]
pub(crate) enum ArtiHscKeyCmd {
    /// If `generate` is true, passes `--generate no` to the `arti hsc key get` command.
    #[display("get")]
    Get { generate: bool },
    #[display("rotate")]
    Rotate,
    #[display("remove")]
    Remove,
}

/// A struct that represents the subcommand `hsc key`.
#[derive(Debug, Clone, Eq, PartialEq, derive_builder::Builder)]
pub(crate) struct KeyCmd {
    /// Path to the configuration file.
    ///
    /// Defaults to [`CFG_PATH_KEY`].
    #[builder(default = "CFG_PATH_KEY.into()")]
    config: String,
    /// `arti hsc key` subcommand.
    subcommand: ArtiHscKeyCmd,
    /// Path to the state directory to use.
    state_dir: PathBuf,
    /// When `true`, the `--batch` flag will be used, making the command run
    /// non-interactively (without accepting input from `stdin`)
    ///
    /// Defaults to `true`.
    #[builder(default = "true")]
    batch: bool,
    /// The value to write to the command's `stdin`.
    ///
    /// `arti hsc key {get, rotate, remove}` always require an onion address to be passed via `stdin`.
    ///
    /// Defaults to [`ONION_ADDR`].
    #[builder(default = "ONION_ADDR.into()")]
    stdin: String,
}

impl KeyCmd {
    /// Execute the command and return its output as an [`Output`].
    pub(crate) fn run(&self) -> std::io::Result<Output> {
        let path_to_state_dir = create_state_dir_entry(self.state_dir.to_string_lossy().as_ref());
        let mut cmd = cargo_bin_cmd!("arti");
        cmd.args([
            "-c",
            &self.config,
            "-o",
            &path_to_state_dir,
            "hsc",
            "key",
            &self.subcommand.to_string(),
        ]);
        if self.batch {
            cmd.arg("--batch");
        }
        match self.subcommand {
            ArtiHscKeyCmd::Get { generate } => {
                cmd.args(["--output", "-"]);
                if !generate {
                    cmd.args(["--generate", "no"]);
                }
            }
            ArtiHscKeyCmd::Rotate => {
                cmd.args(["--output", "-"]);
            }
            ArtiHscKeyCmd::Remove => {}
        }
        cmd.write_stdin(&*self.stdin);
        cmd.output()
    }

    /// Returns `true` if the state directory contains a client key for the service indicated by `addr`.
    pub(crate) fn keystore_contains_priv_key(&self, addr: &str) -> bool {
        let keystore_path = &self
            .state_dir
            .join("keystore/client")
            .join(&addr[..ADDR_LEN]);

        for f in keystore_path.read_dir().unwrap().flatten() {
            if f.file_name() == "ks_hsc_desc_enc.x25519_private" {
                return true;
            }
        }
        false
    }
}
