//! Helpers for testing the `arti hsc key` subcommand.

use std::path::Path;

use assert_cmd::{Command, cargo::cargo_bin_cmd};

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
pub(super) enum ArtiHscKeyCmd {
    #[display("get")]
    Get,
    #[display("rotate")]
    Rotate,
    #[display("remove")]
    Remove,
}

/// Build an `arti hsc key` command, setting the state directory to `state_dir`.
pub(super) fn build_hsc_key_cmd(sub_cmd: ArtiHscKeyCmd, state_dir: &Path) -> Command {
    let opts = create_state_dir_entry(state_dir.to_string_lossy().as_ref());
    let mut cmd = cargo_bin_cmd!("arti");
    cmd.args([
        "-c",
        CFG_PATH_KEY,
        "-o",
        &opts,
        "hsc",
        "key",
        &sub_cmd.to_string(),
        "--batch",
    ]);

    // Add subcommand-specific args
    match sub_cmd {
        ArtiHscKeyCmd::Get => {
            cmd.args(["--key-type=service-discovery", "--output", "-"]);
        }
        ArtiHscKeyCmd::Rotate => {
            cmd.args(["--output", "-"]);
        }
        ArtiHscKeyCmd::Remove => {}
    }

    cmd
}
