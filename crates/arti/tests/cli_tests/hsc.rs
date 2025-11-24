use std::path::Path;

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;

/// A test onion address.
const ONION_ADDR: &str = "fpqqmiwzqiv63jczrshh4qcmlxw6gujcai3arobq23wikt7hk7ojadid.onion";
/// Length of the onion address without ".onion" suffix.
const ADDR_LEN: usize = 56;
/// Path to a test specific configuration
const CFG_PATH: &str = "./tests/testcases/hsc-common/conf/hsc.toml";

/// An `arti hsc` subcommand.
#[derive(Debug, Clone, Copy, Eq, PartialEq, derive_more::Display)]
enum ArtiHscCmd {
    #[display("get")]
    Get,
    #[display("rotate")]
    Rotate,
    #[display("remove")]
    Remove,
}

/// Build an `arti hsc` command, setting the state directory to `state_dir`.
fn build_hsc_cmd(sub_cmd: ArtiHscCmd, state_dir: &Path) -> Command {
    let opts = format!(r#"storage.state_dir="{}""#, state_dir.to_str().unwrap());
    let mut cmd = cargo_bin_cmd!("arti");
    cmd.args([
        "-c",
        CFG_PATH,
        "-o",
        &opts,
        "hsc",
        "key",
        &sub_cmd.to_string(),
        "--batch",
    ]);

    // Add subcommand-specific args
    match sub_cmd {
        ArtiHscCmd::Get => {
            cmd.args(["--key-type=service-discovery", "--output", "-"]);
        }
        ArtiHscCmd::Rotate => {
            cmd.args(["--output", "-"]);
        }
        ArtiHscCmd::Remove => {}
    }

    cmd
}

#[test]
fn gen_key() {
    let state_dir = tempfile::TempDir::new().unwrap();
    let state_dir = state_dir.path();
    let mut cmd = build_hsc_cmd(ArtiHscCmd::Get, state_dir);
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
    let mut cmd = build_hsc_cmd(ArtiHscCmd::Get, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    let descriptor = String::from_utf8(output.stdout).unwrap();
    assert!(descriptor.contains("descriptor:x25519:"));

    let mut cmd = build_hsc_cmd(ArtiHscCmd::Rotate, state_dir);
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
    let mut cmd = build_hsc_cmd(ArtiHscCmd::Get, state_dir);
    cmd.write_stdin(ONION_ADDR);
    let output = cmd.output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("descriptor:x25519:")
    );

    let mut cmd = build_hsc_cmd(ArtiHscCmd::Remove, state_dir);
    cmd.write_stdin(ONION_ADDR);
    cmd.assert().success();

    let keystore_path = state_dir
        .join("keystore/client")
        .join(&ONION_ADDR[..ADDR_LEN]);
    let entries = keystore_path.read_dir().unwrap().flatten();
    // Assert key has been removed
    assert_eq!(entries.count(), 0);
}
