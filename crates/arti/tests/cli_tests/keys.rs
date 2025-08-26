//! Arti keys integration test suite.
//!
//! The `assert_cmd` crate is used here instead of the preferred `trycmd` (see
//! [`README`](../README.md)) because the output of `keys list` is not deterministic across
//! different machines. The design choices of some components are workarounds for this limitation.

use crate::keys::util::{
    KeysListCmdBuilder, KeysListKeystoreCmdBuilder, LIST_OUTPUT_ARTI, LIST_OUTPUT_CTOR,
};
use crate::util::assert_log_message;
mod util;

#[test]
fn list_all_keystore_entries() {
    let output = KeysListCmdBuilder::default()
        .with_arti(true)
        .with_ctor(true)
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    for entry in LIST_OUTPUT_ARTI {
        assert!(stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(stdout.contains(entry))
    }
    assert_log_message(output);
}

#[test]
fn list_arti_keystore_entries() {
    let output = KeysListCmdBuilder::default()
        .with_arti(true)
        .with_ctor(true)
        .keystore(Some("arti".to_string()))
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    for entry in LIST_OUTPUT_ARTI {
        assert!(stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(!stdout.contains(entry))
    }
    assert_log_message(output);
}

#[test]
fn list_ctor_keystore_entries() {
    let output = KeysListCmdBuilder::default()
        .with_arti(true)
        .with_ctor(true)
        .keystore(Some("ctor".to_string()))
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    for entry in LIST_OUTPUT_ARTI {
        assert!(!stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(stdout.contains(entry))
    }
    assert_log_message(output);
}

#[test]
fn list_unregistered_keystore_fails() {
    let unregistered = "unregistered";
    let output = KeysListCmdBuilder::default()
        .keystore(Some(unregistered.to_string()))
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains(&format!("arti: error: Keystore {} not found", unregistered)));
    assert!(output.stdout.is_empty())
}

#[test]
fn list_arti_with_empty_state_dir_and_full_ctor() {
    let output = KeysListCmdBuilder::default()
        .keystore(Some("arti".to_string()))
        .with_ctor(true)
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("Currently there are no entries in the keystore arti."));
    for entry in LIST_OUTPUT_ARTI {
        assert!(!stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(!stdout.contains(entry))
    }
    assert_log_message(output);
}

#[test]
fn list_with_empty_state_dir_and_full_ctor() {
    let output = KeysListCmdBuilder::default()
        .with_ctor(true)
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    for entry in LIST_OUTPUT_ARTI {
        assert!(!stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(stdout.contains(entry))
    }
    assert_log_message(output);
}

#[test]
fn list_with_empty_state_dir_and_no_registered_ctor() {
    let output = KeysListCmdBuilder::default()
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Currently there are no entries in any of the keystores."));
    for entry in LIST_OUTPUT_ARTI {
        assert!(!stdout.contains(entry))
    }
    for entry in LIST_OUTPUT_CTOR {
        assert!(!stdout.contains(entry))
    }
    assert!(output.stderr.is_empty())
}

#[test]
fn list_keystore_with_arti_and_ctor() {
    let output = KeysListKeystoreCmdBuilder::default()
        .with_ctor(true)
        .build()
        .unwrap()
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("arti"));
    assert!(stdout.contains("ctor"));
    assert_log_message(output);
}

#[test]
fn list_keystore_with_arti() {
    let output = KeysListKeystoreCmdBuilder::default()
        .build()
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(stdout.contains("arti"));
    assert!(!stdout.contains("ctor"));
    assert!(output.stderr.is_empty())
}
