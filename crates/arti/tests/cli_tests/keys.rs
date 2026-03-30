//! Arti keys integration test suite.
//!
//! The `assert_cmd` crate is used here instead of the preferred `trycmd` (see
//! [`README`](../README.md)) because the output of `keys list` is not deterministic across
//! different machines. The design choices of some components are workarounds for this limitation.
//!
//! ## Note on the test data
//!
//! Test data for this suite is stored in the `keys/keys.in/local` directory. The structure is as follows:
//!
//! ```
//! local/
//! ├── ctor-keystore
//! │   ├── hostname
//! │   ├── hs_ed25519_public_key
//! │   ├── hs_ed25519_secret_key
//! │   └── hs_unrecognized_entry
//! └── state-dir
//!     └── keystore
//!         ├── client
//!         │   └── mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad
//!         │       └── ks_hsc_desc_enc.x25519_private
//!         ├── hss
//!         │   └── allium-cepa
//!         │       ├── ks_hs_id.ed25519_expanded_private
//!         │       └── unrecognized-entry
//!         └── unrecognized-path-dir
//!             └── ks_hs_id.ed25519_expanded_private
//! ```
//!
//! Where:
//!
//! - `local/ctor-keystore` is a fully populated CTor keystore.
//! - `local/state-dir` is an example Arti state directory, partially populated.
//!   This directory typically corresponds to `~/.local/share/arti`. For the
//!   purposes of testing, it contains only `local/state-dir/keystore`.
//! - `local/state-dir/keystore/hss/allium-cepa` is a partially populated keystore for the hidden service
//!   `allium-cepa`. It includes a long-term identity key and an unregistered entry.
//! - `local/state-dir/keystore/client/mnyizjj7m3hpcr7i5afph3zt7maa65johyu2ruis6z7cmnjmaj3h6tad/ks_hsc_desc_enc.x25519_private`
//!   is a service discovery key for the hidden service `mnyi[..]tad.onion`.
//! - `local/state-dir/keystore/unrecognized-path-dir/ks_hs_id.ed25519_expanded_private` is an
//!   unrecognized path.
//!
//! Form more information about unrecognized entries and paths see
//! [keys list documentation](../../../../doc/keys.md).
// TODO: it would be desirable to have a deterministic script that generates the test files, like
// the one that genearates the keys for `hsc ctor-migrate` (see `maint/keygen-client-auth-test`).
// See issue #2334

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
