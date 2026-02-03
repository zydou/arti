//! Utilities for integration testing of CLI subcommands.

use std::{fs, io, path::Path, process::Output};

/// Due to the "destroy" policy of some service configurations,
/// in some of the tests stderr is not empty; instead, it contains
/// a log message.
/// This function asserts that only this message is present in
/// the stderr channel.
pub(super) fn assert_log_message(output: Output) {
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "arti:\u{1b}[33m WARN\u{1b}[0m \u{1b}[2mtor_hsrproxy::config\u{1b}[0m\u{1b}[2m:\u{1b}[0m Onion service is not configured to accept any connections.\n"
    );
}

/// Generates a value suitable for use with the `-o` flag to specify Arti's state directory.
///
/// Given a path to the state directory, this function returns a formatted string
/// in the form `storage.state_dir="<path>"`, which can be passed directly as an
/// `-o <VALUE>` argument.
///
/// NOTE: This function will become obsolete or require refactoring once #2132 is resolved.
pub(super) fn create_state_dir_entry(state_dir_path: &str) -> String {
    let table: toml::Table = [("state_dir".to_string(), state_dir_path.into())]
        .into_iter()
        .collect();
    let table: toml::Table = [("storage".to_string(), table.into())]
        .into_iter()
        .collect();
    toml::to_string(&table).unwrap()
}

/// Recursively clones the entire contents of the directory `source` into the
/// directory `destination`.
///
/// This function does not check whether `source` and `destination` exist,
/// whether they are directories, or perform any other validation.
pub(super) fn clone_dir(source: &Path, destination: &Path) -> io::Result<()> {
    let entries = source.read_dir()?;
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let source_path = entry.path();
        let file_name = entry.file_name();
        let destination_path = destination.join(file_name);
        if file_type.is_dir() {
            fs::create_dir_all(&destination_path)?;
            clone_dir(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)?;
        }
    }
    Ok(())
}
