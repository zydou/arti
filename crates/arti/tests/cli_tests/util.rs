//! Utilities for integration testing of CLI subcommands.

use std::process::Output;

/// Due to the "destroy" policy of some service configurations,
/// in some of the tests stderr is not empty; instead, it contains
/// a log message.
/// This function asserts that only this message is present in
/// the stderr channel.
pub fn assert_log_message(output: Output) {
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
pub fn create_state_dir_entry(state_dir_path: &str) -> String {
    let table: toml::Table = [("state_dir".to_string(), state_dir_path.into())]
        .into_iter()
        .collect();
    let table: toml::Table = [("storage".to_string(), table.into())]
        .into_iter()
        .collect();
    toml::to_string(&table).unwrap()
}
