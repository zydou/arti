//! Relay-side DNS configuration

use std::path::PathBuf;

use derive_deftly::Deftly;
use tor_config::derive::prelude::*;

/// DNS configuration for exits.
///
/// This is ignored unless exit.enabled = true
///
// TODO(relay): there is no exit config yet, so the above statement is aspirational
#[derive(Debug, Clone, Eq, PartialEq, Deftly)]
#[derive_deftly(TorConfig)]
pub(crate) struct DnsConfig {
    /// Overrides the default DNS configuration with the one specified in this file.
    ///
    /// The file format is the same as the standard Unix "resolv.conf".
    ///
    /// Only supported on non-Apple Unix-like systems.
    /// Defaults to /etc/resolv.conf if not set.
    ///
    /// Ignored on Windows.
    //
    // Note: we might want to support this on windows too,
    // but I have no idea what format windows uses for this,
    // and hickory's system_conf module only exposes helpers on Unix
    // (on Windows, it only exposes `read_system_conf()`,
    // which reads and parses the config from the default location,
    // wherever that might be).
    //
    // Same applies to macOS. For some reason Hickory doesn't expose
    // parse_resolv_conf() if target_vendor = "apple",
    // although I think that ought to be available on mac too? (not sure).
    // In any case, this is unsupported for now.
    #[deftly(tor_config(default))]
    pub(crate) resolv_conf: Option<PathBuf>,
}
