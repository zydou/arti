//! Configuration logic for tor-ptmgr.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{CfgPath, ConfigBuildError};
use tor_linkspec::PtTransportName;

/// A single pluggable transport, to be launched as an external process.
///
/// Pluggable transports are programs that transforms and obfuscates traffic on
/// the network between a Tor client and a Tor bridge, so that an adversary
/// cannot recognize it as Tor traffic.
#[derive(Clone, Debug, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct TransportConfig {
    /// Names of the transport protocols that we are willing to use from this binary.
    ///
    /// (These protocols are arbitrary identifiers that describe which protocols
    /// we want. They must match names that the binary knows how to provide.)
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    pub(crate) protocols: Vec<PtTransportName>,
    /// The path to the binary to run.
    ///
    /// This needs to be the path to some executable file on disk.
    pub(crate) path: CfgPath,
    /// One or more command-line arguments to pass to the binary.
    // TODO: Should this be OsString? That's a pain to parse...
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[builder(default)]
    pub(crate) arguments: Vec<String>,
    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand.
    #[builder(default)]
    pub(crate) run_on_startup: bool,
}

impl TransportConfigBuilder {
    /// Inspect the list of protocols (ie, transport names)
    ///
    /// If none have yet been specified, returns an empty list.
    pub fn get_protocols(&self) -> &[PtTransportName] {
        self.protocols.as_deref().unwrap_or_default()
    }
}
