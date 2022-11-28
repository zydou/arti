//! Configuration logic for tor-ptmgr.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::{CfgPath, ConfigBuildError};
use tor_linkspec::PtTransportName;

/// A single pluggable transport, to be launched as an external process.
#[derive(Clone, Debug, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct ManagedTransportConfig {
    /// The transport protocols that we are willing to use from this binary.
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    pub(crate) protocols: Vec<PtTransportName>,
    /// The path to the binary to run.
    pub(crate) path: CfgPath,
    /// One or more command-line arguments to pass to the binary.
    // TODO: Should this be OsString? That's a pain to parse...
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[builder(default)]
    pub(crate) arguments: Vec<String>,
    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand
    #[builder(default)]
    pub(crate) run_on_startup: bool,
}
