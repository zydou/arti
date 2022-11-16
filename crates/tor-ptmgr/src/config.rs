//! Configuration logic for tor-ptmgr.

#![allow(dead_code)] // TODO pt-client: remove.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tor_config::list_builder::{define_list_builder_accessors, define_list_builder_helper};
use tor_config::{CfgPath, ConfigBuildError};
use tor_linkspec::PtTransportName;

/// Configure one or more pluggable transports.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct PtMgrConfig {
    /// A list of configured transport binaries.
    #[builder(sub_builder, setter(custom))]
    binaries: TransportConfigList,
    // TODO: Someday we will want to also have support for a directory full of
    // transports, transports loaded dynamically from an object file, or stuff
    // like that.
}

define_list_builder_accessors! {
    struct PtMgrConfigBuilder {
        pub binaries: [ManagedTransportConfigBuilder],
    }
}

/// A list of configured transport binaries (type alias for macrology).
type TransportConfigList = Vec<ManagedTransportConfig>;

define_list_builder_helper! {
    pub(crate) struct TransportConfigListBuilder {
        transports: [ManagedTransportConfigBuilder],
    }
    built: TransportConfigList = transports;
    default = vec![];
}

/// A single pluggable transport, to be launched as an external process.
#[derive(Clone, Debug, Builder, Eq, PartialEq)]
#[builder(derive(Debug, Serialize, Deserialize))]
#[builder(build_fn(error = "ConfigBuildError"))]
pub struct ManagedTransportConfig {
    /// The transport protocols that we are willing to use from this binary.
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    protocols: Vec<PtTransportName>,
    /// The path to the binary to run.
    path: CfgPath,
    /// One or more command-line arguments to pass to the binary.
    // TODO: Should this be OsString? That's a pain to parse...
    //
    // NOTE(eta): This doesn't use the list builder stuff, because you're not likely to
    //            set this field more than once.
    #[builder(default)]
    arguments: Vec<String>,
    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand
    #[builder(default)]
    run_on_startup: bool,
}
