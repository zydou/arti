//! Configuration logic for tor-ptmgr.

#![allow(dead_code)] // TODO pt-client: remove.

use tor_config::CfgPath;
use tor_linkspec::TransportId;

/// Configure one or more pluggable transports.
// TODO pt-client: This needs to implement all the builder stuff.
#[derive(Clone, Debug)]
pub struct PtMgrConfig {
    /// A list of configured transport binaries.
    transport: Vec<ManagedTransportConfig>,
    // TODO: Someday we will want to also have support for a directory full of
    // transports, transports loaded dynamically from an object file, or stuff
    // like that.
}

/// A single pluggable transport, to be launched as an external process.
// TODO pt-client: This needs to implement all the builder stuff.
#[derive(Clone, Debug)]
pub struct ManagedTransportConfig {
    /// The transport protocols that we are willing to use from this binary.
    transports: Vec<TransportId>,
    /// The path to the binary to run.
    path: CfgPath,
    /// One or more command-line arguments to pass to the binary.
    // TODO: Should this be OsString? That's a pain to parse...
    arguments: Vec<String>,
    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand
    run_on_startup: bool,
}
