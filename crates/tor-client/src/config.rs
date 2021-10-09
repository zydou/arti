//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
        PathConfigBuilder, RequestTiming, RequestTimingBuilder,
    };
}

/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dirmgr::{
        Authority, AuthorityBuilder, DirMgrConfig, DirMgrConfigBuilder, DownloadScheduleConfig,
        DownloadScheduleConfigBuilder, FallbackDir, FallbackDirBuilder, NetworkConfig,
        NetworkConfigBuilder,
    };
}
