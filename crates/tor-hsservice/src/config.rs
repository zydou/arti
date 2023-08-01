//! Configuration information for onion services.

/// Configuration for a single onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    /// An arbitrary identifier or "nickname" used to look up this service's
    /// keys, state, configuration, etc,
    /// and distinguish them from other services.  This is local-only.
    //
    // TODO HSS: It's possible that instead of having this be _part_ of the
    // service's configuration, we want this to be the key for a map in
    // which the service's configuration is stored.  We'll see how the code
    // evolves.
    nickname: String,

    /// Whether we want this to be a non-anonymous "single onion service".
    /// We could skip this in v1.  We should make sure that our state
    /// is built to make it hard to accidentally set this.
    anonymity: crate::Anonymity,

    /// Number of intro points; defaults to 3; max 20.
    num_intro_points: Option<u8>,
    // TODO HSS: I'm not sure if client encryption belongs as a configuration
    // item, or as a directory like C tor does it.  Or both?
}
