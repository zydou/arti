//! Configuration information for onion services.

use crate::HsNickname;

/// Configuration for a single onion service.
#[derive(Debug, Clone)]
pub struct OnionServiceConfig {
    /// The nickname used to look up this service's keys, state, configuration, etc,
    //
    // TODO HSS: It's possible that instead of having this be _part_ of the
    // service's configuration, we want this to be the key for a map in
    // which the service's configuration is stored.  We'll see how the code
    // evolves.
    // (^ ipt_mgr::IptManager contains a copy of this nickname, that should be fixed too)
    nickname: HsNickname,

    /// Whether we want this to be a non-anonymous "single onion service".
    /// We could skip this in v1.  We should make sure that our state
    /// is built to make it hard to accidentally set this.
    anonymity: crate::Anonymity,

    /// Number of intro points; defaults to 3; max 20.
    /// TODO HSS config this Option should be defaulted prior to the value ending up here
    pub(crate) num_intro_points: Option<u8>,
    // TODO HSS: I'm not sure if client encryption belongs as a configuration
    // item, or as a directory like C tor does it.  Or both?
}
