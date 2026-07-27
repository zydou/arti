//! Test data, downloaded from the live network, and filtered to reduce its size

#[macro_use]
#[path = "../testdata-live/generated_consts.rs"]
#[rustfmt::skip] // shell script output is nice, but not 100% identical to rustfmt
mod generated_consts;

pub use generated_consts::*;

/// Three test data file contents', one per variety
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PerVariety {
    /// Plain consensus
    pub plain: &'static str,

    /// Microdescriptor consensus
    pub md: &'static str,

    /// Vote
    pub vote: &'static str,
}

/// Test data for one (selected) relay
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PerRelay {
    /// Nickname
    pub nick: &'static str,

    /// Data for this relay
    pub data: PerVariety,
}
