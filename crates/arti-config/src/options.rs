//! Handling for arti's configuration formats.

/// Default options to use for our configuration.
//
// TODO should this be in `arti::cfg` ?
pub const ARTI_DEFAULTS: &str = concat!(include_str!("./arti_defaults.toml"),);
