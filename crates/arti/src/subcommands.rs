//! Arti CLI subcommands.

#[cfg(feature = "onion-service-service")]
pub(crate) mod hss;

#[cfg(all(
    feature = "onion-service-client",
    feature = "experimental-api",
    feature = "keymgr"
))]
pub(crate) mod hsc;
