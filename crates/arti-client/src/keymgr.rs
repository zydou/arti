//! A module exporting a key manager implementation.
//!
//! If the `keymgr` feature is enabled, this exports everything from the `tor-keymgr` crate.
//! Otherwise, this exposes a dummy key manager implementation.

#[cfg(not(feature = "keymgr"))]
mod dummy;

/// A private module which exports the key manager API.
mod private {
    #[cfg(not(feature = "keymgr"))]
    pub(crate) use super::dummy::*;

    #[cfg(feature = "keymgr")]
    pub(crate) use tor_keymgr::*;
}

pub(crate) use private::*;
