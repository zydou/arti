//! Error types for the vanguards subsystem.

use std::sync::Arc;

use futures::task::SpawnError;
use tor_error::{ErrorKind, HasKind};

use crate::vanguards::Layer;

/// An error coming from the vanguards subsystem.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VanguardMgrError {
    /// Attempted to use an unbootstrapped `VanguardMgr` for something that
    /// requires bootstrapping to have completed.
    #[error("Cannot {action} with unbootstrapped vanguard manager")]
    BootstrapRequired {
        /// What we were trying to do that required bootstrapping.
        action: &'static str,
    },

    /// Could not find a suitable relay to use for the specifier layer.
    #[error("No suitable relays")]
    NoSuitableRelay(Layer),

    /// Could not get timely network directory.
    #[error("Unable to get timely network directory")]
    NetDir(#[from] tor_netdir::Error),

    /// Failed to access persistent storage.
    #[error("Failed to access persistent vanguard state")]
    State(#[from] tor_persist::Error),

    /// Could not spawn a task.
    #[error("Unable to spawn a task")]
    Spawn(#[source] Arc<SpawnError>),

    /// An internal error occurred.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl HasKind for VanguardMgrError {
    fn kind(&self) -> ErrorKind {
        match self {
            VanguardMgrError::BootstrapRequired { .. } => ErrorKind::BootstrapRequired,
            // TODO HS-VANGUARDS: this is not right
            VanguardMgrError::NoSuitableRelay(_) => ErrorKind::Other,
            VanguardMgrError::NetDir(e) => e.kind(),
            VanguardMgrError::State(e) => e.kind(),
            VanguardMgrError::Spawn(e) => e.kind(),
            VanguardMgrError::Bug(e) => e.kind(),
        }
    }
}
