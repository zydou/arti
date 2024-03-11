//! Experimental support for vanguards.
//!
//! For more information, see the [vanguards spec].
//!
//! [vanguards spec]: https://spec.torproject.org/vanguards-spec/index.html.

pub mod config;
mod set;

use std::sync::{Arc, RwLock};

use tor_config::ReconfigureError;
use tor_error::{ErrorKind, HasKind};
use tor_netdir::{NetDir, NetDirProvider};
use tor_persist::StateMgr;
use tor_rtcompat::Runtime;

pub use config::{VanguardConfig, VanguardConfigBuilder, VanguardMode, VanguardParams};
pub use set::Vanguard;

use set::VanguardSet;

use crate::RetireCircuits;

/// The vanguard manager.
#[allow(unused)] // TODO HS-VANGUARDS
pub struct VanguardMgr {
    /// The mutable state.
    inner: RwLock<Inner>,
    /// The L2 vanguards.
    l2_vanguards: VanguardSet,
    /// The L3 vanguards.
    l3_vanguards: VanguardSet,
}

/// The mutable inner state of [`VanguardMgr`].
#[allow(unused)] // TODO HS-VANGUARDS
struct Inner {
    /// Whether to use full, lite, or no vanguards.
    mode: VanguardMode,
    /// Configuration parameters read from the consensus parameters.
    params: VanguardParams,
}

/// An error coming from the vanguards subsystem.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VanguardMgrError {
    /// Could not find a suitable relay to use for the specifier layer.
    #[error("No suitable relays")]
    NoSuitableRelay(Layer),
}

impl HasKind for VanguardMgrError {
    fn kind(&self) -> ErrorKind {
        match self {
            // TODO HS-VANGUARDS: this is not right
            VanguardMgrError::NoSuitableRelay(_) => ErrorKind::Other,
        }
    }
}

impl VanguardMgr {
    /// Create a new `VanguardMgr`.
    ///
    /// The `state_mgr` handle is used for persisting the "vanguards-full" guard pools to disk.
    #[allow(clippy::needless_pass_by_value)] // TODO HS-VANGUARDS
    pub fn new<S>(config: &VanguardConfig, _state_mgr: S) -> Result<Self, VanguardMgrError>
    where
        S: StateMgr + Send + Sync + 'static,
    {
        let VanguardConfig { mode } = config;

        let inner = Inner {
            mode: *mode,
            // TODO HS-VANGUARDS: read the params from the consensus
            params: Default::default(),
        };

        // TODO HS-VANGUARDS: read the vanguards from disk if mode == VanguardsMode::Full
        Ok(Self {
            inner: RwLock::new(inner),
            l2_vanguards: Default::default(),
            l3_vanguards: Default::default(),
        })
    }

    /// Launch the vanguard pool management tasks.
    pub fn launch_background_tasks<R>(
        self: &Arc<Self>,
        _runtime: &R,
        _netdir_provider: &Arc<dyn NetDirProvider>,
    ) -> Result<(), VanguardMgrError>
    where
        R: Runtime,
    {
        todo!()
    }

    /// Replace the configuration in this `VanguardMgr` with the specified `config`.
    pub fn reconfigure(&self, config: &VanguardConfig) -> Result<RetireCircuits, ReconfigureError> {
        let VanguardConfig { mode } = config;

        let mut inner = self.inner.write().expect("poisoned lock");
        if *mode != inner.mode {
            inner.mode = *mode;
            return Ok(RetireCircuits::All);
        }

        Ok(RetireCircuits::None)
    }

    /// Return a [`Vanguard`] relay for use in the specified layer.
    pub fn select_vanguard(
        &self,
        netdir: &NetDir,
        layer: Layer,
    ) -> Result<Vanguard, VanguardMgrError> {
        let vanguard_set = match layer {
            Layer::Layer2 => &self.l2_vanguards,
            Layer::Layer3 => &self.l3_vanguards,
        };

        vanguard_set
            .pick_relay(netdir)
            .ok_or(VanguardMgrError::NoSuitableRelay(layer))
    }

    /// Flush the vanguard sets to storage, if the mode is "vanguards-full".
    #[allow(unused)] // TODO HS-VANGUARDS
    fn flush_to_storage(&self) -> Result<(), VanguardMgrError> {
        let mode = self.inner.read().expect("poisoned lock").mode;
        match mode {
            VanguardMode::Lite | VanguardMode::Disabled => Ok(()),
            VanguardMode::Full => todo!(),
        }
    }
}

/// The vanguard layer.
#[allow(unused)] // TODO HS-VANGUARDS
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Layer {
    /// L2 vanguard.
    Layer2,
    /// L3 vanguard.
    Layer3,
}
