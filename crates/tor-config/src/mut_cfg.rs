//! Helper type for making configurations mutable.

use std::sync::{Arc, RwLock};

/// A mutable configuration object.
///
/// Internally, this is just a `RwLock<Arc<T>>`; this type just defines some
/// convenience wrappers for it.
#[derive(Debug)]
pub struct MutCfg<T> {
    /// The interior configuration object.
    cfg: RwLock<Arc<T>>,
}

impl<T> MutCfg<T> {
    /// Return a new MutCfg with the provided value.
    pub fn new(config: T) -> Self {
        Self {
            cfg: RwLock::new(Arc::new(config)),
        }
    }

    /// Return the current configuration
    pub fn get(&self) -> Arc<T> {
        Arc::clone(&self.cfg.read().expect("poisoned lock"))
    }

    /// If this configuration object is still the same pointer as `old_config`,
    /// replace it with `new_config`.
    ///
    /// Returns `true` if it was in fact replaced.
    pub fn check_and_replace(&self, old_config: &Arc<T>, new_config: T) -> bool {
        let mut cfg = self.cfg.write().expect("poisoned lock");
        if Arc::ptr_eq(&cfg, old_config) {
            *cfg = Arc::new(new_config);
            true
        } else {
            false
        }
    }

    /// Replace this configuration with `new_config`.
    pub fn replace(&self, new_config: T) {
        *self.cfg.write().expect("poisoned lock") = Arc::new(new_config);
    }

    /// Replace the current configuration with the results of evaluating `func` on it.
    pub fn map_and_replace<F>(&self, func: F)
    where
        F: FnOnce(&Arc<T>) -> T,
    {
        let mut cfg = self.cfg.write().expect("poisoned lock");
        let new_cfg = func(&cfg);
        *cfg = Arc::new(new_cfg);
    }
}

impl<T: Default> Default for MutCfg<T> {
    fn default() -> Self {
        MutCfg::new(T::default())
    }
}

impl<T> From<T> for MutCfg<T> {
    fn from(config: T) -> MutCfg<T> {
        MutCfg::new(config)
    }
}
