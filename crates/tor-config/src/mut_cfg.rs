//! Helper type for making configurations mutable.

use std::sync::{Arc, RwLock};

/// A mutable configuration object.
///
/// Internally, this is just a `RwLock<Arc<T>>`; this type just defines some
/// convenience wrappers for it.
#[derive(Debug, Default)]
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

impl<T> From<T> for MutCfg<T> {
    fn from(config: T) -> MutCfg<T> {
        MutCfg::new(config)
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn basic_constructors() {
        let m = MutCfg::new(7_u32);
        assert_eq!(*m.get(), 7);
        let m: MutCfg<u32> = MutCfg::default();
        assert_eq!(*m.get(), 0);
        let m: MutCfg<u32> = 100.into();
        assert_eq!(*m.get(), 100);
    }

    #[test]
    fn mutate_with_existing_ref() {
        let m = MutCfg::new(100_u32);
        let old_ref = m.get();
        m.replace(101);
        assert_eq!(*old_ref, 100);
        assert_eq!(*m.get(), 101);
    }

    #[test]
    fn check_and_replace() {
        let m = MutCfg::new(100_u32);
        let different_100 = Arc::new(100_u32);
        // won't replace, since it is a different arc.
        assert!(!m.check_and_replace(&different_100, 200));
        let old_100 = m.get();
        assert_eq!(*old_100, 100);
        assert!(m.check_and_replace(&old_100, 200));
        assert_eq!(*m.get(), 200);
    }

    #[test]
    fn map_and_replace() {
        let m = MutCfg::new(100_u32);
        let m_old = m.get();
        m.map_and_replace(|old_val| **old_val * 20);
        assert_eq!(*m.get(), 2000);
        assert_eq!(*m_old, 100);
    }
}
