//! Code to construct paths to a directory for non-anonymous downloads
use super::TorPath;
use crate::Result;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_rtcompat::Runtime;

/// A PathBuilder that can connect to a directory.
#[non_exhaustive]
pub(crate) struct DirPathBuilder {}

impl Default for DirPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DirPathBuilder {
    /// Create a new DirPathBuilder.
    pub(crate) fn new() -> Self {
        DirPathBuilder {}
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub(crate) fn pick_path<'a, RT: Runtime>(
        &self,
        guards: &GuardMgr<RT>,
    ) -> Result<(TorPath<'a>, GuardMonitor, GuardUsable)> {
        let guard_usage = tor_guardmgr::GuardUsageBuilder::default()
            .kind(tor_guardmgr::GuardUsageKind::OneHopDirectory)
            .build()
            .expect("Unable to build directory guard usage");
        let (guard, mon, usable) = guards.select_guard(guard_usage)?;
        Ok((TorPath::new_one_hop_owned(&guard), mon, usable))
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
    use std::collections::HashSet;
    use tor_guardmgr::TestConfig;
    use tor_linkspec::RelayIds;
    use tor_netdir::testnet;
    use tor_persist::TestingStateMgr;

    #[test]
    fn dirpath() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let statemgr = TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            guards.install_test_netdir(&netdir);

            let mut distinct_guards = HashSet::new();

            // This is a nice easy case, since we tested the harder cases
            // in guard-spec.  We'll just have every path succeed.
            for _ in 0..40 {
                let (path, mon, usable) = DirPathBuilder::new().pick_path(&guards).unwrap();
                if let crate::path::TorPathInner::OwnedOneHop(relay) = path.inner {
                    distinct_guards.insert(RelayIds::from_relay_ids(&relay));
                    mon.succeeded();
                    assert!(usable.await.unwrap());
                } else {
                    panic!("Generated the wrong kind of path.");
                }
            }
            assert_eq!(
                distinct_guards.len(),
                netdir.params().guard_dir_use_parallelism.get() as usize
            );
        });
    }
}
