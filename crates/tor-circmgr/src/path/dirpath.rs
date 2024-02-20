//! Code to construct paths to a directory for non-anonymous downloads
use super::TorPath;
use crate::{DirInfo, Error, Result};
use tor_basic_utils::iter::FilterCount;
use tor_error::bad_api_usage;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_netdir::WeightRole;
use tor_rtcompat::Runtime;

use rand::Rng;

/// A PathBuilder that can connect to a directory.
#[non_exhaustive]
pub struct DirPathBuilder {}

impl Default for DirPathBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DirPathBuilder {
    /// Create a new DirPathBuilder.
    pub fn new() -> Self {
        DirPathBuilder {}
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        match (netdir, guards) {
            (_, Some(guardmgr)) => {
                // We use a guardmgr whenever we have one, regardless of whether
                // there's a netdir.
                //
                // That way, we prefer our guards (if they're up) before we default to the fallback directories.

                let guard_usage = tor_guardmgr::GuardUsageBuilder::default()
                    .kind(tor_guardmgr::GuardUsageKind::OneHopDirectory)
                    .build()
                    .expect("Unable to build directory guard usage");
                let (guard, mon, usable) = guardmgr.select_guard(guard_usage)?;
                Ok((TorPath::new_one_hop_owned(&guard), Some(mon), Some(usable)))
            }

            // In the following cases, we don't have a guardmgr, so we'll use the provided information if we can.
            (DirInfo::Fallbacks(f), None) => {
                let relay = f.choose(rng)?;
                Ok((TorPath::new_fallback_one_hop(relay), None, None))
            }
            (DirInfo::Directory(netdir), None) => {
                let mut can_share = FilterCount::default();
                let mut correct_usage = FilterCount::default();
                let relay = netdir
                    .pick_relay(rng, WeightRole::BeginDir, |r| {
                        r.is_flagged_fast()
                            && can_share.count(true)
                            && correct_usage.count(r.is_dir_cache())
                    })
                    .ok_or(Error::NoPath {
                        role: "directory cache",
                        can_share,
                        correct_usage,
                    })?;

                Ok((TorPath::new_one_hop(relay), None, None))
            }
            (DirInfo::Nothing, None) => Err(bad_api_usage!(
                "Tried to build a one hop path with no directory, fallbacks, or guard manager"
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::path::assert_same_path_when_owned;
    use crate::test::OptDummyGuardMgr;
    use std::collections::HashSet;
    use tor_basic_utils::test_rng::testing_rng;
    use tor_guardmgr::fallback::{FallbackDir, FallbackList};
    use tor_guardmgr::TestConfig;
    use tor_linkspec::RelayIds;
    use tor_netdir::testnet;

    #[test]
    fn dirpath_relay() {
        let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
        let mut rng = testing_rng();
        let dirinfo = (&netdir).into();
        let guards: OptDummyGuardMgr<'_> = None;

        for _ in 0..1000 {
            let p = DirPathBuilder::default().pick_path(&mut rng, dirinfo, guards);
            let (p, _, _) = p.unwrap();
            assert!(p.exit_relay().is_none());
            assert_eq!(p.len(), 1);
            assert_same_path_when_owned(&p);
            if let crate::path::TorPathInner::OneHop(r) = p.inner {
                assert!(r.is_dir_cache());
            } else {
                panic!("Generated the wrong kind of path.");
            }
        }
    }

    #[test]
    fn dirpath_fallback() {
        let fb_owned = vec![
            {
                let mut bld = FallbackDir::builder();
                bld.rsa_identity([0x01; 20].into())
                    .ed_identity([0x01; 32].into())
                    .orports()
                    .push("127.0.0.1:9000".parse().unwrap());
                bld.build().unwrap()
            },
            {
                let mut bld = FallbackDir::builder();
                bld.rsa_identity([0x03; 20].into())
                    .ed_identity([0x03; 32].into())
                    .orports()
                    .push("127.0.0.1:9003".parse().unwrap());
                bld.build().unwrap()
            },
        ];
        let fb: FallbackList = fb_owned.clone().into();
        let dirinfo = (&fb).into();
        let mut rng = testing_rng();
        let guards: OptDummyGuardMgr<'_> = None;

        for _ in 0..10 {
            let p = DirPathBuilder::default().pick_path(&mut rng, dirinfo, guards);
            let (p, _, _) = p.unwrap();
            assert!(p.exit_relay().is_none());
            assert_eq!(p.len(), 1);
            assert_same_path_when_owned(&p);

            if let crate::path::TorPathInner::FallbackOneHop(f) = p.inner {
                assert!(f == &fb_owned[0] || f == &fb_owned[1]);
            } else {
                panic!("Generated the wrong kind of path.");
            }
        }
    }

    #[test]
    fn dirpath_no_fallbacks() {
        let fb = FallbackList::from([]);
        let dirinfo = DirInfo::Fallbacks(&fb);
        let mut rng = testing_rng();
        let guards: OptDummyGuardMgr<'_> = None;

        let err = DirPathBuilder::default().pick_path(&mut rng, dirinfo, guards);
        dbg!(err.as_ref().err());
        assert!(matches!(
            err,
            Err(Error::Guard(
                tor_guardmgr::PickGuardError::NoCandidatesAvailable
            ))
        ));
    }

    #[test]
    fn dirpath_with_guards() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir().unwrap_if_sufficient().unwrap();
            let mut rng = testing_rng();
            let dirinfo = (&netdir).into();
            let statemgr = tor_persist::TestingStateMgr::new();
            let guards =
                tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, &TestConfig::default()).unwrap();
            guards.install_test_netdir(&netdir);

            let mut distinct_guards = HashSet::new();

            // This is a nice easy case, since we tested the harder cases
            // in guard-spec.  We'll just have every path succeed.
            for _ in 0..40 {
                let (path, mon, usable) = DirPathBuilder::new()
                    .pick_path(&mut rng, dirinfo, Some(&guards))
                    .unwrap();
                if let crate::path::TorPathInner::OwnedOneHop(relay) = path.inner {
                    distinct_guards.insert(RelayIds::from_relay_ids(&relay));
                    mon.unwrap().succeeded();
                    assert!(usable.unwrap().await.unwrap());
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
