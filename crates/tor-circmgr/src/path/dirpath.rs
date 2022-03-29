//! Code to construct paths to a directory for non-anonymous downloads
use super::TorPath;
use crate::{DirInfo, Error, Result};
use tor_error::bad_api_usage;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_netdir::{Relay, WeightRole};
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
            (dirinfo, Some(guardmgr)) => {
                // We use a guardmgr whenever we have one, regardless of whether
                // there's a netdir.
                //
                // That way, we prefer our guards (if they're up) before we default to the fallback directories.
                let netdir = match dirinfo {
                    DirInfo::Directory(netdir) => {
                        guardmgr.update_network(netdir); // possibly unnecessary.
                        Some(netdir)
                    }
                    _ => None,
                };

                let guard_usage = tor_guardmgr::GuardUsageBuilder::default()
                    .kind(tor_guardmgr::GuardUsageKind::OneHopDirectory)
                    .build()
                    .expect("Unable to build directory guard usage");
                let (guard, mon, usable) = guardmgr.select_guard(guard_usage, netdir)?;
                return Ok((TorPath::new_one_hop_owned(&guard), Some(mon), Some(usable)));
            }

            // In the following cases, we don't have a guardmgr, so we'll use the provided information if we can.
            (DirInfo::Fallbacks(f), None) => {
                let relay = f.choose(rng)?;
                return Ok((TorPath::new_fallback_one_hop(relay), None, None));
            }
            (DirInfo::Directory(netdir), None) => {
                let relay = netdir.pick_relay(rng, WeightRole::BeginDir, Relay::is_dir_cache);
                if let Some(r) = relay {
                    return Ok((TorPath::new_one_hop(r), None, None));
                }
            }
            (DirInfo::Nothing, None) => {
                return Err(bad_api_usage!(
                    "Tried to build a one hop path with no directory, fallbacks, or guard manager"
                )
                .into());
            }
        }
        Err(Error::NoPath(
            "No relays found for use as directory cache".into(),
        ))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::clone_on_copy)]
    use super::*;
    use crate::path::assert_same_path_when_owned;
    use crate::test::OptDummyGuardMgr;
    use std::collections::HashSet;
    use tor_guardmgr::fallback::{FallbackDir, FallbackList};
    use tor_linkspec::ChanTarget;
    use tor_netdir::testnet;

    #[test]
    fn dirpath_relay() {
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let mut rng = rand::thread_rng();
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
            FallbackDir::builder()
                .rsa_identity([0x01; 20].into())
                .ed_identity([0x01; 32].into())
                .orport("127.0.0.1:9000".parse().unwrap())
                .build()
                .unwrap(),
            FallbackDir::builder()
                .rsa_identity([0x03; 20].into())
                .ed_identity([0x03; 32].into())
                .orport("127.0.0.1:9003".parse().unwrap())
                .build()
                .unwrap(),
        ];
        let fb: FallbackList = fb_owned.clone().into();
        let dirinfo = (&fb).into();
        let mut rng = rand::thread_rng();
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
        let mut rng = rand::thread_rng();
        let guards: OptDummyGuardMgr<'_> = None;

        let err = DirPathBuilder::default().pick_path(&mut rng, dirinfo, guards);
        dbg!(err.as_ref().err());
        assert!(matches!(
            err,
            Err(Error::Guard(
                tor_guardmgr::PickGuardError::AllFallbacksDown { .. }
            ))
        ));
    }

    #[test]
    fn dirpath_with_guards() {
        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir()
                .unwrap()
                .unwrap_if_sufficient()
                .unwrap();
            let mut rng = rand::thread_rng();
            let dirinfo = (&netdir).into();
            let statemgr = tor_persist::TestingStateMgr::new();
            let guards = tor_guardmgr::GuardMgr::new(rt.clone(), statemgr, [].into()).unwrap();
            guards.update_network(&netdir);

            let mut distinct_guards = HashSet::new();

            // This is a nice easy case, since we tested the harder cases
            // in guard-spec.  We'll just have every path succeed.
            for _ in 0..40 {
                let (path, mon, usable) = DirPathBuilder::new()
                    .pick_path(&mut rng, dirinfo, Some(&guards))
                    .unwrap();
                if let crate::path::TorPathInner::OwnedOneHop(relay) = path.inner {
                    distinct_guards.insert(relay.ed_identity().clone());
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
