//! Code to construct paths to a directory for non-anonymous downloads
use super::TorPath;
use crate::{DirInfo, Error, Result};
use tor_netdir::{Relay, WeightRole};

use rand::{seq::SliceRandom, Rng};

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
    pub fn pick_path<'a, R: Rng>(&self, rng: &mut R, netdir: DirInfo<'a>) -> Result<TorPath<'a>> {
        // TODO: this will need to learn about directory guards.
        match netdir {
            DirInfo::Fallbacks(f) => {
                let relay = f.choose(rng);
                if let Some(r) = relay {
                    return Ok(TorPath::new_fallback_one_hop(r));
                }
            }
            DirInfo::Directory(netdir) => {
                let relay = netdir.pick_relay(rng, WeightRole::BeginDir, Relay::is_dir_cache);
                if let Some(r) = relay {
                    return Ok(TorPath::new_one_hop(r));
                }
            }
        }
        Err(Error::NoRelays(
            "No relays found for use as directory cache".into(),
        ))
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::path::assert_same_path_when_owned;
    use tor_netdir::fallback::FallbackDir;
    use tor_netdir::testnet;

    #[test]
    fn dirpath_relay() {
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let mut rng = rand::thread_rng();
        let dirinfo = (&netdir).into();

        for _ in 0..1000 {
            let p = DirPathBuilder::default().pick_path(&mut rng, dirinfo);
            let p = p.unwrap();
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
        let fb = vec![
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
        let dirinfo = (&fb[..]).into();
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let p = DirPathBuilder::default().pick_path(&mut rng, dirinfo);
            let p = p.unwrap();
            assert!(p.exit_relay().is_none());
            assert_eq!(p.len(), 1);
            assert_same_path_when_owned(&p);

            if let crate::path::TorPathInner::FallbackOneHop(f) = p.inner {
                assert!(std::ptr::eq(f, &fb[0]) || std::ptr::eq(f, &fb[1]));
            } else {
                panic!("Generated the wrong kind of path.");
            }
        }
    }

    #[test]
    fn dirpath_no_fallbacks() {
        let fb = vec![];
        let dirinfo = DirInfo::Fallbacks(&fb[..]);
        let mut rng = rand::thread_rng();

        let err = DirPathBuilder::default().pick_path(&mut rng, dirinfo);
        assert!(matches!(err, Err(Error::NoRelays(_))));
    }
}
