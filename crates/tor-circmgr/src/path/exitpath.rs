//! Code for building paths to an exit relay.

use super::TorPath;
use crate::{DirInfo, Error, PathConfig, Result, TargetPort};
use rand::Rng;
use tor_netdir::{NetDir, Relay, SubnetConfig, WeightRole};

/// Internal representation of PathBuilder.
enum ExitPathBuilderInner<'a> {
    /// Request a path that allows exit to the given `TargetPort]`s.
    WantsPorts(Vec<TargetPort>),

    /// Request a path that allows exit to _any_ port.
    AnyExit {
        /// If false, then we fall back to non-exit nodes if we can't find an
        /// exit.
        strict: bool,
    },

    /// Request a path that uses a given relay as exit node.
    ChosenExit(Relay<'a>),
}

/// A PathBuilder that builds a path to an exit relay supporting a given
/// set of ports.
pub struct ExitPathBuilder<'a> {
    /// The inner ExitPathBuilder state.
    inner: ExitPathBuilderInner<'a>,
}

impl<'a> ExitPathBuilder<'a> {
    /// Create a new builder that will try to get an exit relay
    /// containing all the ports in `ports`.
    ///
    /// If the list of ports is empty, tries to get any exit relay at all.
    pub fn from_target_ports(wantports: impl IntoIterator<Item = TargetPort>) -> Self {
        let ports: Vec<TargetPort> = wantports.into_iter().collect();
        if ports.is_empty() {
            return Self::for_any_exit();
        }
        Self {
            inner: ExitPathBuilderInner::WantsPorts(ports),
        }
    }

    /// Create a new builder that will try to build a path with the given exit
    /// relay as the last hop.
    pub fn from_chosen_exit(exit_relay: Relay<'a>) -> Self {
        Self {
            inner: ExitPathBuilderInner::ChosenExit(exit_relay),
        }
    }

    /// Create a new builder that will try to get any exit relay at all.
    pub fn for_any_exit() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: true },
        }
    }

    /// Create a new builder that will try to get an exit relay, but which
    /// will be satisfied with a non-exit relay.
    pub(crate) fn for_timeout_testing() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: false },
        }
    }

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    fn pick_exit<R: Rng>(&self, rng: &mut R, netdir: &'a NetDir) -> Result<Relay<'a>> {
        match &self.inner {
            ExitPathBuilderInner::AnyExit { strict } => {
                let exit =
                    netdir.pick_relay(rng, WeightRole::Exit, Relay::policies_allow_some_port);
                match (exit, strict) {
                    (Some(exit), _) => return Ok(exit),
                    (None, true) => return Err(Error::NoRelays("No exit relay found".into())),
                    (None, false) => {}
                }

                // Non-strict case.  Arguably this doesn't belong in
                // ExitPathBuilder.
                netdir
                    .pick_relay(rng, WeightRole::Exit, |_| true)
                    .ok_or_else(|| Error::NoRelays("No relay found".into()))
            }

            ExitPathBuilderInner::WantsPorts(wantports) => Ok(netdir
                .pick_relay(rng, WeightRole::Exit, |r| {
                    wantports.iter().all(|p| p.is_supported_by(r))
                })
                .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?),

            ExitPathBuilderInner::ChosenExit(exit_relay) => Ok(exit_relay.clone()),
        }
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<R: Rng>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        config: &PathConfig,
    ) -> Result<TorPath<'a>> {
        // TODO: implement guards
        let netdir = match netdir {
            DirInfo::Fallbacks(_) => return Err(Error::NeedConsensus),
            DirInfo::Directory(d) => d,
        };
        let subnet_config = &config.enforce_distance;
        let exit = self.pick_exit(rng, netdir)?;

        let middle = netdir
            .pick_relay(rng, WeightRole::Middle, |r| {
                relays_can_share_circuit(r, &exit, subnet_config)
            })
            .ok_or_else(|| Error::NoRelays("No middle relay found".into()))?;

        let entry = netdir
            .pick_relay(rng, WeightRole::Guard, |r| {
                relays_can_share_circuit(r, &middle, subnet_config)
                    && relays_can_share_circuit(r, &exit, subnet_config)
            })
            .ok_or_else(|| Error::NoRelays("No entry relay found".into()))?;

        Ok(TorPath::new_multihop(vec![entry, middle, exit]))
    }
}

/// Returns true if both relays can appear together in the same circuit.
fn relays_can_share_circuit(a: &Relay<'_>, b: &Relay<'_>, subnet_config: &SubnetConfig) -> bool {
    // XXX: features missing from original implementation:
    // - option NodeFamilySets
    // see: src/feature/nodelist/nodelist.c:nodes_in_same_family()

    !a.in_same_family(b) && !a.in_same_subnet(b, subnet_config)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::path::{assert_same_path_when_owned, OwnedPath, TorPathInner};
    use std::convert::TryInto;
    use tor_linkspec::ChanTarget;
    use tor_netdir::testnet;

    fn assert_exit_path_ok(relays: &[Relay]) {
        assert_eq!(relays.len(), 3);

        // TODO: Eventually assert that r1 has Guard, once we enforce that.

        let r1 = &relays[0];
        let r2 = &relays[1];
        let r3 = &relays[2];

        assert!(r1.ed_identity() != r2.ed_identity());
        assert!(r1.ed_identity() != r3.ed_identity());
        assert!(r2.ed_identity() != r3.ed_identity());

        let subnet_config = SubnetConfig::default();
        assert!(relays_can_share_circuit(r1, r2, &subnet_config));
        assert!(relays_can_share_circuit(r1, r3, &subnet_config));
        assert!(relays_can_share_circuit(r2, r3, &subnet_config));
    }

    #[test]
    fn by_ports() {
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let ports = vec![TargetPort::ipv4(443), TargetPort::ipv4(1119)];
        let dirinfo = (&netdir).into();
        let config = PathConfig::default();

        for _ in 0..1000 {
            let path = ExitPathBuilder::from_target_ports(ports.clone())
                .pick_path(&mut rng, dirinfo, &config)
                .unwrap();

            assert_same_path_when_owned(&path);

            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert!(exit.ipv4_policy().allows_port(1119));
            } else {
                panic!("Generated the wrong kind of path");
            }
        }

        let chosen = netdir.by_id(&[0x20; 32].into()).unwrap();

        let config = PathConfig::default();
        for _ in 0..1000 {
            let path = ExitPathBuilder::from_chosen_exit(chosen.clone())
                .pick_path(&mut rng, dirinfo, &config)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert_eq!(exit.ed_identity(), chosen.ed_identity());
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
    }

    #[test]
    fn any_exit() {
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let dirinfo = (&netdir).into();

        let config = PathConfig::default();
        for _ in 0..1000 {
            let path = ExitPathBuilder::for_any_exit()
                .pick_path(&mut rng, dirinfo, &config)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert!(exit.policies_allow_some_port());
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
    }

    #[test]
    fn empty_path() {
        // This shouldn't actually be constructable IRL, but let's test to
        // make sure our code can handle it.
        let bogus_path = TorPath {
            inner: TorPathInner::Path(vec![]),
        };

        assert!(bogus_path.exit_relay().is_none());
        assert!(bogus_path.exit_policy().is_none());
        assert_eq!(bogus_path.len(), 0);

        let owned: Result<OwnedPath> = (&bogus_path).try_into();
        assert!(owned.is_err());
    }
}
