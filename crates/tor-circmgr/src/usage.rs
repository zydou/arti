//! Code related to tracking what activities a circuit can be used for.

use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, TorPath};
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_netdir::Relay;
use tor_netdoc::types::policy::PortPolicy;
use tor_rtcompat::Runtime;

use crate::{Error, Result};

/// An exit policy, as supported by the last hop of a circuit.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExitPolicy {
    /// Permitted IPv4 ports.
    v4: Arc<PortPolicy>,
    /// Permitted IPv6 ports.
    v6: Arc<PortPolicy>,
}

/// A port that we want to connect to as a client.
///
/// Ordinarily, this is a TCP port, plus a flag to indicate whether we
/// must support IPv4 or IPv6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPort {
    /// True if this is a request to connect to an IPv6 address
    ipv6: bool,
    /// The port that the client wants to connect to
    port: u16,
}

impl TargetPort {
    /// Create a request to make sure that a circuit supports a given
    /// ipv4 exit port.
    pub fn ipv4(port: u16) -> TargetPort {
        TargetPort { ipv6: false, port }
    }

    /// Create a request to make sure that a circuit supports a given
    /// ipv6 exit port.
    pub fn ipv6(port: u16) -> TargetPort {
        TargetPort { ipv6: true, port }
    }

    /// Return true if this port is supported by the provided Relay.
    pub fn is_supported_by(&self, r: &tor_netdir::Relay<'_>) -> bool {
        if self.ipv6 {
            r.supports_exit_port_ipv6(self.port)
        } else {
            r.supports_exit_port_ipv4(self.port)
        }
    }
}

/// A token used to isolate unrelated streams on different circuits.
///
/// When two streams are associated with different isolation tokens, they
/// can never share the same circuit.
///
/// Tokens created with [`IsolationToken::new`] are all different from
/// one another, and different from tokens created with
/// [`IsolationToken::no_isolation`]. However, tokens created with
/// [`IsolationToken::no_isolation`] are all equal to one another.
///
/// # Examples
///
/// Creating distinct isolation tokens:
///
/// ```rust
/// # use tor_circmgr::IsolationToken;
/// let token_1 = IsolationToken::new();
/// let token_2 = IsolationToken::new();
///
/// assert_ne!(token_1, token_2);
///
/// // Demonstrating the behaviour of no_isolation() tokens:
/// assert_ne!(token_1, IsolationToken::no_isolation());
/// assert_eq!(IsolationToken::no_isolation(), IsolationToken::no_isolation());
/// ```
///
/// Using an isolation token to route streams differently over the Tor network:
///
/// ```ignore
/// use arti_client::ConnectPrefs;
///
/// let token_1 = IsolationToken::new();
/// let token_2 = IsolationToken::new();
///
/// let mut prefs_1 = ConnectPrefs::new();
/// prefs_1.set_isolation_group(token_1);
///
/// let mut prefs_2 = ConnectPrefs::new();
/// prefs_2.set_isolation_group(token_2);
///
/// // These two connections will come from different source IP addresses.
/// tor_client.connect(("example.com", 80), Some(prefs_1)).await?;
/// tor_client.connect(("example.com", 80), Some(prefs_2)).await?;
/// ```
// # Semver note
//
// This type is re-exported by `arti-client`: any changes to it must be
// reflected in `arti-client`'s version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsolationToken(u64);

#[allow(clippy::new_without_default)]
impl IsolationToken {
    /// Create a new IsolationToken, unequal to any other token this function
    /// has created.
    ///
    /// # Panics
    ///
    /// Panics if we have already allocated 2^64 isolation tokens: in that
    /// case, we have exhausted the space of possible tokens, and it is
    /// no longer possible to ensure isolation.
    pub fn new() -> Self {
        /// Internal counter used to generate different tokens each time
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        // Ordering::Relaxed is fine because we don't care about causality, we just want a
        // different number each time
        let token = COUNTER.fetch_add(1, Ordering::Relaxed);
        assert!(token < u64::MAX);
        IsolationToken(token)
    }

    /// Create a new IsolationToken equal to every other token created
    /// with this function, but different from all tokens created with
    /// `new`.
    ///
    /// This can be used when no isolation is wanted for some streams.
    pub fn no_isolation() -> Self {
        IsolationToken(0)
    }
}

/// A set of information about how a stream should be isolated.
///
/// If two streams are isolated from one another, they may not share
/// a circuit.
#[derive(Copy, Clone, Eq, Debug, PartialEq, derive_builder::Builder)]
pub struct StreamIsolation {
    /// Any isolation token set on the stream.
    #[builder(default = "IsolationToken::no_isolation()")]
    stream_token: IsolationToken,
    /// Any additional isolation token set on an object that "owns" this
    /// stream.  This is typically owned by a `TorClient`.
    #[builder(default = "IsolationToken::no_isolation()")]
    owner_token: IsolationToken,
}

impl StreamIsolation {
    /// Construct a new StreamIsolation with no isolation enabled.
    pub fn no_isolation() -> Self {
        StreamIsolationBuilder::new()
            .build()
            .expect("Bug constructing StreamIsolation")
    }

    /// Return a new StreamIsolationBuilder for constructing
    /// StreamIsolation objects.
    pub fn builder() -> StreamIsolationBuilder {
        StreamIsolationBuilder::new()
    }
}

impl StreamIsolationBuilder {
    /// Construct a builder with no items set.
    pub fn new() -> Self {
        StreamIsolationBuilder::default()
    }
}

impl ExitPolicy {
    /// Make a new exit policy from a given Relay.
    pub(crate) fn from_relay(relay: &Relay<'_>) -> Self {
        Self {
            v4: relay.ipv4_policy(),
            v6: relay.ipv6_policy(),
        }
    }

    /// Return true if a given port is contained in this ExitPolicy.
    fn allows_port(&self, p: TargetPort) -> bool {
        let policy = if p.ipv6 { &self.v6 } else { &self.v4 };
        policy.allows_port(p.port)
    }

    /// Returns true if this policy allows any ports at all.
    fn allows_some_port(&self) -> bool {
        self.v4.allows_some_port() || self.v6.allows_some_port()
    }
}

/// The purpose for which a circuit is being created.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug)]
pub(crate) enum TargetCircUsage {
    /// Use for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Use to exit to one or more ports.
    Exit {
        /// List of ports the circuit has to allow.
        ///
        /// If this list of ports is empty, then the circuit doesn't need
        /// to support any particular port, but it still needs to be an exit.
        ports: Vec<TargetPort>,
        /// Isolation group the circuit shall be part of
        isolation: StreamIsolation,
    },
    /// For a circuit is only used for the purpose of building it.
    TimeoutTesting,
}

/// The purposes for which a circuit is usable.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SupportedCircUsage {
    /// Useable for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Usable to exit to a set of ports.
    Exit {
        /// Exit policy of the circuit
        policy: ExitPolicy,
        /// Isolation group the circuit is part of. None when the circuit is not yet assigned to an
        /// isolation group.
        isolation: Option<StreamIsolation>,
    },
    /// This circuit is not suitable for any usage.
    NoUsage,
}

impl TargetCircUsage {
    /// Construct path for a given circuit purpose; return it and the
    /// usage that it _actually_ supports.
    pub(crate) fn build_path<'a, R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: crate::DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        config: &crate::PathConfig,
    ) -> Result<(
        TorPath<'a>,
        SupportedCircUsage,
        Option<GuardMonitor>,
        Option<GuardUsable>,
    )> {
        match self {
            TargetCircUsage::Dir => {
                let (path, mon, usable) = DirPathBuilder::new().pick_path(rng, netdir, guards)?;
                Ok((path, SupportedCircUsage::Dir, mon, usable))
            }
            TargetCircUsage::Exit {
                ports: p,
                isolation,
            } => {
                let (path, mon, usable) = ExitPathBuilder::from_target_ports(p.clone())
                    .pick_path(rng, netdir, guards, config)?;
                let policy = path
                    .exit_policy()
                    .expect("ExitPathBuilder gave us a one-hop circuit?");
                Ok((
                    path,
                    SupportedCircUsage::Exit {
                        policy,
                        isolation: Some(*isolation),
                    },
                    mon,
                    usable,
                ))
            }
            TargetCircUsage::TimeoutTesting => {
                let (path, mon, usable) = ExitPathBuilder::for_timeout_testing()
                    .pick_path(rng, netdir, guards, config)?;
                let policy = path.exit_policy();
                let usage = match policy {
                    Some(policy) if policy.allows_some_port() => SupportedCircUsage::Exit {
                        policy,
                        isolation: None,
                    },
                    _ => SupportedCircUsage::NoUsage,
                };

                Ok((path, usage, mon, usable))
            }
        }
    }
}

impl crate::mgr::AbstractSpec for SupportedCircUsage {
    type Usage = TargetCircUsage;

    fn supports(&self, target: &TargetCircUsage) -> bool {
        use SupportedCircUsage::*;
        match (self, target) {
            (Dir, TargetCircUsage::Dir) => true,
            (
                Exit {
                    policy: p1,
                    isolation: i1,
                },
                TargetCircUsage::Exit {
                    ports: p2,
                    isolation: i2,
                },
            ) => {
                i1.map(|i1| i1 == *i2).unwrap_or(true)
                    && p2.iter().all(|port| p1.allows_port(*port))
            }
            (Exit { .. } | NoUsage, TargetCircUsage::TimeoutTesting) => true,
            (_, _) => false,
        }
    }

    fn restrict_mut(&mut self, usage: &TargetCircUsage) -> Result<()> {
        use SupportedCircUsage::*;

        match (self, usage) {
            (Dir, TargetCircUsage::Dir) => Ok(()),
            (
                Exit {
                    isolation: ref mut i1,
                    ..
                },
                TargetCircUsage::Exit { isolation: i2, .. },
            ) if i1.map(|i1| i1 == *i2).unwrap_or(true) => {
                *i1 = Some(*i2);
                Ok(())
            }
            (Exit { .. }, TargetCircUsage::Exit { .. }) => {
                Err(Error::UsageNotSupported("Bad isolation".into()))
            }
            (Exit { .. } | NoUsage, TargetCircUsage::TimeoutTesting) => Ok(()),
            (_, _) => Err(Error::UsageNotSupported("Incompatible usage".into())),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::test::OptDummyGuardMgr;
    use tor_netdir::testnet;

    #[test]
    fn exit_policy() {
        let network = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();

        // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
        // exits.  Odd-numbered ones allow only ports 80 and 443;
        // even-numbered ones allow all ports.
        let id_noexit = [0x05; 32].into();
        let id_webexit = [0x11; 32].into();
        let id_fullexit = [0x20; 32].into();

        let not_exit = network.by_id(&id_noexit).unwrap();
        let web_exit = network.by_id(&id_webexit).unwrap();
        let full_exit = network.by_id(&id_fullexit).unwrap();

        let ep_none = ExitPolicy::from_relay(&not_exit);
        let ep_web = ExitPolicy::from_relay(&web_exit);
        let ep_full = ExitPolicy::from_relay(&full_exit);

        assert!(!ep_none.allows_port(TargetPort::ipv4(80)));
        assert!(!ep_none.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_web.allows_port(TargetPort::ipv4(80)));
        assert!(ep_web.allows_port(TargetPort::ipv4(443)));
        assert!(!ep_web.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_full.allows_port(TargetPort::ipv4(80)));
        assert!(ep_full.allows_port(TargetPort::ipv4(443)));
        assert!(ep_full.allows_port(TargetPort::ipv4(9999)));

        // Note that nobody in the testdir::network allows ipv6.
        assert!(!ep_none.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_web.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_full.allows_port(TargetPort::ipv6(80)));

        // Check is_supported_by while we're here.
        // TODO: Make sure that if BadExit is set, this function returns no
        assert!(TargetPort::ipv4(80).is_supported_by(&web_exit));
        assert!(!TargetPort::ipv6(80).is_supported_by(&web_exit));
    }

    #[test]
    fn usage_ops() {
        use crate::mgr::AbstractSpec;
        // Make an exit-policy object that allows web on IPv4 and
        // smtp on IPv6.
        let policy = ExitPolicy {
            v4: Arc::new("accept 80,443".parse().unwrap()),
            v6: Arc::new("accept 23".parse().unwrap()),
        };
        let tok1 = IsolationToken::new();
        let tok2 = IsolationToken::new();
        let isolation = StreamIsolationBuilder::new()
            .owner_token(tok1)
            .build()
            .unwrap();
        let isolation2 = StreamIsolationBuilder::new()
            .owner_token(tok2)
            .build()
            .unwrap();

        let supp_dir = SupportedCircUsage::Dir;
        let targ_dir = TargetCircUsage::Dir;
        let supp_exit = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation: Some(isolation),
        };
        let supp_exit_iso2 = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation: Some(isolation2),
        };
        let supp_exit_no_iso = SupportedCircUsage::Exit {
            policy,
            isolation: None,
        };
        let targ_80_v4 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation,
        };
        let targ_80_v4_iso2 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation: isolation2,
        };
        let targ_80_23_v4 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80), TargetPort::ipv4(23)],
            isolation,
        };
        let targ_80_23_mixed = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80), TargetPort::ipv6(23)],
            isolation,
        };
        let targ_999_v6 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv6(999)],
            isolation,
        };

        assert!(supp_dir.supports(&targ_dir));
        assert!(!supp_dir.supports(&targ_80_v4));
        assert!(!supp_exit.supports(&targ_dir));
        assert!(supp_exit.supports(&targ_80_v4));
        assert!(!supp_exit.supports(&targ_80_v4_iso2));
        assert!(supp_exit.supports(&targ_80_23_mixed));
        assert!(!supp_exit.supports(&targ_80_23_v4));
        assert!(!supp_exit.supports(&targ_999_v6));
        assert!(!supp_exit_iso2.supports(&targ_80_v4));
        assert!(supp_exit_iso2.supports(&targ_80_v4_iso2));
        assert!(supp_exit_no_iso.supports(&targ_80_v4));
        assert!(supp_exit_no_iso.supports(&targ_80_v4_iso2));
        assert!(!supp_exit_no_iso.supports(&targ_80_23_v4));
    }

    #[test]
    fn restrict_mut() {
        use crate::mgr::AbstractSpec;

        let policy = ExitPolicy {
            v4: Arc::new("accept 80,443".parse().unwrap()),
            v6: Arc::new("accept 23".parse().unwrap()),
        };

        let tok1 = IsolationToken::new();
        let tok2 = IsolationToken::new();
        let isolation = StreamIsolationBuilder::new()
            .owner_token(tok1)
            .build()
            .unwrap();
        let isolation2 = StreamIsolationBuilder::new()
            .owner_token(tok2)
            .build()
            .unwrap();

        let supp_dir = SupportedCircUsage::Dir;
        let targ_dir = TargetCircUsage::Dir;
        let supp_exit = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation: Some(isolation),
        };
        let supp_exit_iso2 = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation: Some(isolation2),
        };
        let supp_exit_no_iso = SupportedCircUsage::Exit {
            policy,
            isolation: None,
        };
        let targ_exit = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation,
        };
        let targ_exit_iso2 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation: isolation2,
        };

        // not allowed, do nothing
        let mut supp_dir_c = supp_dir.clone();
        assert!(supp_dir_c.restrict_mut(&targ_exit).is_err());
        assert_eq!(supp_dir, supp_dir_c);

        let mut supp_exit_c = supp_exit.clone();
        assert!(supp_exit_c.restrict_mut(&targ_dir).is_err());
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_c = supp_exit.clone();
        assert!(supp_exit_c.restrict_mut(&targ_exit_iso2).is_err());
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_iso2_c = supp_exit_iso2.clone();
        assert!(supp_exit_iso2_c.restrict_mut(&targ_exit).is_err());
        assert_eq!(supp_exit_iso2, supp_exit_iso2_c);

        // allowed but nothing to do
        let mut supp_dir_c = supp_dir.clone();
        supp_dir_c.restrict_mut(&targ_dir).unwrap();
        assert_eq!(supp_dir, supp_dir_c);

        let mut supp_exit_c = supp_exit.clone();
        supp_exit_c.restrict_mut(&targ_exit).unwrap();
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_iso2_c = supp_exit_iso2.clone();
        supp_exit_iso2_c.restrict_mut(&targ_exit_iso2).unwrap();
        assert_eq!(supp_exit_iso2, supp_exit_iso2_c);

        // allowed, do something
        let mut supp_exit_no_iso_c = supp_exit_no_iso.clone();
        supp_exit_no_iso_c.restrict_mut(&targ_exit).unwrap();
        assert!(supp_exit_no_iso_c.supports(&targ_exit));
        assert!(!supp_exit_no_iso_c.supports(&targ_exit_iso2));

        let mut supp_exit_no_iso_c = supp_exit_no_iso;
        supp_exit_no_iso_c.restrict_mut(&targ_exit_iso2).unwrap();
        assert!(!supp_exit_no_iso_c.supports(&targ_exit));
        assert!(supp_exit_no_iso_c.supports(&targ_exit_iso2));
    }

    #[test]
    fn buildpath() {
        use crate::mgr::AbstractSpec;
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let di = (&netdir).into();
        let config = crate::PathConfig::default();
        let guards: OptDummyGuardMgr<'_> = None;

        // Only doing basic tests for now.  We'll test the path
        // building code a lot more closely in the tests for TorPath
        // and friends.
        let (p_dir, u_dir, _, _) = TargetCircUsage::Dir
            .build_path(&mut rng, di, guards, &config)
            .unwrap();
        assert!(matches!(u_dir, SupportedCircUsage::Dir));
        assert_eq!(p_dir.len(), 1);

        let tok1 = IsolationToken::new();
        let isolation = StreamIsolationBuilder::new()
            .owner_token(tok1)
            .build()
            .unwrap();

        let exit_usage = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(995)],
            isolation,
        };
        let (p_exit, u_exit, _, _) = exit_usage
            .build_path(&mut rng, di, guards, &config)
            .unwrap();
        assert!(matches!(
            u_exit,
            SupportedCircUsage::Exit {
                isolation: iso,
                ..
            } if iso == Some(isolation)
        ));
        assert!(u_exit.supports(&exit_usage));
        assert_eq!(p_exit.len(), 3);
    }
}
