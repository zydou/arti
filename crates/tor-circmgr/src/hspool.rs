//! Manage a pool of circuits for usage with onion services.
#![allow(dead_code)]

mod pool;

use std::sync::Arc;

use crate::{CircMgr, Error, Result};
use futures::TryFutureExt;
use tor_error::{bad_api_usage, internal};
use tor_linkspec::{OwnedChanTarget, OwnedCircTarget};
use tor_netdir::{NetDir, Relay, SubnetConfig};
use tor_proto::circuit::ClientCirc;
use tor_rtcompat::{Runtime, SleepProviderExt};

/// The (onion-service-related) purpose for which a given circuit is going to be
/// used.
///
/// We will use this to tell how the path for a given circuit is to be
/// constructed.
#[cfg(feature = "hs-common")]
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HsCircKind {
    /// Circuit from an onion service to an HsDir.
    SvcHsDir,
    /// Circuit from an onion service to an Introduction Point.
    SvcIntro,
    /// Circuit from an onion service to a Rendezvous Point.
    SvcRend,
    /// Circuit from an onion service client to an HsDir.
    ClientHsDir,
    /// Circuit from an onion service client to an Introduction Point.
    ClientIntro,
    /// Circuit from an onion service client to a Rendezvous Point.
    ClientRend,
}

/// An object to provide circuits for implementing onion services.
pub struct HsCircPool<R: Runtime> {
    /// An underlying circuit manager, used for constructing circuits.
    circmgr: Arc<CircMgr<R>>,
    /// A collection of pre-constructed circuits.
    pool: pool::Pool,
}

impl<R: Runtime> HsCircPool<R> {
    /// Create a new `HsCircPool`.
    pub fn new(circmgr: &Arc<CircMgr<R>>) -> Self {
        let circmgr = Arc::clone(circmgr);
        let pool = pool::Pool::default();
        Self { circmgr, pool }
    }

    /// Create a circuit suitable for use as a rendezvous circuit by a client.
    ///
    /// Return the circuit, along with a [`Relay`] from `netdir` representing its final hop.
    pub async fn get_or_launch_client_rend<'a>(
        &self,
        netdir: &'a NetDir,
    ) -> Result<(ClientCirc, Relay<'a>)> {
        // For rendezvous points, clients use 3-hop circuits.
        let circ = self.take_or_launch_stub_circuit(netdir, None).await?;
        let path = circ.path();
        match path.last() {
            Some(ct) => match netdir.by_ids(ct) {
                Some(relay) => Ok((circ, relay)),
                // This can't happen, since launch_hs_unmanaged() only takes relays from the netdir
                // it is given, and circuit_compatible_with_target() ensures that
                // every relay in the circuit is listed.
                //
                // TODO: Still, it's an ugly place in our API; maybe we should return the last hop
                // from take_or_launch_stub_circuit()?  But in many cases it won't be needed...
                None => Err(internal!("Got circuit with unknown last hop!?").into()),
            },
            None => Err(internal!("Circuit with an empty path!?").into()),
        }
    }

    /// Create a circuit suitable for use for `kind`, ending at the chosen hop `target`.
    pub async fn get_or_launch_specific(
        &self,
        netdir: &NetDir,
        kind: HsCircKind,
        target: OwnedCircTarget,
    ) -> Result<ClientCirc> {
        // The kind makes no difference yet, but it will at some point in the future.
        match kind {
            HsCircKind::ClientRend => {
                return Err(
                    bad_api_usage!("get_or_launch_specific with ClientRend circuit!?").into(),
                )
            }
            HsCircKind::SvcIntro => {
                // TODO HS: In this case we will want to add an extra hop, once we have vanguards.
                // When this happens, the whole match statement will want to become
                // let extra_hop = match kind {...}
            }
            HsCircKind::SvcHsDir
            | HsCircKind::SvcRend
            | HsCircKind::ClientHsDir
            | HsCircKind::ClientIntro => {}
        }

        // For most* of these circuit types, we want to build our circuit with
        // an extra hop, since the target hop is under somebody else's control.
        //
        // * The exceptions are ClientRend, which we handle in a different
        //   method, and SvcIntro, where we will eventually  want an extra hop
        //   to avoid vanguard discovery attacks.

        // Get an unfinished circuit that's compatible with our target.
        let circ = self
            .take_or_launch_stub_circuit(netdir, Some(&target))
            .await?;

        // Estimate how long it will take to extend it one more hop, and
        // construct a timeout as appropriate.
        let n_hops = circ.n_hops();
        let (extend_timeout, _) = self.circmgr.mgr.peek_builder().estimator().timeouts(
            &crate::timeouts::Action::ExtendCircuit {
                initial_length: n_hops,
                final_length: n_hops + 1,
            },
        );

        // Make a future to extend the circuit.
        let params = crate::DirInfo::from(netdir).circ_params();
        let extend_future = circ
            .extend_ntor(&target, &params)
            .map_err(|error| Error::Protocol {
                action: "extending to chosen HS hop",
                peer: None, // Either party could be to blame.
                error,
            });

        // Wait up to the timeout for the future to complete.
        self.circmgr
            .mgr
            .peek_runtime()
            .timeout(extend_timeout, extend_future)
            .await
            .map_err(|_| Error::CircTimeout)??;

        // With any luck, return the circuit.
        Ok(circ)
    }

    /// Take and return a circuit from our pool suitable for being extended to `avoid_target`.
    ///
    /// If there is no such circuit, build and return a new one.
    async fn take_or_launch_stub_circuit(
        &self,
        netdir: &NetDir,
        avoid_target: Option<&OwnedCircTarget>,
    ) -> Result<ClientCirc> {
        let mut rng = rand::thread_rng();
        let subnet_config = self.circmgr.builder().path_config().subnet_config();
        let target = avoid_target.map(|target| TargetInfo {
            target,
            relay: netdir.by_ids(target),
        });
        if let Some(circuit) = self.pool.take_one_where(&mut rng, |circ| {
            circuit_compatible_with_target(netdir, subnet_config, circ, target.as_ref())
        }) {
            return Ok(circuit);
        }

        // TODO: There is a possible optimization here. Instead of only waiting
        // for the circuit we launch to finish, we could also wait for any of
        // our preemptive circuits to finish.

        // TODO: We could in launch multiple circuits in parallel?

        self.circmgr.launch_hs_unmanaged(avoid_target, netdir).await
    }

    /// Internal: Remove every closed circuit from this pool.
    fn remove_closed(&self) {
        self.pool.retain(|circ| !circ.is_closing());
    }

    /// Internal: Remove every circuit form this pool for which any relay is not
    /// listed in `netdir`.
    fn remove_unlisted(&self, netdir: &NetDir) {
        self.pool
            .retain(|circ| all_circ_relays_are_listed_in(circ, netdir));
    }
}

/// Wrapper around a target final hop, and any information about that target we
/// were able to find from the directory.
///
/// TODO: This is possibly a bit redundant with path::MaybeOwnedRelay.  We
/// should consider merging them someday, once we have a better sense of what we
/// truly want here.
struct TargetInfo<'a> {
    /// The target to be used as a final hop.
    target: &'a OwnedCircTarget,
    /// A Relay reference for the targe, if we found one.
    relay: Option<Relay<'a>>,
}

impl<'a> TargetInfo<'a> {
    /// Return true if, according to the rules of `subnet_config`, this target can share a circuit with `r`.
    fn may_share_circuit_with(&self, r: &Relay<'_>, subnet_config: SubnetConfig) -> bool {
        if let Some(this_r) = &self.relay {
            if this_r.in_same_family(r) {
                return false;
            }
            // TODO: When bridge families are finally implemented (likely via
            // proposal `321-happy-families.md`), we should move family
            // functionality into CircTarget.
        }

        !subnet_config.any_addrs_in_same_subnet(self.target, r)
    }
}

/// Return true if we can extend a pre-built circuit `circ` to `target`.
///
/// We require that the circuit is open, that every hop  in the circuit is
/// listed in `netdir`, and that no hop in the circuit shares a family with
/// `target`.
fn circuit_compatible_with_target(
    netdir: &NetDir,
    subnet_config: SubnetConfig,
    circ: &ClientCirc,
    target: Option<&TargetInfo<'_>>,
) -> bool {
    if circ.is_closing() {
        return false;
    }

    // TODO HS: I don't like having to copy the whole path out at this point; it
    // seems like that could get expensive. -nickm

    let path = circ.path();
    path.iter().all(|c: &OwnedChanTarget| {
        match (target, netdir.by_ids(c)) {
            // We require that every relay in this circuit is still listed; an
            // unlisted relay means "reject".
            (_, None) => false,
            // If we have a target, the relay must be compatible with it.
            (Some(t), Some(r)) => t.may_share_circuit_with(&r, subnet_config),
            // If we have no target, any listed relay is okay.
            (None, Some(_)) => true,
        }
    })
}

/// Return true if  every relay in `circ` is listed in `netdir`.
fn all_circ_relays_are_listed_in(circ: &ClientCirc, netdir: &NetDir) -> bool {
    // TODO HS: Again, I don't like having to copy the whole path out at this point.
    let path = circ.path();

    // TODO HS: Are there any other checks we should do before declaring that
    // this is still usable?

    // TODO HS: THere is some duplicate logic here and in
    // circuit_compatible_with_target.  I think that's acceptable for now, but
    // we should consider refactoring if these functions grow.
    path.iter()
        .all(|c: &OwnedChanTarget| netdir.by_ids(c).is_some())
}
