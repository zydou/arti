//! Manage a pool of circuits for usage with onion services.

use std::sync::Arc;

use crate::{CircMgr, Error, Result};
use futures::TryFutureExt;
use tor_error::{bad_api_usage, internal};
use tor_linkspec::OwnedCircTarget;
use tor_netdir::{NetDir, Relay};
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
}

impl<R: Runtime> HsCircPool<R> {
    /// Create a new `HsCircPool`.
    pub fn new(circmgr: &Arc<CircMgr<R>>) -> Self {
        let circmgr = Arc::clone(circmgr);
        Self { circmgr }
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
                // TODO HS: This will become possible once we have a circuit pool.
                None => Err(internal!("Generated a circuit with unknown last hop!?").into()),
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
        // TODO: Add a pool of unused circuits.  Right now we build everything on demand.

        self.circmgr.launch_hs_unmanaged(avoid_target, netdir).await
    }
}
