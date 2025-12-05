//! Code related to tunnel object that wraps the tor-proto tunnel.
//!
//! These tunnel types are part of the public API.

use derive_deftly::{Deftly, define_derive_deftly};
use std::{net::IpAddr, sync::Arc};

use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_error::internal;
use tor_linkspec::{CircTarget, IntoOwnedChanTarget, OwnedChanTarget};
use tor_proto::{
    ClockSkew, TargetHop,
    circuit::UniqId,
    client::circuit::{CircParameters, CircuitBinding, ClientCirc},
    client::stream::{DataStream, StreamParameters},
};
use tracing::instrument;

use crate::{Error, Result};

#[cfg(feature = "hs-common")]
use tor_proto::client::circuit::handshake;

// The tunnel base methods. This MUST be derived on all tunnel types.
define_derive_deftly! {
    BaseTunnel for struct:

    impl From<tor_proto::ClientTunnel> for $ttype {
        fn from(tunnel: tor_proto::ClientTunnel) -> Self {
            Self { tunnel: Arc::new(tunnel) }
        }
    }

    impl From<Arc<tor_proto::ClientTunnel>> for $ttype {
        fn from(tunnel: Arc<tor_proto::ClientTunnel>) -> Self {
            Self { tunnel }
        }
    }

    impl AsRef<tor_proto::ClientTunnel> for $ttype {
        fn as_ref(&self) -> &tor_proto::ClientTunnel {
            self.tunnel.as_ref()
        }
    }

    impl $ttype {
        /// Return a reference to the underlying tunnel.
        ///
        /// Note: The "tunnel" name is hardcoded here. If it becomes an annoyance, we could make it
        /// as a meta value of the deftly declaration.
        fn tunnel_ref(&self) -> &Arc<tor_proto::ClientTunnel> {
            &self.tunnel
        }

        /// Return true if this tunnel is closed and therefore unusable.
        pub fn is_closed(&self) -> bool {
            self.tunnel_ref().is_closed()
        }

        /// Return a [`TargetHop`] representing precisely the last hop of the circuit as in set as a
        /// HopLocation with its id and hop number.
        ///
        /// Return an error if there is no last hop.
        pub fn last_hop(&self) -> Result<TargetHop> {
            self.tunnel_ref().last_hop()
                .map_err(|error| Error::Protocol {
                    action: "get last hop",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }

        /// Shutdown the tunnel meaning this sends a shutdown command to the underlying circuit
        /// reactor which will stop asynchronously.
        ///
        /// Note that it is not necessary to use this method as in if the tunnel reference is
        /// dropped, the circuit will close automatically.
        pub fn terminate(&self) {
            self.tunnel_ref().terminate();
        }

        /// Return a process-unique identifier for this tunnel.
        pub fn unique_id(&self) -> UniqId {
            self.tunnel_ref().unique_id()
        }

        /// Send raw message.
        #[cfg(feature = "send-control-msg")]
        pub async fn send_raw_msg(&self, msg: AnyRelayMsg, hop: TargetHop) -> Result<()> {
            self.tunnel_ref()
                .send_raw_msg(msg, hop)
                .await
                .map_err(|error| Error::Protocol {
                    action: "send raw msg",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }

        /// Start an ad-hoc protocol exchange to the specified hop on this tunnel.
        ///
        /// See [`ClientTunnel::start_conversation`](tor_proto::ClientTunnel::start_conversation)
        /// documentation for more details.
        #[cfg(feature = "send-control-msg")]
        pub async fn start_conversation(&self,
            msg: Option<tor_cell::relaycell::msg::AnyRelayMsg>,
            reply_handler: impl tor_proto::MsgHandler + Send + 'static,
            hop: TargetHop
        ) -> Result<tor_proto::Conversation<'_>> {
            self.tunnel_ref().start_conversation(msg, reply_handler, hop).await
                .map_err(|error| Error::Protocol {
                    action: "start conversation",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel_ref().unique_id()),
                })
        }

        /// Return a future that will resolve once this circuit has closed.
        ///
        /// Note that this method does not itself cause the circuit to shut down.
        ///
        // TODO: Perhaps this should return some kind of status indication instead
        // of just ()
        pub fn wait_for_close(&self) -> impl futures::Future<Output = ()> + Send + Sync + 'static + use<> {
            self.tunnel_ref().wait_for_close()
        }

        // TODO(conflux): mq_account() is not needed because it is only used internally in a ClientCirc
        // in order to open streams. It might be the case that we need at some point to get the
        // CircuitAccount(s) from a tunnel. We would need then to either have a TunnelAccount or return
        // a Vec<CircuitAccount>.
    }
}

// Methods for a single path tunnel.
define_derive_deftly! {
    SinglePathTunnel for struct:

    impl $ttype {
        /// Return a reference to the circuit of this tunnel.
        fn circuit(&self) -> Result<&ClientCirc> {
            Ok(self.tunnel_ref()
                .as_single_circ()
                .map_err(|e| internal!("Non single path in a single path tunnel: {}", e))?)
        }

        /// Extend the circuit to a new target last hop using the ntor v3 handshake.
        ///
        /// TODO: Might want to pass which handshake type as a parameter so this function can be a
        /// catch all on all possible handshakes. For now, use ntor v3 for all the things.
        pub async fn extend<T: CircTarget>(&self, target: &T, params: CircParameters) -> Result<()> {
            self.circuit()?
                .extend(target, params)
                .await
                .map_err(|error| Error::Protocol {
                    action: "extend tunnel",
                    peer: Some(target.to_owned().to_logged()),
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }

        /// Return the number of hops of the underlying circuit.
        pub fn n_hops(&self) -> Result<usize> {
            self.circuit()?.n_hops()
                .map_err(|error| Error::Protocol {
                    action: "get number hops",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel_ref().unique_id()),
                })
        }

    }
}

// Methods for a multi path tunnel.
#[cfg(feature = "conflux")]
define_derive_deftly! {
    MultiPathTunnel for struct:

    impl $ttype {
        // TODO(conflux)
        //
        // As we add multi path support accross the code, we'll might need or not some specific
        // functions that would go here.
    }
}

// Methods for a tunnel that can transmit data (BEGIN).
define_derive_deftly! {
    DataTunnel for struct:

    impl $ttype {
        /// Start a stream to the given address and port, using a BEGIN cell.
        ///
        /// The use of a string for the address is intentional: you should let
        /// the remote Tor relay do the hostname lookup for you.
        #[instrument(skip_all, level = "trace")]
        pub async fn begin_stream(
            &self,
            target: &str,
            port: u16,
            params: Option<StreamParameters>,
        ) -> Result<DataStream> {
            self.tunnel_ref()
                .begin_stream(target, port, params)
                .await
                .map_err(|error| Error::Protocol {
                    action: "begin stream",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }
    }

}

// Methods for a tunnel that can do DNS resolution (RESOLVE).
define_derive_deftly! {
    DnsTunnel for struct:

    impl $ttype {
        /// Perform a DNS lookup, using a RESOLVE cell with the last relay in this circuit.
        ///
        /// Note that this function does not check for timeouts; that's the caller's responsibility.
        pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
            self.tunnel_ref()
                .resolve(hostname)
                .await
                .map_err(|error| Error::Protocol {
                    action: "resolve",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }

        /// Perform a reverse DNS lookup, using a RESOLVE cell with the last relay in this circuit.
        ///
        /// Note that this function does not check for timeouts; that's the caller's responsibility.
        pub async fn resolve_ptr(&self, addr: IpAddr) -> Result<Vec<String>> {
            self.tunnel_ref()
                .resolve_ptr(addr)
                .await
                .map_err(|error| Error::Protocol {
                    action: "resolve PTR",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }
    }
}

// Methods for a tunnel that can do directory requests (BEGIN_DIR).
define_derive_deftly! {
    DirTunnel for struct:

    impl $ttype {
        /// Start a stream to the given address and port, using a BEGIN_DIR cell.
        pub async fn begin_dir_stream(&self) -> Result<DataStream> {
            self.tunnel_ref().clone()
                .begin_dir_stream()
                .await
                .map_err(|error| Error::Protocol {
                    action: "begin dir stream",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }
    }
}

// Methods for a tunnel that can transmit data (BEGIN).
define_derive_deftly! {
    OnionServiceDataTunnel for struct:

    impl $ttype {
        /// Extend this circuit by a single, "virtual" hop.
        ///
        /// A virtual hop is one for which we do not add an actual network connection
        /// between separate hosts (such as Relays).  We only add a layer of
        /// cryptography.
        ///
        /// This is used to implement onion services: the client and the service
        /// both build a circuit to a single rendezvous point, and tell the
        /// rendezvous point to relay traffic between their two circuits.  Having
        /// completed a [`handshake`] out of band[^1], the parties each extend their
        /// circuits by a single "virtual" encryption hop that represents their
        /// shared cryptographic context.
        ///
        /// Once a circuit has been extended in this way, it is an error to try to
        /// extend it in any other way.
        ///
        /// [^1]: Technically, the handshake is only _mostly_ out of band: the
        ///     client sends their half of the handshake in an ` message, and the
        ///     service's response is inline in its `RENDEZVOUS2` message.
        //
        // TODO hs: let's try to enforce the "you can't extend a circuit again once
        // it has been extended this way" property.  We could do that with internal
        // state, or some kind of a type state pattern.
        //
        // TODO hs: possibly we should take a set of Protovers, and not just `Params`.
        #[cfg(feature = "hs-common")]
        pub async fn extend_virtual(
            &self,
            protocol: handshake::RelayProtocol,
            role: handshake::HandshakeRole,
            seed: impl handshake::KeyGenerator,
            params: CircParameters,
            capabilities: &tor_protover::Protocols,
        ) -> Result<()> {
            self.circuit()?
                .extend_virtual(protocol, role, seed, &params, capabilities)
                .await
                .map_err(|error| Error::Protocol {
                    action: "extend virtual tunnel",
                    peer: None,
                    error,
                    unique_id: Some(self.tunnel.unique_id()),
                })
        }
    }

}

/// A client single path data tunnel.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, DnsTunnel, SinglePathTunnel)]
pub struct ClientDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client directory tunnel. This is always single path.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DirTunnel, SinglePathTunnel)]
pub struct ClientDirTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client onion service single path data tunnel.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, OnionServiceDataTunnel, SinglePathTunnel)]
pub struct ClientOnionServiceDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client onion service directory tunnel (to an HSDir). This is always single path.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DirTunnel, SinglePathTunnel)]
pub struct ClientOnionServiceDirTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client onion service introduction tunnel. This is always single path.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, SinglePathTunnel)]
pub struct ClientOnionServiceIntroTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A service onion service single path data tunnel.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, OnionServiceDataTunnel, SinglePathTunnel)]
pub struct ServiceOnionServiceDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A service onion service directory tunnel (to an HSDir). This is always single path.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DirTunnel, SinglePathTunnel)]
pub struct ServiceOnionServiceDirTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A service onion service introduction tunnel. This is always single path.
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, SinglePathTunnel)]
pub struct ServiceOnionServiceIntroTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client multi path data tunnel (Conflux).
#[cfg(feature = "conflux")]
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, DnsTunnel, MultiPathTunnel)]
pub struct ClientMultiPathDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A client multi path onion service data tunnel (Conflux, Rendeszvous).
#[cfg(feature = "conflux")]
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, MultiPathTunnel)]
pub struct ClientMultiPathOnionServiceDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

/// A service multi path onion service data tunnel (Conflux, Rendeszvous).
#[cfg(feature = "conflux")]
#[derive(Debug, Deftly)]
#[derive_deftly(BaseTunnel, DataTunnel, MultiPathTunnel)]
pub struct ServiceMultiPathOnionServiceDataTunnel {
    /// The protocol level tunnel.
    tunnel: Arc<tor_proto::ClientTunnel>,
}

impl ClientDirTunnel {
    /// Return a description of the first hop of this circuit.
    pub fn first_hop(&self) -> OwnedChanTarget {
        self.tunnel_ref()
            .first_hop()
            .expect("Bug getting dir tunnel first hop")
    }

    /// Get the clock skew claimed by the first hop of the circuit.
    ///
    /// See [`Channel::clock_skew()`](tor_proto::channel::Channel::clock_skew).
    pub async fn first_hop_clock_skew(&self) -> Result<ClockSkew> {
        // TODO(conflux): Is this CircCanceled error right?
        self.circuit()?
            .first_hop_clock_skew()
            .await
            .map_err(|_| Error::CircCanceled)
    }
}

impl ServiceOnionServiceDataTunnel {
    /// Tell this tunnel to begin allowing the final hop of the tunnel to try
    /// to create new Tor streams, and to return those pending requests in an
    /// asynchronous stream.
    ///
    /// Ordinarily, these requests are rejected.
    ///
    /// There can only be one [`Stream`](futures::Stream) of this type created on a given tunnel.
    /// If a such a [`Stream`](futures::Stream) already exists, this method will return
    /// an error.
    ///
    /// After this method has been called on a tunnel, the tunnel is expected
    /// to receive requests of this type indefinitely, until it is finally closed.
    /// If the `Stream` is dropped, the next request on this tunnel will cause it to close.
    ///
    /// Only onion services (and eventually) exit relays should call this
    /// method.
    //
    // TODO: Someday, we might want to allow a stream request handler to be
    // un-registered.  However, nothing in the Tor protocol requires it.
    #[cfg(feature = "hs-service")]
    pub async fn allow_stream_requests<'a, FILT>(
        &self,
        allow_commands: &'a [tor_cell::relaycell::RelayCmd],
        hop: TargetHop,
        filter: FILT,
    ) -> Result<
        impl futures::Stream<Item = tor_proto::client::stream::IncomingStream> + use<'a, FILT>,
    >
    where
        FILT: tor_proto::client::stream::IncomingStreamRequestFilter,
    {
        self.tunnel_ref()
            .allow_stream_requests(allow_commands, hop, filter)
            .await
            .map_err(|error| Error::Protocol {
                action: "allow stream requests",
                peer: None,
                error,
                unique_id: Some(self.tunnel.unique_id()),
            })
    }
}

#[cfg(feature = "hs-service")]
impl ServiceOnionServiceIntroTunnel {
    /// Return the cryptographic material used to prove knowledge of a shared
    /// secret with with `hop`.
    ///
    /// See [`CircuitBinding`] for more information on how this is used.
    ///
    /// Return None if we have no circuit binding information for the hop, or if
    /// the hop does not exist.
    pub async fn binding_key(&self, hop: TargetHop) -> Result<Option<CircuitBinding>> {
        let circ = self.circuit()?;
        circ.binding_key(hop)
            .await
            .map_err(|error| Error::Protocol {
                action: "binding key",
                peer: None,
                error,
                unique_id: Some(self.tunnel.unique_id()),
            })
    }
}
