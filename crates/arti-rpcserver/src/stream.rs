//! Objects that can become or wrap a [`arti_client::DataStream`].

use arti_client::rpc::{ClientConnectionResult, ClientConnectionTarget};
use async_trait::async_trait;
use derive_deftly::Deftly;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tor_proto::stream::DataStreamCtrl;
use tor_rpcbase::{self as rpc, templates::*};

use crate::RpcSession;

/// An RPC object representing a (possibly unconstructed) DataStream.
///
/// This object is created from an RPC method, and starts out with
/// enough information to know how to create a DataStream or to respond
/// to some other SOCKS request.
///
/// This object is single-use: once a SOCKS request has referred to it,
/// it cannot be used for any other SOCKS request.
//
// TODO RPC: This object's name is questionable.
#[derive(Deftly)]
#[derive_deftly(Object)]
#[deftly(rpc(expose_outside_of_session))]
pub(crate) struct RpcDataStream {
    /// The inner state of this object.
    inner: Mutex<Inner>,
}

/// The inner state of a DataStream
enum Inner {
    /// Newly constructed: Waiting for a SOCKS command.
    Unused(Arc<dyn ClientConnectionTarget>),

    /// The actual connection is being made, ie we are within `connect_with_prefs`
    ///
    /// If the state is `Launching`, no one except `connect_with_prefs` may change it.
    Launching,

    /// Stream constructed; may or may not be connected.
    Stream(Arc<DataStreamCtrl>),

    /// Stream was used for a resolve or resolve_ptr request; there is no underlying stream.
    UsedToResolve,

    /// Failed to construct the tor_proto::DataStream object.
    StreamFailed,
}

/// Error returned by an operations from RpcDataStream.
#[derive(Debug, thiserror::Error)]
enum DataStreamError {
    /// Application tried to provide an identifier for an RpcDataStream,
    /// but that RpcDataStream had already been used previously.
    #[error("Data stream object already used")]
    AlreadyUsed,
}

impl tor_error::HasKind for DataStreamError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use DataStreamError as E;
        match self {
            E::AlreadyUsed => EK::BadApiUsage, // TODO RPC: is this the correct ErrorKind?
        }
    }
}

impl RpcDataStream {
    /// Construct a new unused DataStream that will make its connection
    /// with `connector`.
    pub(crate) fn new(connector: Arc<dyn ClientConnectionTarget>) -> Self {
        Self {
            inner: Mutex::new(Inner::Unused(connector)),
        }
    }

    /// If this DataStream is in state Unused, replace its state with `new_state`
    /// and return the ClientConnectionTarget.  Otherwise, leave its state unchanged
    /// and return an error.
    fn take_connector(
        &self,
        new_state: Inner,
    ) -> Result<Arc<dyn ClientConnectionTarget>, DataStreamError> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let val = std::mem::replace(&mut *inner, new_state);
        if let Inner::Unused(conn) = val {
            Ok(conn)
        } else {
            *inner = val;
            Err(DataStreamError::AlreadyUsed)
        }
    }

    /// Return the `DataStreamCtrl` for this stream, if it has one.
    #[allow(dead_code)]
    fn get_ctrl(&self) -> Option<Arc<DataStreamCtrl>> {
        let inner = self.inner.lock().expect("poisoned lock");
        if let Inner::Stream(s) = &*inner {
            Some(s.clone())
        } else {
            None
        }
    }
}

#[async_trait]
impl ClientConnectionTarget for RpcDataStream {
    async fn connect_with_prefs(
        &self,
        target: &arti_client::TorAddr,
        prefs: &arti_client::StreamPrefs,
    ) -> ClientConnectionResult<arti_client::DataStream> {
        // Extract the connector.
        //
        // As we do this, we put this RpcDataStream into a Launching state.
        //
        // (`Launching`` wouldn't need to exist if we `connect_with_prefs` were synchronous,
        // but it isn't synchronous, so `Launching` is an observable state.)
        let connector = self
            .take_connector(Inner::Launching)
            .map_err(|e| Box::new(e) as _)?;

        let mut prefs = prefs.clone();
        let was_optimistic = prefs.is_optimistic();
        // We want this to be treated internally as an "optimistic" connection,
        // so that inner connect_with_prefs() will return ASAP.
        prefs.optimistic();

        // Now, launch the connection.  Since we marked it as optimistic,
        // this call should return almost immediately.
        let stream: Result<arti_client::DataStream, _> =
            connector.connect_with_prefs(target, &prefs).await;

        // Pick the new state for this object, and install it.
        let new_obj = match &stream {
            Ok(s) => Inner::Stream(s.ctrl().clone()),
            Err(_) => Inner::StreamFailed, // TODO RPC: Remember some error information here.
        };
        {
            let mut inner = self.inner.lock().expect("poisoned lock");
            *inner = new_obj;
        }
        // Return early on failure.
        let mut stream = stream?;

        if !was_optimistic {
            // Implement non-optimistic behavior, if that is what was originally configured.
            stream
                .wait_for_connection()
                .await
                .map_err(|e| Box::new(e) as _)?;
        }

        // Return the stream; the SOCKS layer will take it from here.
        Ok(stream)
    }

    async fn resolve_with_prefs(
        &self,
        hostname: &str,
        prefs: &arti_client::StreamPrefs,
    ) -> ClientConnectionResult<Vec<IpAddr>> {
        let connector = self
            .take_connector(Inner::UsedToResolve)
            .map_err(|e| Box::new(e) as _)?;

        connector.resolve_with_prefs(hostname, prefs).await
    }

    async fn resolve_ptr_with_prefs(
        &self,
        addr: IpAddr,
        prefs: &arti_client::StreamPrefs,
    ) -> ClientConnectionResult<Vec<String>> {
        let connector = self
            .take_connector(Inner::UsedToResolve)
            .map_err(|e| Box::new(e) as _)?;

        connector.resolve_ptr_with_prefs(addr, prefs).await
    }
}

/// Method to create a stream handle.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:new-stream-handle"))]
pub(crate) struct NewStreamHandle {}

impl rpc::Method for NewStreamHandle {
    type Output = rpc::SingletonId;
    type Update = rpc::NoUpdates; // TODO actually, updates are quite suitable here.
}

/// Helper: construct and register an RpcDataStream.
fn new_stream_handle_impl(
    connector: Arc<dyn ClientConnectionTarget>,
    ctx: &dyn rpc::Context,
) -> rpc::ObjectId {
    let rpc_stream = Arc::new(RpcDataStream::new(connector));
    ctx.register_owned(rpc_stream as _)
}

/// Implement NewStreamHandle for clients.
pub(crate) async fn new_stream_handle_on_client<R: tor_rtcompat::Runtime>(
    client: Arc<arti_client::TorClient<R>>,
    _method: Box<NewStreamHandle>,
    ctx: Box<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    Ok(new_stream_handle_impl(client, ctx.as_ref()).into())
}

/// Implement NewStreamHandle for RpcSession.
async fn new_stream_handle_on_session(
    session: Arc<RpcSession>,
    _method: Box<NewStreamHandle>,
    ctx: Box<dyn rpc::Context>,
) -> Result<rpc::SingletonId, rpc::RpcError> {
    Ok(new_stream_handle_impl(session, ctx.as_ref()).into())
}
rpc::static_rpc_invoke_fn! { new_stream_handle_on_session; }
