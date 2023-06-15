//! Top-level `RpcMgr` to launch sessions.

use std::sync::{Arc, Mutex, RwLock, Weak};

use arti_client::TorClient;
use rand::Rng;
use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;
use weak_table::WeakValueHashMap;

use crate::{
    connection::{Connection, ConnectionId},
    globalid::{GlobalId, MacKey},
};

/// Shared state, configuration, and data for all RPC sessions.
///
/// An RpcMgr knows how to listen for incoming RPC connections, and launch sessions based on them.
///
/// TODO RPC: Actually not all of the above functionality is implemented yet. But it should be.
pub struct RpcMgr {
    /// A key that we use to ensure that identifiers are unforgeable.
    ///
    /// When giving out a global (non-session-bound) identifier, we use this key
    /// to authenticate the identifier when it's given back to us.
    ///
    /// We make copies of this key when constructing a session.
    global_id_mac_key: MacKey,

    /// Our reference to the dispatch table used to look up the functions that
    /// implement each object on each.
    ///
    /// We keep this in an `Arc` so we can share it with sessions.
    dispatch_table: Arc<RwLock<rpc::DispatchTable>>,

    /// Lock-protected view of the manager's state.
    inner: Mutex<Inner>,
}

/// The [`RpcMgr`]'s state. This is kept inside a lock for interior mutability.
struct Inner {
    /// A map from [`ConnectionId`] to weak [`Connection`] references.
    ///
    /// We use this map to give connections a manager-global identifier that can
    /// be used to identify them from a SOCKS connection (or elsewhere outside
    /// of the RPC system).
    ///
    /// We _could_ use a generational arena here, but there isn't any point:
    /// since these identifiers are global, we need to keep them secure by
    /// MACing anything derived from them, which in turn makes the overhead of a
    /// HashMap negligible.
    connections: WeakValueHashMap<ConnectionId, Weak<Connection>>,
}

impl RpcMgr {
    /// Create a new RpcMgr.
    ///
    /// TODO RPC: Perhaps this should take a Client instead, and new_session
    /// should take nothing.  Also perhaps instead of a Client, it should take
    /// an `Arc<dyn Object>` that becomes the session.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Arc<Self> {
        Arc::new(RpcMgr {
            global_id_mac_key: MacKey::new(&mut rand::thread_rng()),
            dispatch_table: Arc::new(RwLock::new(rpc::DispatchTable::from_inventory())),
            inner: Mutex::new(Inner {
                connections: WeakValueHashMap::new(),
            }),
        })
    }

    /// Start a new session based on this RpcMgr, with a given TorClient.
    ///
    ///
    /// TODO RPC: If `client` is not a `TorClient<PreferredRuntime>`, it won't
    /// be possible to invoke any of its methods. See #837.
    #[allow(clippy::missing_panics_doc)]
    pub fn new_connection<R: Runtime>(self: &Arc<Self>, client: TorClient<R>) -> Arc<Connection> {
        let connection_id = ConnectionId::from(rand::thread_rng().gen::<[u8; 16]>());
        let client_obj = Arc::new(client);

        let mut inner = self.inner.lock().expect("poisoned lock");
        let connection = Arc::new(Connection::new(
            connection_id,
            self.dispatch_table.clone(),
            self.global_id_mac_key.clone(),
            client_obj,
            Arc::downgrade(self),
        ));
        let old = inner.connections.insert(connection_id, connection.clone());
        assert!(
            old.is_none(),
            // Specifically, we shouldn't expect collisions until we have made on the
            // order of 2^64 connections, and that shouldn't be possible on
            // realistic systems.
            "connection ID collision detected; this is phenomenally unlikely!",
        );
        connection
    }

    /// Look up an object in  the context of this `RpcMgr`.
    ///
    /// Some object identifiers exist in a manager-global context, so that they
    /// can be used outside of a single RPC session.  This function looks up an
    /// object by such an identifier string.  It returns an error if the
    /// identifier is invalid or the object does not exist.
    pub fn lookup_object(
        &self,
        id: &rpc::ObjectId,
    ) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        let global_id = GlobalId::try_decode(&self.global_id_mac_key, id)?;
        self.lookup_by_global_id(&global_id)
            .ok_or_else(|| rpc::LookupError::NoObject(id.clone()))
    }

    /// As `lookup_object`, but takes a parsed and validated [`GlobalId`].
    pub(crate) fn lookup_by_global_id(&self, id: &GlobalId) -> Option<Arc<dyn rpc::Object>> {
        let inner = self.inner.lock().expect("lock poisoned");
        let connection = inner.connections.get(&id.connection)?;
        connection.lookup_by_idx(id.local_id)
    }
}
