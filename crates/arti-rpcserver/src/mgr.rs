//! Top-level `RpcMgr` to launch sessions.

use std::sync::{Arc, Mutex, RwLock, Weak};

use rand::Rng;
use tor_rpcbase as rpc;
use weak_table::WeakValueHashMap;

use crate::{
    connection::{Connection, ConnectionId},
    globalid::{GlobalId, MacKey},
    RpcAuthentication, RpcSession,
};

/// A function we use to construct Session objects in response to authentication.
//
// TODO RPC: Perhaps this should return a Result?
type SessionFactory = Box<dyn Fn(&RpcAuthentication) -> Arc<RpcSession> + Send + Sync>;

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

    /// A function that we use to construct new Session objects when authentication
    /// is successful.
    session_factory: SessionFactory,

    /// Lock-protected view of the manager's state.
    ///
    /// NOTE: In the lock hierarchy, this mutex is at a _lower_ level than the
    /// per-Connection locks.  You must not take any per-connection lock if you
    /// hold this lock.  Functions that take or hold this lock must be checked
    /// to make sure that they follow this rule.
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
    pub fn new<F>(make_session: F) -> Arc<Self>
    where
        F: Fn(&RpcAuthentication) -> Arc<RpcSession> + Send + Sync + 'static,
    {
        Arc::new(RpcMgr {
            global_id_mac_key: MacKey::new(&mut rand::thread_rng()),
            dispatch_table: Arc::new(RwLock::new(rpc::DispatchTable::from_inventory())),
            session_factory: Box::new(make_session),
            inner: Mutex::new(Inner {
                connections: WeakValueHashMap::new(),
            }),
        })
    }

    /// Start a new session based on this RpcMgr, with a given TorClient.
    #[allow(clippy::missing_panics_doc)]
    pub fn new_connection(self: &Arc<Self>) -> Arc<Connection> {
        let connection_id = ConnectionId::from(rand::thread_rng().gen::<[u8; 16]>());
        let connection = Arc::new(Connection::new(
            connection_id,
            self.dispatch_table.clone(),
            self.global_id_mac_key.clone(),
            Arc::downgrade(self),
        ));

        let mut inner = self.inner.lock().expect("poisoned lock");
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
        let connection = {
            let inner = self.inner.lock().expect("lock poisoned");
            inner.connections.get(&id.connection)?
            // Here we release the lock on self.inner, which makes it okay to
            // invoke a method on `connection` that may take its lock.
        };
        connection.lookup_by_idx(id.local_id)
    }

    /// Construct a new object to serve as the `session` for a connection.
    pub(crate) fn create_session(&self, auth: &RpcAuthentication) -> Arc<RpcSession> {
        (self.session_factory)(auth)
    }
}
