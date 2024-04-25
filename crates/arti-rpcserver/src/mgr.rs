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
    /// Shared with each [`Connection`].
    ///
    /// **NOTE: observe the [Lock hierarchy](crate::mgr::Inner#lock-hierarchy)**
    dispatch_table: Arc<RwLock<rpc::DispatchTable>>,

    /// A function that we use to construct new Session objects when authentication
    /// is successful.
    session_factory: SessionFactory,

    /// Lock-protected view of the manager's state.
    ///
    /// **NOTE: observe the [Lock hierarchy](crate::mgr::Inner#lock-hierarchy)**
    ///
    /// This mutex is at an _inner_ level
    /// compared to the
    /// per-Connection locks.
    /// You must not take any per-connection lock if you
    /// hold this lock.
    /// Code that holds this lock must be checked
    /// to make sure that it doesn't then acquire any `Connection` lock.
    inner: Mutex<Inner>,
}

/// The [`RpcMgr`]'s state. This is kept inside a lock for interior mutability.
///
/// # Lock hierarchy
///
/// This system has, relevantly to the RPC code, three locks.
/// In order from outermost (acquire earlier) to innermost (acquire later):
///
///  1. [`Connection`]`.inner`
///  2. [`RpcMgr`]`.inner`
///  3. `RwLock<rpc::DispatchTable>`
///     (found in [`RpcMgr`]`.dispatch_table` *and* [`Connection`]`.dispatch_table`)
///
/// To avoid deadlock, when more than one of these locks is acquired,
/// they must be acquired in an order consistent with the order listed above.
///
/// (This ordering is slightly surprising:
/// normally a lock covering more-global state would be
/// "outside" (or "earlier")
/// compared to one covering more-narrowly-relevant state.)
// pub(crate) so we can link to the doc comment and its lock hierarchy
pub(crate) struct Inner {
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

    /// Run `func` with a mutable reference to our dispatch table as an argument.
    ///
    /// Used to register additional methods.
    pub fn with_dispatch_table<F, T>(&self, func: F) -> T
    where
        F: FnOnce(&mut rpc::DispatchTable) -> T,
    {
        let mut table = self.dispatch_table.write().expect("poisoned lock");
        func(&mut table)
    }

    /// Start a new session based on this RpcMgr, with a given TorClient.
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
            let connection = inner.connections.get(&id.connection)?;
            // Here we release the lock on self.inner, which makes it okay to
            // invoke a method on `connection` that may take its lock.
            drop(inner);
            connection
        };
        connection.lookup_by_idx(id.local_id)
    }

    /// Construct a new object to serve as the `session` for a connection.
    pub(crate) fn create_session(&self, auth: &RpcAuthentication) -> Arc<RpcSession> {
        (self.session_factory)(auth)
    }
}
