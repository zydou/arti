//! Authentication where both parties prove the ability to read a "cookie" file from disk.
//!
//! For full documentation of the protocol, see `rpc-cookie-sketch.md`

use std::sync::{Arc, Mutex, Weak};

use derive_deftly::Deftly;
use tor_rpc_connect::auth::{
    cookie::{Cookie, CookieAuthMac, CookieAuthNonce},
    RpcAuth,
};
use tor_rpcbase::{self as rpc, templates::*};

use crate::{Connection, RpcMgr};

use super::{AuthenticateReply, AuthenticationFailure};

/// Begin authenticating on an RPC connection, using Cookie authentication.
///
/// In cookie authentication, both parties prove knowledge of a
/// shared secret, written to a file on disk.  This method
/// does not prevent MITM attacks on its own.
///
/// When cookie authentication is in use, clients use this method
/// to begin cookie authentication by telling the RPC server
/// a temporary nonce.
///
/// You typically won't need to invoke this method yourself;
/// instead, your RPC library (such as `arti-rpc-client-core`)
/// should handle it for you.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "auth:cookie_begin"))]
struct CookieBegin {
    /// A client-selected random nonce.
    ///
    /// Used as input to the `server_mac` calculation
    client_nonce: CookieAuthNonce,
}
impl rpc::RpcMethod for CookieBegin {
    type Output = CookieBeginReply;
    type Update = rpc::NoUpdates;
}

/// An RPC server's response to an `auth:cookie_begin` request.
#[derive(Debug, serde::Serialize)]
struct CookieBeginReply {
    /// An object to use for the client's subsequent `cookie_continue`.
    cookie_auth: rpc::ObjectId,
    /// The address that the server believes it is listening on.
    server_addr: String,
    /// A MAC proving that the server knows the secret cookie.
    server_mac: CookieAuthMac,
    /// A secret nonce chosen by the server.
    server_nonce: CookieAuthNonce,
}

/// An in-progress cookie authentication attempt.
///
/// This object is returned by `auth:cookie_begin`;
/// it can be used a single time with `auth:cookie_continue` to finish authentication.
#[derive(Deftly)]
#[derive_deftly(rpc::Object)]
struct CookieAuthInProgress {
    /// The cookie we're using to check the client's authentication.
    cookie: Arc<Cookie>,
    /// The RPC manager we'll use, if successful, to create a session.
    mgr: Weak<RpcMgr>,
    /// The nonce that the client sent us.
    client_nonce: CookieAuthNonce,
    /// The nonce that we sent to the client.
    ///
    /// If this is None, then the client already authenticated once, and this object
    /// can no longer be used.
    server_nonce: Mutex<Option<CookieAuthNonce>>,
    /// The address that we believe we're listening on.
    server_addr: String,
}

/// Finish cookie authentication, returning a new RPC Session.
///
/// You typically won't need to invoke this method yourself;
/// instead, your RPC library (such as `arti-rpc-client-core`)
/// should handle it for you.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "auth:cookie_continue"))]
struct CookieContinue {
    /// MAC to prove knowledge of the secret cookie.
    client_mac: CookieAuthMac,
}

impl rpc::RpcMethod for CookieContinue {
    type Output = AuthenticateReply;
    type Update = rpc::NoUpdates;
}

/// Invoke the `auth:cookie_begin` method on a connection.
async fn cookie_begin(
    unauth: Arc<Connection>,
    method: Box<CookieBegin>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<CookieBeginReply, rpc::RpcError> {
    // Make sure that we actually want cookie authentication.
    let (cookie, server_addr) = match &unauth.require_auth {
        RpcAuth::Cookie {
            secret,
            server_address,
            ..
        } => (
            secret.load().map_err(|_| {
                // This is an internal error, since server cookies are always preloaded.
                rpc::RpcError::new(
                    "Somehow had an unloadable cookie".into(),
                    rpc::RpcErrorKind::InternalError,
                )
            })?,
            server_address.clone(),
        ),
        _ => return Err(AuthenticationFailure::IncorrectMethod.into()),
    };
    let mut rng = rand::thread_rng();

    let server_nonce = CookieAuthNonce::new(&mut rng);

    let server_mac = cookie.server_mac(&method.client_nonce, &server_nonce, server_addr.as_str());

    let auth_in_progress = Arc::new(CookieAuthInProgress {
        cookie,
        mgr: unauth.mgr.clone(),
        client_nonce: method.client_nonce,
        server_nonce: Mutex::new(Some(server_nonce.clone())),
        server_addr: server_addr.clone(),
    });
    let cookie_auth = ctx.register_owned(auth_in_progress);

    Ok(CookieBeginReply {
        cookie_auth,
        server_addr,
        server_mac,
        server_nonce,
    })
}

/// Invoke the `auth:cookie_continue` method on a [`CookieAuthInProgress`]
async fn cookie_continue(
    in_progress: Arc<CookieAuthInProgress>,
    method: Box<CookieContinue>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<AuthenticateReply, rpc::RpcError> {
    // Make sure we haven't gotten another one of these.
    let Some(server_nonce) = in_progress
        .server_nonce
        .lock()
        .expect("lock poisoned")
        .take()
    else {
        return Err(AuthenticationFailure::CookieNonceReused.into());
    };

    let expected_client_mac = in_progress.cookie.client_mac(
        &in_progress.client_nonce,
        &server_nonce,
        &in_progress.server_addr,
    );

    if expected_client_mac != method.client_mac {
        return Err(AuthenticationFailure::IncorrectAuthentication.into());
    }

    let mgr = in_progress
        .mgr
        .upgrade()
        .ok_or(AuthenticationFailure::ShuttingDown)?;
    let auth = &super::RpcAuthentication {};
    let session = mgr.create_session(auth);
    let session = ctx.register_owned(session);

    Ok(AuthenticateReply { session })
}

rpc::static_rpc_invoke_fn! {
    cookie_begin;
    cookie_continue;
}
