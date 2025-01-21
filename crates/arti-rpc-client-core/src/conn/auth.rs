//! Authentication for RpcConn.

use serde::{Deserialize, Serialize};
use tor_rpc_connect::auth::cookie::{Cookie, CookieAuthMac, CookieAuthNonce};

use crate::msgs::{request::Request, ObjectId};

use super::{ConnectError, EmptyReply, NoParams, RpcConn};

/// Arguments to an `auth:authenticate` request.
#[derive(Serialize, Debug)]
struct AuthParams<'a> {
    /// The authentication scheme we are using.
    scheme: &'a str,
}
/// Response to an `auth:authenticate` or `auth:cookie_continue` request.
#[derive(Deserialize, Debug)]
struct AuthenticatedReply {
    /// A session object that we use to access the rest of Arti's functionality.
    session: ObjectId,
}

/// Arguments to an `auth:cookie_begin` request.
#[derive(Serialize, Debug)]
struct CookieBeginParams {
    /// Client-selected nonce; used while the server is proving knowledge of the cookie.
    client_nonce: CookieAuthNonce,
}

#[derive(Deserialize, Debug)]
struct CookieBeginReply {
    /// Temporary ID to use while authenticating.
    cookie_auth: ObjectId,
    /// Address that the server thinks it's listening on.
    server_addr: String,
    /// MAC returned by the server to prove knowledge of the cookie.
    server_mac: CookieAuthMac,
    /// Server-selected nonce to use while we prove knowledge of the cookie.
    server_nonce: CookieAuthNonce,
}

/// Arguments to an `auth:cookie_begin` request.
#[derive(Serialize, Debug)]
struct CookieContinueParams {
    /// Make to prove our knowledge of the cookie.
    client_mac: CookieAuthMac,
}

impl RpcConn {
    /// Try to negotiate "inherent" authentication, using the provided scheme name.
    ///
    /// (Inherent authentication is available whenever the client proves that they
    /// are authorized through being able to connect to Arti at all.  Examples
    /// include connecting to a unix domain socket, and an in-process Arti implementation.)
    pub(crate) fn authenticate_inherent(
        &self,
        scheme_name: &str,
    ) -> Result<ObjectId, ConnectError> {
        let r: Request<AuthParams> = Request::new(
            ObjectId::connection_id(),
            "auth:authenticate",
            AuthParams {
                scheme: scheme_name,
            },
        );
        let authenticated: AuthenticatedReply = self.execute_internal_ok(&r.encode()?)?;

        Ok(authenticated.session)
    }

    /// Try to negotiate "cookie" authentication, using the provided cookie and server address.
    pub(crate) fn authenticate_cookie(
        &self,
        cookie: &Cookie,
        server_addr: &str,
    ) -> Result<ObjectId, ConnectError> {
        // This protocol is documented in `rpc-cookie-sketch.md`.
        let client_nonce = CookieAuthNonce::new(&mut rand::thread_rng());

        let cookie_begin: Request<CookieBeginParams> = Request::new(
            ObjectId::connection_id(),
            "auth:cookie_begin",
            CookieBeginParams {
                client_nonce: client_nonce.clone(),
            },
        );
        let reply: CookieBeginReply = self.execute_internal_ok(&cookie_begin.encode()?)?;

        if server_addr != reply.server_addr {
            return Err(ConnectError::ServerAddressMismatch {
                ours: server_addr.into(),
                theirs: reply.server_addr,
            });
        }

        let expected_server_mac =
            cookie.server_mac(&client_nonce, &reply.server_nonce, server_addr);
        if reply.server_mac != expected_server_mac {
            return Err(ConnectError::CookieMismatch);
        }

        let client_mac = cookie.client_mac(&client_nonce, &reply.server_nonce, server_addr);
        let cookie_auth_obj = reply.cookie_auth.clone();
        let cookie_continue = Request::new(
            cookie_auth_obj.clone(),
            "auth:cookie_continue",
            CookieContinueParams { client_mac },
        );
        let authenticated: AuthenticatedReply =
            self.execute_internal_ok(&cookie_continue.encode()?)?;

        // Drop the cookie_auth_obj: we don't need it now that we have authenticated.
        let drop_request = Request::new(cookie_auth_obj, "rpc:release", NoParams {});
        let _reply: EmptyReply = self.execute_internal_ok(&drop_request.encode()?)?;

        Ok(authenticated.session)
    }
}
