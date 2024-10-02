//! Authentication for RpcConn.

use serde::{Deserialize, Serialize};

use crate::msgs::{request::Request, ObjectId};

use super::{ConnectError, RpcConn};

/// Arguments to an `auth:authenticate` request.
#[derive(Serialize, Debug)]
struct AuthParams<'a> {
    /// The authentication scheme we are using.
    scheme: &'a str,
}
/// Response to an `auth:authenticate` request.
#[derive(Deserialize, Debug)]
struct Authenticated {
    /// A session object that we use to access the rest of Arti's functionality.
    session: ObjectId,
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
        let authenticated: Authenticated = self.execute_internal_ok(&r.encode()?)?;

        Ok(authenticated.session)
    }
}
