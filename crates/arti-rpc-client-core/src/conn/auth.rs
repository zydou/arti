//! Authentication for RpcConn.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::msgs::{request::Request, ObjectId};

use super::{ConnectError, RpcConn};

impl super::SuccessResponse {
    /// Try to decode the "result" field of a SuccessResponse as an instance of `D`.
    //
    // TODO RPC: This might want to be moved and made public.  If we do, it needs a different error type.
    fn deserialize_as<D: DeserializeOwned>(&self) -> Result<D, ConnectError> {
        /// Helper object for decoding the "result" field.
        #[derive(Deserialize)]
        struct Response<R> {
            /// The decoded value.
            result: R,
        }

        let r: Response<D> = serde_json::from_str(self.as_ref())?;
        Ok(r.result)
    }
}

/*
/// Response to an `auth:get_rpc_params`` message.
///
/// TODO: This does not exist; see below.
#[derive(Deserialize, Debug)]
struct RpcProtocol {
    version: String,
}
    */
/// Response to an `auth:query` request.
#[derive(Deserialize, Debug)]
struct AuthInfo {
    /// A list of supported authentication schemes.
    schemes: Vec<String>,
}

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

/// Expand to a 0-argument request on the `connection` object.
///
/// (None of the request in this module are concurrent, so we just use id 0.)
macro_rules! conn_req0 (
    { $method:expr } => {
        concat!(r#"{"id":0, "obj":"connection", "method":""#, $method, r#"", "params": {}}"# )
    }
);

impl RpcConn {
    /// Helper: probe arti for information about the protocol and supported authentication schemes.
    fn get_protocol_info(&self) -> Result<AuthInfo, ConnectError> {
        /*  TODO: See notes in arti_rpcserver::connection::auth; this method does not exit.
        let proto = self
            .execute(conn_req0!("auth:get_rpc_protocol"))?
            .map_err(ConnectError::NegotiationRejected)?
            .deserialize_as::<RpcProtocol>()?;
        if proto.version != "alpha" {
            return Err(ConnectError::ProtoNotSupported(proto.version));
        }
        */

        let authinfo = self
            .execute(conn_req0!("auth:query"))?
            .map_err(ConnectError::NegotiationRejected)?
            .deserialize_as::<AuthInfo>()?;

        Ok(authinfo)
    }

    /// Try to negotiate "inherent" authentication, using the provided scheme name.
    ///
    /// (Inherent authentication is available whenever the client proves that they
    /// are authorized through being able to connect to Arti at all.  Examples
    /// include connecting to a unix domain socket, and an in-process Arti implementation.)
    pub(crate) fn negotiate_inherent(&self, scheme_name: &str) -> Result<ObjectId, ConnectError> {
        let authinfo = self.get_protocol_info()?;

        if !authinfo.schemes.iter().any(|s| s == scheme_name) {
            return Err(ConnectError::SchemeNotSupported);
        }

        let r: Request<AuthParams> = Request {
            id: 0.into(),
            obj: "connection".to_string().into(),
            meta: Default::default(),
            method: "auth:authenticate".into(),
            params: AuthParams {
                scheme: scheme_name,
            },
        };
        let authenticated = self
            .execute(&r.encode()?)?
            .map_err(ConnectError::AuthenticationRejected)?
            .deserialize_as::<Authenticated>()?;

        Ok(authenticated.session)
    }
}
