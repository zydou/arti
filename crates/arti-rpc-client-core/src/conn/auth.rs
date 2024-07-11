//! Authentication for RpcConn.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::msgs::{request::Request, ObjectId};

use super::{ConnectError, RpcConn};

// TODO RPC: This might want to be moved and made public.  If we do, it needs a different error type.
impl super::SuccessResponse {
    fn deserialize_as<D: DeserializeOwned>(&self) -> Result<D, ConnectError> {
        #[derive(Deserialize)]
        struct Response<R> {
            result: R,
        }

        let r: Response<D> = serde_json::from_str(self.as_ref())?;
        Ok(r.result)
    }
}

/*
#[derive(Deserialize, Debug)]
struct RpcProtocol {
    version: String,
}
    */
#[derive(Deserialize, Debug)]
struct AuthInfo {
    schemes: Vec<String>,
}

#[derive(Serialize, Debug)]
struct AuthParams<'a> {
    scheme: &'a str,
}
#[derive(Deserialize, Debug)]
struct Authenticated {
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
