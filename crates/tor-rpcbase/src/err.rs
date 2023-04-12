//! Error-related functionality for RPC functions.

/// An error type returned by failing RPC methods.
#[derive(serde::Serialize)]
pub struct RpcError {
    /// A human-readable message.
    message: String,
    /// An error code inspired by json-rpc.
    code: i32,
    /// The ErrorKind(s) of this error.
    #[serde(serialize_with = "ser_kind")]
    kinds: tor_error::ErrorKind,
    /// An underlying serializable object, if any, to be sent along with the
    /// error.
    data: Option<Box<dyn erased_serde::Serialize + Send>>,
}

impl<T> From<T> for RpcError
where
    T: std::error::Error + tor_error::HasKind + serde::Serialize + Send + 'static,
{
    fn from(value: T) -> Self {
        let message = value.to_string();
        let code = -12345; // TODO RPC: this is wrong.
        let kinds = value.kind();
        let boxed: Box<dyn erased_serde::Serialize + Send> = Box::new(value);
        let data = Some(boxed);
        RpcError {
            message,
            code,
            kinds,
            data,
        }
    }
}

impl From<crate::dispatch::InvokeError> for crate::RpcError {
    fn from(_value: crate::dispatch::InvokeError) -> Self {
        crate::RpcError {
            message: "Tried to invoke unsupported method on object".to_string(),
            code: -23456,                                // TODO RPC wrong.
            kinds: tor_error::ErrorKind::NotImplemented, // TODO RPC wrong
            data: None,
        }
    }
}

impl From<crate::LookupError> for crate::RpcError {
    fn from(value: crate::LookupError) -> Self {
        crate::RpcError {
            message: value.to_string(),
            code: -3001,                        // TODO RPC wrong.
            kinds: tor_error::ErrorKind::Other, // TODO RPC wrong.
            data: None,
        }
    }
}

/// Helper: Serialize an ErrorKind in RpcError.
fn ser_kind<S: serde::Serializer>(kind: &tor_error::ErrorKind, s: S) -> Result<S::Ok, S::Error> {
    // Our spec says that `kinds` is a list, and that each kind we
    // define will be prefixed by arti:.

    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(1))?;
    seq.serialize_element(&format!("arti:{:?}", kind))?;
    seq.end()
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcError")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("kinds", &self.kinds)
            .field("data", &self.data.as_ref().map(|_| "..."))
            .finish()
    }
}
