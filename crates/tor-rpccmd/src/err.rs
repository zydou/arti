//! Error-related functionality for RPC functions.

/// An error type returned by failing RPC commands.
#[derive(serde::Serialize)]
pub struct RpcError {
    /// A human-readable message.
    message: String,
    /// An error code inspired by json-rpc.
    code: i32,
    /// The ErrorKind of this error.
    #[serde(serialize_with = "ser_kind")]
    kind: tor_error::ErrorKind,
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
        let kind = value.kind();
        let boxed: Box<dyn erased_serde::Serialize + Send> = Box::new(value);
        let data = Some(boxed);
        RpcError {
            message,
            code,
            kind,
            data,
        }
    }
}

fn ser_kind<S: serde::Serializer>(kind: &tor_error::ErrorKind, s: S) -> Result<S::Ok, S::Error> {
    // TODO RPC: this format is wrong and temporary.
    s.serialize_str(&format!("{:?}", kind))
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcError")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("kind", &self.kind)
            .field("data", &self.data.as_ref().map(|_| "..."))
            .finish()
    }
}
