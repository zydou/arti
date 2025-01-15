//!  Error types used in by `arti-rpcserver`].

use tor_rpcbase::RpcError;

/// An error encountered while parsing an RPC request,
/// that we will report to the client.
///
/// Note that this does not include fatal parsing errors
/// that result in closing the connection entirely.
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub enum RequestParseError {
    /// The `id` field was missing.
    #[error("Request did not have any `id` field.")]
    IdMissing,

    /// The `id` field did not have the expected type (integer or string).
    #[error("Request's `id` field was not an integer or a string.")]
    IdType,

    /// The `obj` field was missing.
    #[error("Request did not have any `obj` field.")]
    ObjMissing,

    /// The `method` field did not have the expected type (string).
    #[error("Request's `obj` field was not a string.")]
    ObjType,

    /// The `method` field was missing.
    #[error("Request had no `method` field.")]
    MethodMissing,

    /// The `method` field did not have the expected type (string).
    #[error("Request's `method` field was not a string.")]
    MethodType,

    /// The `meta` field was present, but it could not be parsed.
    ///
    /// Maybe it was not a json object; maybe it had a field of the wrong type.
    #[error("Request's `meta` field was not valid.")]
    MetaType,

    /// The `method` field was not the name of any recognized method.
    #[error("Request's `method` field was unrecognized")]
    NoSuchMethod,

    /// The parameters were of the wrong type for the method.
    #[error("Parameter types incorrect for specified method")]
    ParamType,

    /// The `params` field was missing.
    #[error("Request's `params` field was missing.")]
    MissingParams,
}

impl From<RequestParseError> for RpcError {
    fn from(err: RequestParseError) -> Self {
        use tor_rpcbase::RpcErrorKind as EK;
        use RequestParseError as E;
        let kind = match err {
            E::IdMissing
            | E::IdType
            | E::ObjMissing
            | E::ObjType
            | E::MethodMissing
            | E::MethodType
            | E::MetaType
            | E::MissingParams => EK::InvalidRequest,
            E::NoSuchMethod => EK::NoSuchMethod,
            E::ParamType => EK::InvalidMethodParameters,
        };
        RpcError::new(err.to_string(), kind)
    }
}
