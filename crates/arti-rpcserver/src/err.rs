//!  Error types used in by `arti-rpcserver`].

/// An error encountered while parsing an RPC request.
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub(crate) enum RequestParseError {
    /// The provided object was not well-formed json.
    #[error("Error in json syntax.")]
    InvalidJson,

    /// Received something that was json, but not a json object.
    #[error("Received something other than a json object.")]
    NotAnObject,

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
    MethodNotFound,

    /// The parameters were of the wrong type for the method.
    #[error("Parameter types incorrect for specified method")]
    ParamType,

    /// The `params` field was missing.
    #[error("Request's `params` field was missing.")]
    MissingParams,
}

impl tor_error::HasKind for RequestParseError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;

        match self {
            Self::InvalidJson
            | Self::NotAnObject
            | Self::IdMissing
            | Self::IdType
            | Self::ObjMissing
            | Self::ObjType
            | Self::MethodMissing
            | Self::MethodType
            | Self::MetaType
            | Self::MissingParams => EK::RpcInvalidRequest,
            Self::MethodNotFound => EK::RpcMethodNotFound,
            Self::ParamType => EK::RpcInvalidMethodParameters,
        }
    }
}
