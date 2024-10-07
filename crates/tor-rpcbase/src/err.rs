//! Error-related functionality for RPC functions.

/// An error type returned by failing RPC methods.
#[derive(serde::Serialize)]
pub struct RpcError {
    /// A human-readable message.
    message: String,
    /// An error code inspired by json-rpc.
    code: RpcCode,
    /// The ErrorKind(s) of this error.
    #[serde(serialize_with = "ser_kind")]
    kinds: tor_error::ErrorKind,
}

impl RpcError {
    /// Return true if this is an internal error.
    pub fn is_internal(&self) -> bool {
        matches!(self.kinds, tor_error::ErrorKind::Internal)
    }
}

impl<T> From<T> for RpcError
where
    T: std::error::Error + tor_error::HasKind + Send + 'static,
{
    fn from(value: T) -> RpcError {
        use tor_error::ErrorReport as _;
        let message = value.report().to_string();
        let code = kind_to_code(value.kind());
        let kinds = value.kind();
        RpcError {
            message,
            code,
            kinds,
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

/// Error codes for backward compatibility with json-rpc.
#[derive(Clone, Debug, Eq, PartialEq, serde_repr::Serialize_repr)]
#[repr(i32)]
#[allow(clippy::enum_variant_names)]
enum RpcCode {
    /// "The JSON sent is not a valid Request object."
    RpcInvalidRequest = -32600,
    /// "The method does not exist."
    RpcNoSuchMethod = -32601,
    /// "Invalid method parameter(s)."
    RpcInvalidParams = -32602,
    /// "The server suffered some kind of internal problem"
    RpcInternalError = -32603,
    /// "Some requested object was not valid"
    RpcObjectError = 1,
    /// "Some other error occurred"
    RpcRequestError = 2,
    /// This method exists, but wasn't implemented on this object.
    RpcMethodNotImpl = 3,
    /// This request was cancelled before it could finish.
    RpcRequestCancelled = 4,
    /// This request listed a required feature that doesn't exist.
    RpcFeatureNotPresent = 5,
}

/// Helper: Return an error code (for backward compat with json-rpc) for an
/// ErrorKind.
///
/// These are not especially helpful and nobody should really use them.
fn kind_to_code(kind: tor_error::ErrorKind) -> RpcCode {
    use tor_error::ErrorKind as EK;
    match kind {
        EK::RpcInvalidRequest => RpcCode::RpcInvalidRequest,
        EK::RpcMethodNotFound => RpcCode::RpcNoSuchMethod,
        EK::RpcMethodNotImpl => RpcCode::RpcMethodNotImpl,
        EK::RpcInvalidMethodParameters => RpcCode::RpcInvalidParams,
        EK::Internal | EK::BadApiUsage => RpcCode::RpcInternalError,
        EK::RpcObjectNotFound => RpcCode::RpcObjectError,
        EK::RpcRequestCancelled => RpcCode::RpcRequestCancelled,
        EK::RpcFeatureNotPresent => RpcCode::RpcFeatureNotPresent,
        _ => RpcCode::RpcRequestError, // (This is our catch-all "request error.")
    }
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcError")
            .field("message", &self.message)
            .field("code", &self.code)
            .field("kinds", &self.kinds)
            .finish()
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[derive(Debug, thiserror::Error, serde::Serialize)]
    enum ExampleError {
        #[error("The {} exploded because {}", what, why)]
        SomethingExploded { what: String, why: String },

        #[error("I'm hiding the {0} in my {1}")]
        SomethingWasHidden(String, String),

        #[error("The {0} was missing")]
        SomethingWasMissing(String),

        #[error("I don't feel up to it today")]
        ProgramUnwilling,
    }

    impl tor_error::HasKind for ExampleError {
        fn kind(&self) -> tor_error::ErrorKind {
            match self {
                Self::SomethingExploded { .. } => tor_error::ErrorKind::Other,
                Self::SomethingWasHidden(_, _) => tor_error::ErrorKind::RpcObjectNotFound,
                Self::SomethingWasMissing(_) => tor_error::ErrorKind::FeatureDisabled,
                Self::ProgramUnwilling => tor_error::ErrorKind::Internal,
            }
        }
    }

    /// Assert that two json strings deserialize to equivalent objects.
    macro_rules! assert_json_eq {
        ($a:expr, $b:expr) => {
            let json_a: serde_json::Value = serde_json::from_str($a).unwrap();
            let json_b: serde_json::Value = serde_json::from_str($b).unwrap();
            assert_eq!(json_a, json_b);
        };
    }

    #[test]
    fn serialize_error() {
        // TODO: Since we do not expose `data`, these error formats are now more or less useless.
        // We should revisit them if we decide to reintroduce error data.

        let err = ExampleError::SomethingExploded {
            what: "previous implementation".into(),
            why: "worse things happen at C".into(),
        };
        let err = RpcError::from(err);
        assert_eq!(err.code, RpcCode::RpcRequestError);
        let serialized = serde_json::to_string(&err).unwrap();
        let expected_json = r#"
          {
            "message": "error: The previous implementation exploded because worse things happen at C",
            "code": 2,
            "kinds": ["arti:Other"]
         }
        "#;
        assert_json_eq!(&serialized, expected_json);

        let err = ExampleError::SomethingWasHidden(
            "zircon-encrusted tweezers".into(),
            "chrome dinette".into(),
        );
        let err = RpcError::from(err);
        let serialized = serde_json::to_string(&err).unwrap();
        let expected = r#"
        {
            "message": "error: I'm hiding the zircon-encrusted tweezers in my chrome dinette",
            "code": 1,
            "kinds": ["arti:RpcObjectNotFound"]
         }
        "#;
        assert_json_eq!(&serialized, expected);

        let err = ExampleError::SomethingWasMissing("turbo-encabulator".into());
        let err = RpcError::from(err);
        let serialized = serde_json::to_string(&err).unwrap();
        let expected = r#"
        {
            "message": "error: The turbo-encabulator was missing",
            "code": 2,
            "kinds": ["arti:FeatureDisabled"]
         }
        "#;
        assert_json_eq!(&serialized, expected);

        let err = ExampleError::ProgramUnwilling;
        let err = RpcError::from(err);
        let serialized = serde_json::to_string(&err).unwrap();
        let expected = r#"
        {
            "message": "error: I don't feel up to it today",
            "code": -32603,
            "kinds": ["arti:Internal"]
         }
        "#;
        assert_json_eq!(&serialized, expected);
    }
}
