//! Error-related functionality for RPC functions.

/// An error type returned by failing RPC methods.
#[derive(serde::Serialize)]
pub struct RpcError {
    /// A human-readable message.
    message: String,
    /// An error code inspired by json-rpc.
    #[serde(serialize_with = "ser_code")]
    code: RpcErrorKind,
    /// The ErrorKind(s) of this error.
    #[serde(serialize_with = "ser_kind")]
    kinds: AnyErrorKind,
}

impl RpcError {
    /// Construct a new `RpcError` with the provided message and error code.
    pub fn new(message: String, code: RpcErrorKind) -> Self {
        Self {
            message,
            code,
            kinds: AnyErrorKind::Rpc(code),
        }
    }

    /// Change the declared kind of this error to `kind`.
    pub fn set_kind(&mut self, kind: tor_error::ErrorKind) {
        self.kinds = AnyErrorKind::Tor(kind);
    }

    /// Return true if this is an internal error.
    pub fn is_internal(&self) -> bool {
        matches!(
            self.kinds,
            AnyErrorKind::Tor(tor_error::ErrorKind::Internal)
                | AnyErrorKind::Rpc(RpcErrorKind::InternalError)
        )
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
        let kinds = AnyErrorKind::Tor(value.kind());
        RpcError {
            message,
            code,
            kinds,
        }
    }
}

/// Helper: Serialize an AnyErrorKind in RpcError.
fn ser_kind<S: serde::Serializer>(kind: &AnyErrorKind, s: S) -> Result<S::Ok, S::Error> {
    // Our spec says that `kinds` is a list.  Any tor_error::ErrorKind is prefixed with `arti:`,
    // and any RpcErrorKind is prefixed with `rpc:`

    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(None)?;
    match kind {
        AnyErrorKind::Tor(kind) => seq.serialize_element(&format!("arti:{:?}", kind))?,
        AnyErrorKind::Rpc(kind) => seq.serialize_element(&format!("rpc:{:?}", kind))?,
    }
    seq.end()
}

/// Helper: Serialize an RpcErrorKind as a numeric code.
fn ser_code<S: serde::Serializer>(kind: &RpcErrorKind, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i32(*kind as i32)
}

/// An ErrorKind as held by an `RpcError`
#[derive(Clone, Copy, Debug)]
enum AnyErrorKind {
    /// An ErrorKind representing a non-RPC problem.
    Tor(tor_error::ErrorKind),
    /// An ErrorKind originating within the RPC system.
    #[allow(unused)] //XXXX
    Rpc(RpcErrorKind),
}

/// Error kinds for RPC errors.
///
/// Unlike `tor_error::ErrorKind`,
/// these codes do not represent a problem in an Arti function per se:
/// they are only visible to the RPC system, and should only be reported there.
///
/// For backward compatibility with json-rpc,
/// each of these codes has a unique numeric ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
#[non_exhaustive]
pub enum RpcErrorKind {
    /// "The JSON sent is not a valid Request object."
    InvalidRequest = -32600,
    /// "The method does not exist."
    NoSuchMethod = -32601,
    /// "Invalid method parameter(s)."
    InvalidMethodParameters = -32602,
    /// "The server suffered some kind of internal problem"
    InternalError = -32603,
    /// "Some requested object was not valid"
    ObjectNotFound = 1,
    /// "Some other error occurred"
    RequestError = 2,
    /// This method exists, but wasn't implemented on this object.
    MethodNotImpl = 3,
    /// This request was cancelled before it could finish.
    RequestCancelled = 4,
    /// This request listed a required feature that doesn't exist.
    FeatureNotPresent = 5,
}

/// Helper: Return an error code (for backward compat with json-rpc) for an
/// ErrorKind.
///
/// These are not especially helpful and nobody should really use them.
fn kind_to_code(kind: tor_error::ErrorKind) -> RpcErrorKind {
    use tor_error::ErrorKind as EK;
    use RpcErrorKind as RC;
    match kind {
        EK::RpcInvalidRequest => RC::InvalidRequest,
        EK::RpcMethodNotFound => RC::NoSuchMethod,
        EK::RpcMethodNotImpl => RC::MethodNotImpl,
        EK::RpcInvalidMethodParameters => RC::InvalidMethodParameters,
        EK::Internal | EK::BadApiUsage => RC::InternalError,
        EK::RpcObjectNotFound => RC::ObjectNotFound,
        EK::RpcRequestCancelled => RC::RequestCancelled,
        EK::RpcFeatureNotPresent => RC::FeatureNotPresent,
        _ => RC::RequestError, // (This is our catch-all "request error.")
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
        assert_eq!(err.code, RpcErrorKind::RequestError);
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
