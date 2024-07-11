//! Support for decoding RPC Responses.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value as JsonValue;

use super::AnyRequestId;
use crate::{conn::ErrorResponse, util::define_from_for_arc};

/// An unparsed and unvalidated response, as received from Arti.
///
/// (It will have no internal newlines, and a single NL at the end.)
#[derive(Clone, Debug, derive_more::AsRef)]
pub struct UnparsedResponse {
    /// The body of this response.
    msg: String,
}

impl UnparsedResponse {
    /// Construct a new UnparsedResponse.
    pub(crate) fn new(msg: String) -> Self {
        Self { msg }
    }
}

/// A response that we have validated for correct syntax,
/// and decoded enough to find the information we need about it
/// to deliver it to the application.
#[derive(Clone, Debug)]
pub(crate) struct ValidatedResponse {
    /// The text of this response.
    pub(crate) msg: String,
    /// The metadata from this response.
    pub(crate) meta: ResponseMeta,
}

/// An error that occurred when trying to decode an RPC response.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum DecodeResponseError {
    /// We couldn't decode a response as json.
    #[error("Arti sent a message that didn't conform to the RPC protocol: {0}")]
    JsonProtocolViolation(Arc<serde_json::Error>),

    /// There was something (other than json encoding) wrong with a response.
    #[error("Arti sent a message that didn't conform to the RPC protocol: {0}")]
    ProtocolViolation(&'static str),

    /// We decoded the response, but rather than having an `id`,
    /// it had an error message from Arti with no id.  We treat this as fatal.
    #[error("Arti reported a fatal error: {0:?}")]
    Fatal(ErrorResponse),
}
define_from_for_arc!( serde_json::Error => DecodeResponseError [JsonProtocolViolation] );

impl UnparsedResponse {
    /// If this response is well-formed, and it corresponds to a single request,
    /// return it as a ValidatedResponse.
    pub(crate) fn try_validate(self) -> Result<ValidatedResponse, DecodeResponseError> {
        let meta = response_meta(self.as_ref())?;
        Ok(ValidatedResponse {
            msg: self.msg,
            meta,
        })
    }
}

impl ValidatedResponse {
    /// Return true if no additional response should arrive for this request.
    pub(crate) fn is_final(&self) -> bool {
        use ResponseKind as K;
        match self.meta.kind {
            K::Error | K::Success => true,
            K::Update => false,
        }
    }

    /// Return the request ID associated with this response.
    pub(crate) fn id(&self) -> &AnyRequestId {
        &self.meta.id
    }
}

impl From<ValidatedResponse> for String {
    fn from(value: ValidatedResponse) -> Self {
        value.msg
    }
}

/// Metadata extracted from a response while decoding it.
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct ResponseMeta {
    /// The request ID for this response.
    pub(crate) id: AnyRequestId,
    /// The kind of response that was received.
    pub(crate) kind: ResponseKind,
}

/// A kind of response received from Arti.
//
// TODO: Possibly unify or derive from ResponseMetaBodyDe?
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResponseKind {
    /// Arti reports that an error has occurred.
    Error,
    /// Arti reports that the request completed successfully.
    Success,
    /// Arti reports an incremental update for the request.
    Update,
}

/// Serde-only type: decodes enough fields from a response in order to validate it
/// and route it to the application.
#[derive(Deserialize, Debug)]
struct ResponseMetaDe {
    /// The request ID for this response.
    ///
    /// This field is mandatory for any non-Error response.
    id: Option<AnyRequestId>,
    /// The body as decoded for this response.
    #[serde(flatten)]
    body: ResponseMetaBodyDe,
}
/// Inner type to implement ResponseMetaDe
#[derive(Deserialize, Debug)]
enum ResponseMetaBodyDe {
    /// Arti reports that an error has occurred.
    ///
    /// In this case, we decode the error to make sure it's well-formed.
    #[serde(rename = "error")]
    Error(RpcError),
    /// Arti reports that the request completed successfully.
    #[serde(rename = "result")]
    Success(JsonAnyObj),
    /// Arti reports an incremental update for the request.
    #[serde(rename = "update")]
    Update(JsonAnyObj),
}
impl<'a> From<&'a ResponseMetaBodyDe> for ResponseKind {
    fn from(value: &'a ResponseMetaBodyDe) -> Self {
        use ResponseKind as RK;
        use ResponseMetaBodyDe as RMB;
        // TODO RPC: If we keep the current set of types,
        // we should have this discriminant code be macro-generated.
        match value {
            RMB::Error(_) => RK::Error,
            RMB::Success(_) => RK::Success,
            RMB::Update(_) => RK::Update,
        }
    }
}

/// Try to extract metadata for a request in `s`, and make sure it is well-formed.
pub(crate) fn response_meta(s: &str) -> Result<ResponseMeta, DecodeResponseError> {
    use DecodeResponseError as E;
    use ResponseMetaBodyDe as Body;
    let ResponseMetaDe { id, body } = serde_json::from_str(s)?;
    match (id, body) {
        (None, Body::Error(_ignore)) => {
            Err(E::Fatal(ErrorResponse::from_validated_string(s.to_owned())))
        }
        (None, _) => Err(E::ProtocolViolation("Missing ID field")),
        (Some(id), body) => Ok(ResponseMeta {
            id,
            kind: (&body).into(),
        }),
    }
}

/// Try to decode `s` as an error response, and return its error.
pub(crate) fn response_err(s: &str) -> Result<Option<RpcError>, DecodeResponseError> {
    let ResponseMetaDe { body, .. } = serde_json::from_str(s)?;
    match body {
        ResponseMetaBodyDe::Error(e) => Ok(Some(e)),
        _ => Ok(None),
    }
}

/// Serde helper: deserializes (and discards) the contents of any json Object.
#[derive(serde::Deserialize, Debug)]
struct JsonAnyObj {}

/// An error sent by Arti, decoded into its parts.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct RpcError {
    /// A human-readable message from Arti.
    message: String,
    /// An error code representing the underlying problem.
    code: RpcErrorCode,
    /// One or more `ErrorKind`s, encoded as strings.
    kinds: Vec<String>,
    /// Associated data.
    //
    // TODO RPC: Enforce that this is a Map or a String.
    data: Option<JsonValue>,
}

impl RpcError {
    /// Return the human-readable message that Arti sent as part of this error.
    pub fn message(&self) -> &str {
        self.message.as_str()
    }
    /// Return the numeric error code from this error.
    pub fn code(&self) -> RpcErrorCode {
        self.code
    }
    /// Return an iterator over the ErrorKinds for this error.
    //
    // Note: This is not a great API for FFI purposes.
    // But FFI code should get errors as a String, so that's probably fine.
    pub fn kinds_iter(&self) -> impl Iterator<Item = &'_ str> {
        self.kinds.iter().map(|s| s.as_ref())
    }
    /// Return the data field from this error.
    //
    // Note: This is not a great API for FFI purposes.
    // But FFI code should get errors as a String, so that's probably fine.
    pub fn data(&self) -> Option<&JsonValue> {
        self.data.as_ref()
    }
}

caret::caret_int! {
    #[derive(serde::Deserialize)]
    pub struct RpcErrorCode(i32) {
        /// "The JSON sent is not a valid Request object."
        //
        // TODO RPC: Our current serde code does not distinguish between "I know of
        // no method called X", "I know of a method called X but the parameters were
        // wrong", and "I couldn't even parse that thing as a Request!
        INVALID_REQUEST = -32600,
        /// "The method does not exist / is not available on this object."
        METHOD_NOT_FOUND = -32601,
        /// "Invalid method parameter(s)."
        INVALID_PARAMS = -32602,
        /// "The server suffered some kind of internal problem"
        INTERNAL_ERROR = -32603,
        /// "Some requested object was not valid"
        OBJECT_ERROR = 1,
        /// "Some other error occurred"
        REQUEST_ERROR = 2,
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

    #[test]
    fn any_obj_good() {
        for ok in [
            r#"{}"#,
            r#"{"7": 7}"#,
            r#"{"stuff": "nonsense", "this": {"that": "the other"}}"#,
        ] {
            let _obj: JsonAnyObj = serde_json::from_str(ok).unwrap();
        }

        for bad in [r#"7"#, r#"ksldjfa"#, r#""#, r#"{7:"foo"}"#] {
            let err: Result<JsonAnyObj, _> = serde_json::from_str(bad);
            assert!(err.is_err());
        }
    }

    #[test]
    fn response_meta_good() {
        use ResponseKind as RK;
        use ResponseMeta as RM;
        for (s, expected) in [
            (
                r#"{"id":7, "result": {}}"#,
                RM {
                    id: 7.into(),
                    kind: RK::Success,
                },
            ),
            (
                r#"{"id":"hi", "update": {"here":["goes", "nothing"]}}"#,
                RM {
                    id: "hi".to_string().into(),
                    kind: RK::Update,
                },
            ),
            (
                r#"{"id": 6, "error": {"message":"iffy wobbler", "code":999, "kinds": ["BadVibes"]}}"#,
                RM {
                    id: 6.into(),
                    kind: RK::Error,
                },
            ),
            (
                r#"{"id": 6, "error": {"message":"iffy wobbler", "code":999, "kinds": ["BadVibes"], "data": {"a":"b"}}}"#,
                RM {
                    id: 6.into(),
                    kind: RK::Error,
                },
            ),
        ] {
            let got = response_meta(s).unwrap();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn response_meta_bad() {
        macro_rules! check_err {
            { $s:expr, $p:pat } => {
                let got_err = response_meta($s).unwrap_err();
                assert!(matches!(got_err, $p));
            }

        }

        use DecodeResponseError as E;

        // No ID; arti is saying we screwed up.
        check_err!(
            r#"{"error": {"message":"iffy wobbler", "code":999, "kinds": ["BadVibes"], "data": {"a":"b"}}}"#,
            E::Fatal(_)
        );
        // Missing ID on a success.
        check_err!(r#"{"result": {}}"#, E::ProtocolViolation(_));
        // Missing ID on an update.
        check_err!(r#"{"update": {}}"#, E::ProtocolViolation(_));
        // No recognized type.
        check_err!(r#"{"id": 7, "flupdate": {}}"#, E::JsonProtocolViolation(_));
        // Couldn't parse.
        check_err!(r#"{{{{{"#, E::JsonProtocolViolation(_));
        // Error is no good.
        check_err!(
            r#"{"id": 77 "error": {"message":"iffy wobbler"}}"#,
            E::JsonProtocolViolation(_)
        );
    }

    #[test]
    fn bad_json() {
        // we rely on the json parser rejecting some things.
        for s in [
            "{ ",         // not complete
            "",           // Empty.
            "{ \0 }",     // contains nul byte.
            "{ \"\0\" }", // string contains nul byte.
        ] {
            let r: Result<JsonAnyObj, _> = serde_json::from_str(s);
            assert!(dbg!(r.err()).is_some());
        }
    }
}
