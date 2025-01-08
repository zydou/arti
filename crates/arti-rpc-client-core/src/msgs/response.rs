//! Support for decoding RPC Responses.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{AnyRequestId, JsonAnyObj};
use crate::{
    conn::ErrorResponse,
    util::{define_from_for_arc, Utf8CString},
};

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
/// re-encoded in canonical form,
/// and enough to find the information we need about it
/// to deliver it to the application.
#[derive(Clone, Debug)]
pub(crate) struct ValidatedResponse {
    /// The re-encoded text of this response.
    pub(crate) msg: Utf8CString,
    /// The metadata from this response.
    pub(crate) meta: ResponseMeta,
}

/// An error that occurred when trying to decode an RPC response.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum DecodeResponseError {
    /// We couldn't decode a response as json.
    #[error("Arti sent a message that didn't conform to the RPC protocol: {0}")]
    JsonProtocolViolation(#[source] Arc<serde_json::Error>),

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
    /// re-encode it and return it as a ValidatedResponse.
    pub(crate) fn try_validate(self) -> Result<ValidatedResponse, DecodeResponseError> {
        // We're using serde_json::Value in order to preserve any unrecognized fields
        // in the response when we re-encode it.
        //
        // The alternative would be to preserve unrecognized fields using serde(flatten) and a
        // JsonMap in each struct.  But that creates a risk of forgetting to do so in some
        // struct that we create in the future.
        let json: serde_json::Value = serde_json::from_str(&self.msg)?;
        let mut msg: String = serde_json::to_string(&json)?;
        debug_assert!(!msg.contains('\n'));
        msg.push('\n');
        let msg: Utf8CString = msg.try_into().map_err(|_| {
            // (This should be impossible; serde_json rejects NULs.)
            DecodeResponseError::ProtocolViolation("Unexpected NUL in validated message")
        })?;
        let response: Response = serde_json::from_value(json)?;
        let meta = match ResponseMeta::try_from_response(&response) {
            Ok(m) => m?,
            Err(_) => {
                return Err(DecodeResponseError::Fatal(
                    ErrorResponse::from_validated_string(msg),
                ))
            }
        };
        Ok(ValidatedResponse { msg, meta })
    }

    /// Return the inner `str` for this unparsed message.
    pub(crate) fn as_str(&self) -> &str {
        self.msg.as_str()
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
struct Response {
    /// The request ID for this response.
    ///
    /// This field is mandatory for any non-Error response.
    id: Option<AnyRequestId>,
    /// The body as decoded for this response.
    #[serde(flatten)]
    body: ResponseBody,
}

/// Inner type to implement `Response``
#[derive(Deserialize, Debug)]
enum ResponseBody {
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
impl<'a> From<&'a ResponseBody> for ResponseKind {
    fn from(value: &'a ResponseBody) -> Self {
        use ResponseBody as RMB;
        use ResponseKind as RK;
        // TODO RPC: If we keep the current set of types,
        // we should have this discriminant code be macro-generated.
        match value {
            RMB::Error(_) => RK::Error,
            RMB::Success(_) => RK::Success,
            RMB::Update(_) => RK::Update,
        }
    }
}

/// Error returned from [`ResponseMeta::try_from_response`] when a response
/// has no Id field, and therefore indicates a fatal protocol error.
#[derive(thiserror::Error, Debug, Clone)]
#[error("Response was fatal (it had no ID)")]
struct ResponseWasFatal;

impl ResponseMeta {
    /// Try to extract a `ResponseMeta` from a response.
    ///
    /// Return `Err(ResponseWasFatal)` if the ID was missing on an error, and `Err(Err(_))` on any
    /// other problem.
    fn try_from_response(
        response: &Response,
    ) -> Result<Result<Self, DecodeResponseError>, ResponseWasFatal> {
        use DecodeResponseError as E;
        use ResponseBody as Body;
        match (&response.id, &response.body) {
            (None, Body::Error(_ignore)) => {
                // No ID, so this is a fatal response.
                // Re-encode the response.
                Err(ResponseWasFatal)
            }
            (None, _) => Ok(Err(E::ProtocolViolation("Missing ID field"))),
            (Some(id), body) => Ok(Ok(ResponseMeta {
                id: id.clone(),
                kind: (body).into(),
            })),
        }
    }
}

/// Try to decode `s` as an error response, and return its error.
///
/// (Gives an error if this is not an error response)
//
// TODO RPC: Eventually we should try to refactor this out if we can; it is only called in one
// place.
pub(crate) fn try_decode_response_as_err(s: &str) -> Result<Option<RpcError>, DecodeResponseError> {
    let Response { body, .. } = serde_json::from_str(s)?;
    match body {
        ResponseBody::Error(e) => Ok(Some(e)),
        _ => Ok(None),
    }
}

/// An error sent by Arti, decoded into its parts.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct RpcError {
    /// A human-readable message from Arti.
    message: String,
    /// An error code representing the underlying problem.
    code: RpcErrorCode,
    /// One or more `ErrorKind`s, encoded as strings.
    kinds: Vec<String>,
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
}

caret::caret_int! {
    #[derive(serde::Deserialize, serde::Serialize)]
    pub struct RpcErrorCode(i32) {
        /// "The JSON sent is not a valid Request object."
        INVALID_REQUEST = -32600,
        /// "The method does not exist ."
        NO_SUCH_METHOD = -32601,
        /// "Invalid method parameter(s)."
        INVALID_PARAMS = -32602,
        /// "The server suffered some kind of internal problem"
        INTERNAL_ERROR = -32603,
        /// "Some requested object was not valid"
        OBJECT_ERROR = 1,
        /// "Some other error occurred"
        REQUEST_ERROR = 2,
        /// This method exists, but wasn't implemented on this object.
        METHOD_NOT_IMPL = 3,
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

    /// Helper: Decode a string into a Response, then convert it into
    /// a ResponseMeta.
    fn response_meta(s: &str) -> Result<ResponseMeta, DecodeResponseError> {
        match ResponseMeta::try_from_response(&serde_json::from_str::<Response>(s)?) {
            Ok(v) => v,
            Err(_) => {
                let utf8 = Utf8CString::try_from(s.to_string())
                    .map_err(|_| DecodeResponseError::ProtocolViolation("not utf8cstr?"))?;
                Err(DecodeResponseError::Fatal(
                    ErrorResponse::from_validated_string(utf8),
                ))
            }
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
            let r: Result<serde_json::Value, _> = serde_json::from_str(s);
            assert!(dbg!(r.err()).is_some());
        }
    }

    #[test]
    fn re_encode() {
        let response = r#"{
            "id": 6,
            "error": {
                "message":"iffy wobbler",
                "code":999,
                "kinds": ["BadVibes"],
                "data": {"a":"b"},
                "explosion": 22
             },
             "xyzzy":"plugh"
        }"#;
        let json_orig: serde_json::Value = serde_json::from_str(response).unwrap();
        let resp = UnparsedResponse::new(response.into());
        let valid = resp.try_validate().unwrap();
        let msg: &str = valid.msg.as_ref();
        let json_reencoded: serde_json::Value = serde_json::from_str(msg).unwrap();
        // To make sure all fields were preserved, we have to compare the json objects for equality;
        // we cannot rely on the order of the fields.
        assert_eq!(json_orig, json_reencoded);
    }
}
