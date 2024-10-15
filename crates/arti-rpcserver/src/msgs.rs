//! Message types used in the Arti's RPC protocol.
//
// TODO: This could become a more zero-copy-friendly with some effort, but it's
// not really sure if it's needed.

mod invalid;
use serde::{Deserialize, Serialize};
use tor_rpcbase as rpc;

/// An identifier for a Request within the context of a Session.
///
/// Multiple inflight requests can share the same `RequestId`,
/// but doing so may make Arti's responses ambiguous.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum RequestId {
    /// A client-provided string.
    //
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Str(Box<str>),
    /// A client-provided integer.
    ///
    /// [I-JSON] says that we don't have to handle any integer that can't be
    /// represented as an `f64`, but we do anyway.  This won't confuse clients,
    /// since we won't send them any integer that they didn't send us first.
    ///
    /// [I-JSON]: https://www.rfc-editor.org/rfc/rfc7493
    Int(i64),
}

/// Metadata associated with a single Request.
//
// NOTE: When adding new fields to this type, make sure that `Default` gives
// the correct value for an absent metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ReqMeta {
    /// If true, the client will accept intermediate Updates other than the
    /// final Request or Response.
    #[serde(default)]
    pub(crate) updates: bool,

    /// A list of features which must be implemented in order to understand the request.
    /// If any feature in this list is not available, the request must be rejected.
    #[serde(default)]
    pub(crate) require: Vec<String>,
}

/// A single Request received from an RPC client.
#[derive(Debug, Deserialize)]
pub(crate) struct Request {
    /// The client's identifier for this request.
    ///
    /// We'll use this to link all responses to this request.
    pub(crate) id: RequestId,
    /// The object to receive this request.
    pub(crate) obj: rpc::ObjectId,
    /// Any metadata to explain how this request is handled.
    #[serde(default)]
    pub(crate) meta: ReqMeta,
    /// The method to actually execute.
    ///
    /// Using "flatten" here will make it expand to "method" and "params".
    #[serde(flatten)]
    pub(crate) method: Box<dyn rpc::DeserMethod>,
}

/// A request that may or may not be valid.
///
/// If it invalid, it contains information that can be used to construct an error.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum FlexibleRequest {
    /// A valid request.
    Valid(Request),
    /// An invalid request.
    Invalid(invalid::InvalidRequest),
    // TODO RPC: Right now `InvalidRequest` should handle any Json Object,
    // but we might additionally want to parse any Json _Value_
    // (and reject it without killing the connection).
    // If we do, we ought to add a third variant here.
    //
    // Without this change, our implementation will be slightly more willing to close connections
    // than the spec requires:
    // The spec says we need to kill a connection on anything that can't be parsed as Json;
    // we kill a connection on anything that can't be parsed as a Json _Object_.
}

/// A Response to send to an RPC client.
#[derive(Debug, Serialize)]
pub(crate) struct BoxedResponse {
    /// An ID for the request that we're responding to.
    ///
    /// This is always present on a response to every valid request; it is also
    /// present on responses to invalid requests if we could discern what their
    /// `id` field was. We only omit it when the request id was indeterminate.
    /// If we do that, we close the connection immediately afterwards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<RequestId>,
    /// The body  that we're sending.
    #[serde(flatten)]
    pub(crate) body: ResponseBody,
}

impl BoxedResponse {
    /// Construct a BoxedResponse from an error that can be converted into an
    /// RpcError.
    pub(crate) fn from_error<E>(id: Option<RequestId>, error: E) -> Self
    where
        E: Into<rpc::RpcError>,
    {
        let error: rpc::RpcError = error.into();
        let body = ResponseBody::Error(Box::new(error));
        Self { id, body }
    }
}

/// The body of a response for an RPC client.
#[derive(Serialize)]
pub(crate) enum ResponseBody {
    /// The request has failed; no more responses will be sent in reply to it.
    #[serde(rename = "error")]
    Error(Box<rpc::RpcError>),
    /// The request has succeeded; no more responses will be sent in reply to
    /// it.
    ///
    /// Note that in the spec, this is called a "result": we don't propagate
    /// that terminology into Rust, where `Result` has a different meaning.
    #[serde(rename = "result")]
    Success(Box<dyn erased_serde::Serialize + Send>),
    /// The request included the `updates` flag to increment that incremental
    /// progress information is acceptable.
    #[serde(rename = "update")]
    Update(Box<dyn erased_serde::Serialize + Send>),
}

impl ResponseBody {
    /// Return true if this body type indicates that no future responses will be
    /// sent for this request.
    pub(crate) fn is_final(&self) -> bool {
        match self {
            ResponseBody::Error(_) | ResponseBody::Success(_) => true,
            ResponseBody::Update(_) => false,
        }
    }
}

impl From<rpc::RpcError> for ResponseBody {
    fn from(inp: rpc::RpcError) -> ResponseBody {
        ResponseBody::Error(Box::new(inp))
    }
}

impl std::fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // We use serde_json to format the output for debugging, since that's all we care about at this point.
        let json = |x| match serde_json::to_string(x) {
            Ok(s) => s,
            Err(e) => format!("«could not serialize: {}»", e),
        };
        match self {
            Self::Error(arg0) => f.debug_tuple("Error").field(arg0).finish(),
            Self::Update(arg0) => f.debug_tuple("Update").field(&json(arg0)).finish(),
            Self::Success(arg0) => f.debug_tuple("Success").field(&json(arg0)).finish(),
        }
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
    use derive_deftly::Deftly;
    use tor_rpcbase::templates::*;

    /// Assert that two arguments have the same output from `std::fmt::Debug`.
    ///
    /// This can be handy for testing for some notion of equality on objects
    /// that implement `Debug` but not `PartialEq`.
    macro_rules! assert_dbg_eq {
        ($a:expr, $b:expr) => {
            assert_eq!(format!("{:?}", $a), format!("{:?}", $b));
        };
    }

    // TODO RPC: note that the existence of this method type can potentially
    // leak into our real RPC engine when we're compiled with `test` enabled!
    // We should consider how bad this is, and maybe use a real method instead.
    #[derive(Debug, serde::Deserialize, Deftly)]
    #[derive_deftly(DynMethod)]
    #[deftly(rpc(method_name = "x-test:dummy"))]
    struct DummyMethod {
        #[serde(default)]
        #[allow(dead_code)]
        stuff: u64,
    }

    impl rpc::RpcMethod for DummyMethod {
        type Output = DummyResponse;
        type Update = rpc::NoUpdates;
    }

    #[derive(Serialize)]
    struct DummyResponse {
        hello: i64,
        world: String,
    }

    #[test]
    fn valid_requests() {
        let parse_request = |s| match serde_json::from_str::<FlexibleRequest>(s) {
            Ok(FlexibleRequest::Valid(req)) => req,
            other => panic!("{:?}", other),
        };

        let r =
            parse_request(r#"{"id": 7, "obj": "hello", "method": "x-test:dummy", "params": {} }"#);
        assert_dbg_eq!(
            r,
            Request {
                id: RequestId::Int(7),
                obj: rpc::ObjectId::from("hello"),
                meta: ReqMeta::default(),
                method: Box::new(DummyMethod { stuff: 0 })
            }
        );
    }

    #[test]
    fn invalid_requests() {
        use crate::err::RequestParseError as RPE;
        fn parsing_error(s: &str) -> RPE {
            match serde_json::from_str::<FlexibleRequest>(s) {
                Ok(FlexibleRequest::Invalid(req)) => req.error(),
                x => panic!("Didn't expect {:?}", x),
            }
        }

        macro_rules! expect_err {
            ($p:pat, $e:expr) => {
                let err = parsing_error($e);
                assert!(matches!(err, $p), "Unexpected error type {:?}", err);
            };
        }

        expect_err!(
            RPE::IdMissing,
            r#"{ "obj": "hello", "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::IdType,
            r#"{ "id": {}, "obj": "hello", "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::ObjMissing,
            r#"{ "id": 3, "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::ObjType,
            r#"{ "id": 3, "obj": 9, "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::MethodMissing,
            r#"{ "id": 3, "obj": "hello",  "params": {} }"#
        );
        expect_err!(
            RPE::MethodType,
            r#"{ "id": 3, "obj": "hello", "method": [], "params": {} }"#
        );
        expect_err!(
            RPE::MetaType,
            r#"{ "id": 3, "obj": "hello", "meta": 7, "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::MetaType,
            r#"{ "id": 3, "obj": "hello", "meta": { "updates": 3}, "method": "x-test:dummy", "params": {} }"#
        );
        expect_err!(
            RPE::MethodNotFound,
            r#"{ "id": 3, "obj": "hello", "method": "arti:this-is-not-a-method", "params": {} }"#
        );
        expect_err!(
            RPE::MissingParams,
            r#"{ "id": 3, "obj": "hello", "method": "x-test:dummy" }"#
        );
        expect_err!(
            RPE::ParamType,
            r#"{ "id": 3, "obj": "hello", "method": "x-test:dummy", "params": 7 }"#
        );
    }

    #[test]
    fn fmt_replies() {
        let resp = BoxedResponse {
            id: Some(RequestId::Int(7)),
            body: ResponseBody::Success(Box::new(DummyResponse {
                hello: 99,
                world: "foo".into(),
            })),
        };
        let s = serde_json::to_string(&resp).unwrap();
        // NOTE: This is a bit fragile for a test, since nothing in serde or
        // serde_json guarantees that the fields will be serialized in this
        // exact order.
        assert_eq!(s, r#"{"id":7,"result":{"hello":99,"world":"foo"}}"#);

        let resp = BoxedResponse {
            id: None,
            body: ResponseBody::Error(Box::new(rpc::RpcError::from(
                crate::err::RequestParseError::IdMissing,
            ))),
        };
        let s = serde_json::to_string(&resp).unwrap();
        // NOTE: as above.
        assert_eq!(
            s,
            r#"{"error":{"message":"error: Request did not have any `id` field.","code":-32600,"kinds":["arti:RpcInvalidRequest"]}}"#
        );
    }
}
