//! Support for encoding and decoding RPC Requests.
//!
//! There are several types in this module:
//!
//! - [`Request`] is for requests that are generated from within this crate,
//!   to implement authentication, negotiation, and other functionality.
//! - `ParsedRequestFields` (internal) is for a request we've completely validated,
//!   with all of its fields present.
//! - [`ValidatedRequest`] is for a string that we have validated as a request.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Alias for a Map as used by the serde_json.
pub(crate) type JsonMap = serde_json::Map<String, serde_json::Value>;

use crate::conn::ProtoError;

use super::{AnyRequestId, JsonAnyObj, ObjectId};

/// An outbound request that we have generated from within this crate.
///
/// It lacks a required `id` field (since we will generate one when sending it),
/// and it allows any Serialize for its `params`.
#[derive(Serialize, Debug)]
// Testing only. Don't implement Deserialize here; this is not the type you should parse into!
#[cfg_attr(test, derive(Eq, PartialEq, Deserialize))]
#[allow(clippy::missing_docs_in_private_items)] // Fields are as for ParsedRequest.
pub(crate) struct Request<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<AnyRequestId>,
    pub(crate) obj: ObjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) meta: Option<RequestMeta>,
    pub(crate) method: String,
    pub(crate) params: T,
}

/// An error that has prevented us from validating an request.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidRequestError {
    /// We failed to turn the request into any kind of json.
    #[error("Request was not valid Json")]
    InvalidJson(#[source] Arc<serde_json::Error>),
    /// We got the request into json, but we couldn't find the fields we wanted.
    #[error("Request's fields were invalid or missing")]
    InvalidFormat(#[source] Arc<serde_json::Error>),
    /// We validated the request, but couldn't re-encode it.
    #[error("Unable to re-encode or format request")]
    ReencodeFailed(#[source] Arc<serde_json::Error>),
}

impl<T: Serialize> Request<T> {
    /// Construct a new outbound Request.
    pub(crate) fn new(obj: ObjectId, method: impl Into<String>, params: T) -> Self {
        Self {
            id: None,
            obj,
            meta: Default::default(),
            method: method.into(),
            params,
        }
    }
    /// Try to encode this request as a String.
    ///
    /// The string may not yet be a valid request; it might need to get an ID assigned.
    pub(crate) fn encode(&self) -> Result<String, ProtoError> {
        serde_json::to_string(self).map_err(|e| ProtoError::CouldNotEncode(Arc::new(e)))
    }
}

/// A request in its decoded (or unencoded) format.
///
/// We use this type to validate outbound requests from the application.
#[derive(Deserialize, Debug)]
// Don't implement Serialize here; this is not for generating requests!
#[allow(dead_code)] // The fields here are only used for validating serde objects.
struct ParsedRequestFields {
    /// The identifier for this request.
    ///
    /// Used to match a request with its responses.
    id: AnyRequestId,
    /// The ID for the object to which this request is addressed.
    ///
    /// (Every request goes to a single object.)
    obj: ObjectId,
    /// Additional information for Arti about how to handle the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<RequestMeta>,
    /// The name of the method to invoke.
    method: String,
    /// Parameters to pass to the method.
    params: JsonAnyObj,
}

/// A known-valid request, encoded as a string (in a single line, with a terminating newline).
#[derive(derive_more::AsRef, Debug, Clone)]
pub(crate) struct ValidatedRequest {
    /// The message itself, as encoded.
    #[as_ref]
    msg: String,
    /// The ID for this request.
    id: AnyRequestId,
}

impl ValidatedRequest {
    /// Return the Id associated with this request.
    pub(crate) fn id(&self) -> &AnyRequestId {
        &self.id
    }

    /// Try to construct a validated request from a `serde_json::Value`.
    fn from_json_value(val: serde_json::Value) -> Result<Self, InvalidRequestError> {
        let mut msg = serde_json::to_string(&val)
            .map_err(|e| InvalidRequestError::ReencodeFailed(Arc::new(e)))?;
        debug_assert!(!msg.contains('\n'));
        msg.push('\n');

        let req: ParsedRequestFields = serde_json::from_value(val)
            .map_err(|e| InvalidRequestError::InvalidFormat(Arc::new(e)))?;
        let id = req.id;

        Ok(ValidatedRequest { id, msg })
    }

    /// Try to construct a validated request using `s`.
    pub(crate) fn from_string_strict(s: &str) -> Result<Self, InvalidRequestError> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|e| InvalidRequestError::InvalidJson(Arc::new(e)))?;
        Self::from_json_value(value)
    }

    /// Try to construct a ValidatedRequest from the string in `s`.
    ///
    /// If it has no `id`, add one using `id_generator`.
    pub(crate) fn from_string_loose<F>(
        s: &str,
        id_generator: F,
    ) -> Result<Self, InvalidRequestError>
    where
        F: FnOnce() -> AnyRequestId,
    {
        let mut value: serde_json::Value =
            serde_json::from_str(s).map_err(|e| InvalidRequestError::InvalidJson(Arc::new(e)))?;

        if let Some(obj) = value.as_object_mut() {
            obj.entry("id")
                .or_insert_with(|| id_generator().into_json_value());
        }

        Self::from_json_value(value)
    }
}

/// Crate-internal: The "meta" field in a request.
#[derive(Deserialize, Serialize, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct RequestMeta {
    /// If true, the application wants to receive incremental updates
    /// about the request that it sent.
    ///
    /// (Default: false)
    #[serde(default)]
    pub(crate) updates: bool,
    /// Any unrecognized fields that we received from the user.
    /// (We re-encode these in case the user knows about fields that we don't.)
    #[serde(flatten)]
    pub(crate) unrecognized_fields: JsonMap,
}

/// A helper to return unique Request identifiers.
///
/// All identifiers are prefixed with `"!aut o!--"`:
/// if you don't use that string in your own IDs,
/// you won't have any collisions.
#[derive(Debug, Default)]
pub(crate) struct IdGenerator {
    /// The number
    next_id: u64,
}

impl IdGenerator {
    /// Return a previously unyielded identifier.
    pub(crate) fn next_id(&mut self) -> AnyRequestId {
        let id = self.next_id;
        self.next_id += 1;
        format!("!auto!--{id}").into()
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

    impl ParsedRequestFields {
        /// Return true if this request is asking for updates.
        fn updates_requested(&self) -> bool {
            self.meta.as_ref().map(|m| m.updates).unwrap_or(false)
        }
    }

    use crate::util::assert_same_json;

    use super::*;
    const REQ1: &str = r#"{"id":7, "obj": "hi", "meta": {"updates": true}, "method":"twiddle", "params":{"stuff": "nonsense"} }"#;
    const REQ2: &str = r#"{"id":"fred", "obj": "hi", "method":"twiddle", "params":{} }"#;
    const REQ3: &str =
        r#"{"id":"fred", "obj": "hi", "method":"twiddle", "params":{},"unrecognized":"waffles"}"#;

    #[test]
    fn parse_requests() {
        let req1: ParsedRequestFields = serde_json::from_str(REQ1).unwrap();
        assert_eq!(req1.id, 7.into());
        assert_eq!(req1.obj.as_ref(), "hi");
        assert_eq!(req1.updates_requested(), true);
        assert_eq!(req1.method, "twiddle");

        let req2: ParsedRequestFields = serde_json::from_str(REQ2).unwrap();
        assert_eq!(req2.id, "fred".to_string().into());
        assert_eq!(req2.obj.as_ref(), "hi");
        assert_eq!(req2.updates_requested(), false);
        assert_eq!(req2.method, "twiddle");

        let _req3: ParsedRequestFields = serde_json::from_str(REQ2).unwrap();
    }

    #[test]
    fn reencode_requests() {
        for r in [REQ1, REQ2, REQ3] {
            let val1 = ValidatedRequest::from_string_strict(r).unwrap();
            let val2 = ValidatedRequest::from_string_loose(r, || panic!()).unwrap();

            assert_same_json!(val1.as_ref(), val2.as_ref());
            assert_same_json!(val1.as_ref(), r);
        }
    }

    #[test]
    fn bad_requests() {
        for text in [
            // not an object.
            "123",
            // missing most parts.
            r#"{"id":12,}"#,
            // no id.
            r#"{"obj":"hi", "method":"twiddle", "params":{"stuff":"nonsense"}}"#,
            // no params
            r#"{"obj":"hi", "id": 7, "method":"twiddle"}"#,
            // bad params type
            r#"{"obj":"hi", "id": 7, "method":"twiddle", "params": []}"#,
            // weird obj.
            r#"{"obj":7, "id": 7, "method":"twiddle", "params":{"stuff":"nonsense"}}"#,
            // weird id.
            r#"{"obj":"hi", "id": [], "method":"twiddle", "params":{"stuff":"nonsense"}}"#,
            // weird method
            r#"{"obj":"hi", "id": 7, "method":6", "params":{"stuff":"nonsense"}}"#,
        ] {
            let r: Result<ParsedRequestFields, _> = serde_json::from_str(dbg!(text));
            assert!(r.is_err());
        }
    }

    #[test]
    fn fix_requests() {
        let no_id = r#"{"obj":"hi", "method":"twiddle", "params":{"stuff":"nonsense"}}"#;
        let validated = ValidatedRequest::from_string_loose(no_id, || 7.into()).unwrap();
        let expected_with_id =
            r#"{"id": 7, "obj":"hi", "method":"twiddle", "params":{"stuff":"nonsense"}}"#;
        assert_same_json!(validated.as_ref(), expected_with_id);
    }

    #[test]
    fn preserve_fields() {
        let orig = r#"
            {"obj":"hi",
             "meta": { "updates": true, "waffles": "yesplz" },
             "method":"twiddle",
             "params":{"stuff":"nonsense"},
             "explosions": -70
            }"#;
        let validated = ValidatedRequest::from_string_loose(orig, || 77.into()).unwrap();
        let expected_with_id = r#"
            {"id":77,
            "obj":"hi",
            "meta": { "updates": true, "waffles": "yesplz" },
            "method":"twiddle",
            "params":{"stuff":"nonsense"},
            "explosions": -70
            }"#;
        assert_same_json!(validated.as_ref(), expected_with_id);
    }
}
