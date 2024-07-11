use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub(crate) type JsonMap = serde_json::Map<String, serde_json::Value>;

use crate::{conn::CmdError, util::define_from_for_arc};

use super::{AnyRequestId, ObjectId};

/// A request in its decoded (or unencoded) format.
///
/// We use this type to validate outbound requests from the application,
/// and to generate our own requests.
//
// TODO RPC: Conceivably this should not be the same type as ParsedRequest.
#[derive(Deserialize, Serialize, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct Request<T> {
    pub(crate) id: AnyRequestId,
    pub(crate) obj: ObjectId,
    #[serde(default)]
    pub(crate) meta: RequestMeta,
    pub(crate) method: String,
    pub(crate) params: T,
    // TODO: This loses any extra fields that the application may have set.
    //  I am presuming that's okay, but we may want to revisit that.
}

impl<T: Serialize> Request<T> {
    pub(crate) fn encode(&self) -> Result<String, CmdError> {
        serde_json::to_string(self).map_err(|e| CmdError::CouldNotEncode(Arc::new(e)))
    }
}

/// Crate-internal: An outbound request.
///
/// We use this type to make sure that a request is syntactically valid before sending it out.
pub(crate) type ParsedRequest = Request<JsonMap>;

/// A known-valid request, encoded as a string (in a single line, with a terminating newline).
#[derive(derive_more::AsRef, Debug, Clone)]
pub(crate) struct ValidatedRequest {
    #[as_ref]
    msg: String,
    id: AnyRequestId,
}

impl ParsedRequest {
    /// Convert a ParsedRequest into a string that is known to be valid.
    pub(crate) fn format(&self) -> Result<ValidatedRequest, serde_json::Error> {
        let id = self.id.clone();
        let mut msg = serde_json::to_string(self)?;
        debug_assert!(!msg.contains('\n'));
        msg.push('\n');
        Ok(ValidatedRequest { id, msg })
    }

    /// Return the Id associated with this request.
    pub(crate) fn id(&self) -> &AnyRequestId {
        &self.id
    }
}

impl ValidatedRequest {
    /// Return the Id associated with this request.
    pub(crate) fn id(&self) -> &AnyRequestId {
        &self.id
    }
}

/// Crate-internal: The "meta" field in a request.
#[derive(Deserialize, Serialize, Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub(crate) struct RequestMeta {
    updates: bool,
}

/// Crate-internal: A parsed request from the application which may not (yet) be valid.
///
/// We can convert this into a ParsedRequest after fixing up any missing or invalid fields.
#[derive(Deserialize, Debug)]
pub(crate) struct LooseParsedRequest {
    id: Option<AnyRequestId>,
    obj: ObjectId,
    #[serde(default)]
    meta: RequestMeta,
    method: String,
    params: JsonMap,
    // TODO: This loses any extra fields that the application may have set.
    //  I am presuming that's okay, but we may want to revisit that.
}

impl LooseParsedRequest {
    pub(crate) fn into_request<F>(self, id_generator: F) -> ParsedRequest
    where
        F: FnOnce() -> AnyRequestId,
    {
        ParsedRequest {
            id: self.id.unwrap_or_else(id_generator),
            obj: self.obj,
            meta: self.meta,
            method: self.method,
            params: self.params,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct IdGenerator {
    next_id: u64,
}

impl IdGenerator {
    pub(crate) fn next_id(&mut self) -> AnyRequestId {
        let id = self.next_id;
        self.next_id += 1;
        format!("!auto!---{id}").into()
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RequestError {
    InvalidRequest(Arc<serde_json::Error>),
}
define_from_for_arc!( serde_json::Error => RequestError [InvalidRequest] );

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
    const REQ1: &str = r#"{"id":7, "obj": "hi", "meta": {"updates": true}, "method":"twiddle", "params":{"stuff": "nonsense"} }"#;
    const REQ2: &str = r#"{"id":"fred", "obj": "hi", "method":"twiddle", "params":{} }"#;
    const REQ3: &str =
        r#"{"id":"fred", "obj": "hi", "method":"twiddle", "params":{},"unrecognized":"waffles"}"#;

    #[test]
    fn parse_requests() {
        let req1: ParsedRequest = serde_json::from_str(REQ1).unwrap();
        assert_eq!(req1.id, 7.into());
        assert_eq!(req1.obj.as_ref(), "hi");
        assert_eq!(req1.meta.updates, true);
        assert_eq!(req1.method, "twiddle");
        assert_eq!(
            req1.params.get("stuff").unwrap(),
            &serde_json::Value::String("nonsense".into())
        );

        let req2: ParsedRequest = serde_json::from_str(REQ2).unwrap();
        assert_eq!(req2.id, "fred".to_string().into());
        assert_eq!(req2.obj.as_ref(), "hi");
        assert_eq!(req2.meta.updates, false);
        assert_eq!(req2.method, "twiddle");
        assert!(req2.params.is_empty());

        let _req3: ParsedRequest = serde_json::from_str(REQ2).unwrap();
    }
    #[test]
    fn reencode_requests() {
        for r in [REQ1, REQ2, REQ3] {
            let r: ParsedRequest = serde_json::from_str(r).unwrap();
            let v = r.format().unwrap();
            let r2: ParsedRequest = serde_json::from_str(v.as_ref()).unwrap();
            assert_eq!(r, r2);
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
            let r: Result<ParsedRequest, _> = serde_json::from_str(text);
            assert!(r.is_err());
        }
    }

    #[test]
    fn fix_requests() {
        let no_id = r#"{"obj":"hi", "method":"twiddle", "params":{"stuff":"nonsense"}}"#;
        let loose: LooseParsedRequest = serde_json::from_str(no_id).unwrap();
        let req = loose.into_request(|| 7.into());
        let with_id = req.format().unwrap();
        let req2: ParsedRequest = serde_json::from_str(with_id.as_ref()).unwrap();
        assert_eq!(req, req2);
    }
}
