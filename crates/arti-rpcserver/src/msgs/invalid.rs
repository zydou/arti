//! Variations on our message types used to give better diagnostics for
//! unparseable requests.

use tor_rpcbase as rpc;

use super::{ReqMeta, RequestId};
use crate::err::RequestParseError;

/// An invalid approximation of a request.  
///
/// If we can't deserialize a [`Request`] properly, we try to deserialize it into
/// _this_ structure so we can explain what was wrong with it.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct InvalidRequest {
    /// Possibly, an ID field.
    ///
    /// If we can't parse this, then there's no hope of giving back a cogent
    /// response.
    id: Option<Possibly<RequestId>>,
    /// The object that was passed in, if any.
    obj: Option<Possibly<rpc::ObjectId>>,
    /// The metadata that was passed in, if any.
    meta: Option<Possibly<ReqMeta>>,
    /// The method that was passed in, if any.
    method: Option<Possibly<String>>,
    /// The params that were passed in, if any.
    params: Option<serde_json::Value>,
}

/// Either a "good" value that we could deserialize as a `T`, or some "Bad" value that we couldn't.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum Possibly<T> {
    /// The value was deserialized as expected.
    Good(T),
    /// The value could not be deserialized as expected.
    Bad(serde_json::Value),
}

impl InvalidRequest {
    /// Return the ID for this request, if it has one.
    pub(crate) fn id(&self) -> Option<&RequestId> {
        match &self.id {
            Some(Possibly::Good(id)) => Some(id),
            _ => None,
        }
    }

    /// Return an error explaining why this wasn't a valid request.
    pub(crate) fn error(&self) -> RequestParseError {
        use Possibly::*;
        use RequestParseError as E;

        match self.id {
            None => return E::IdMissing,
            Some(Bad(_)) => return E::IdType,
            _ => {}
        }

        match self.obj {
            None => return E::ObjMissing,
            Some(Bad(_)) => return E::ObjType,
            _ => {}
        }

        match self.method {
            None => return E::MethodMissing,
            Some(Bad(_)) => return E::MethodType,
            _ => {}
        }

        if matches!(self.meta, Some(Bad(_))) {
            return E::MetaType;
        }

        if self.params.is_none() {
            return E::MissingParams;
        }

        // This is, sadly, the best we can do until we can look into the typetag
        // registry ourselves to see whether the method was recognized.
        E::MethodProblem
    }
}
