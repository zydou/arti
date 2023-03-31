use serde::{Deserialize, Serialize};

pub trait Object {}

/// An identifier for an Object within the context of a Session.
///
/// These are opaque from the client's perspective.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Box<str>,
);

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T> From<T> for ObjectId
where
    T: Into<Box<str>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}
