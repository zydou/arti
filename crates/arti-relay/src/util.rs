//! Miscellaneous utility functions/macros/types.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(into = "Vec<T>")]
#[serde(try_from = "Vec<T>")]
/// A list that contains at least one item.
///
/// We mainly use this for ensuring the user configures at least one item during config
/// deserialization, but may be useful for enforcing at least one item in the type system.
pub(crate) struct NonEmptyList<T: Clone>(T, Vec<T>);

impl<T: Clone> NonEmptyList<T> {
    /// Get the items in the list.
    ///
    /// Is guaranteed to have at least one item.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        Some(&self.0).into_iter().chain(&self.1)
    }
}

impl<T: Clone> From<NonEmptyList<T>> for Vec<T> {
    fn from(from: NonEmptyList<T>) -> Vec<T> {
        Some(from.0).into_iter().chain(from.1).collect()
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyList<T> {
    type Error = EmptyListError;

    fn try_from(mut from: Vec<T>) -> Result<Self, Self::Error> {
        if from.is_empty() {
            return Err(EmptyListError);
        }
        Ok(Self(from.remove(0), from))
    }
}

#[derive(Debug, thiserror::Error)]
/// An error indicating that the list was empty, so cannot be converted to a [`NonEmptyList`].
#[error("The list is empty")]
pub(crate) struct EmptyListError;

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn non_empty_list() {
        let v = vec![1, 2, 3];
        let l: NonEmptyList<_> = v.clone().try_into().unwrap();
        assert_eq!(v, Vec::from(l));

        assert!(NonEmptyList::<u32>::try_from(Vec::new()).is_err());
    }
}
