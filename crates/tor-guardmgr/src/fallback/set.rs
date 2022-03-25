//! Declare the [`FallbackSet`] type, which is used to store a set of FallbackDir.

use rand::seq::IteratorRandom;
use std::iter::FromIterator;

use super::FallbackDir;
use crate::PickGuardError;
use serde::Deserialize;

/// A list of fallback directories.
///
/// Fallback directories (represented by [`FallbackDir`]) are used by Tor
/// clients when they don't already have enough other directory information to
/// contact the network.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct FallbackList {
    /// The underlying fallbacks in this set.
    fallbacks: Vec<FallbackDir>,
}

impl FromIterator<FallbackDir> for FallbackList {
    fn from_iter<T: IntoIterator<Item = FallbackDir>>(iter: T) -> Self {
        FallbackList {
            fallbacks: iter.into_iter().collect(),
        }
    }
}

impl<T: IntoIterator<Item = FallbackDir>> From<T> for FallbackList {
    fn from(fallbacks: T) -> Self {
        FallbackList {
            fallbacks: fallbacks.into_iter().collect(),
        }
    }
}

impl FallbackList {
    /// Return the number of fallbacks in this list.
    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }
    /// Return true if there are no fallbacks in this list.
    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }
    /// Return a random member of this list.
    pub fn choose<R: rand::Rng>(&self, rng: &mut R) -> Result<&FallbackDir, PickGuardError> {
        // TODO: Return NoCandidatesAvailable when the fallback list is empty.
        self.fallbacks
            .iter()
            .choose(rng)
            .ok_or(PickGuardError::AllFallbacksDown { retry_at: None })
    }
}
