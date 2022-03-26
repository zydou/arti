//! Declare the [`FallbackSet`] type, which is used to store a set of FallbackDir.

use rand::seq::IteratorRandom;
use std::{iter::FromIterator, time::Instant};

use super::{FallbackDir, Status};
use crate::{GuardId, PickGuardError};
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

/// A set of fallback directories, in usable form.
#[derive(Debug, Clone)]
pub(crate) struct FallbackSet {
    /// The list of fallbacks in the set.
    ///
    /// We require that these are sorted and unique by (ED,RSA) keys.
    fallbacks: Vec<Entry>,
}

/// Wrapper type for FallbackDir converted into crate::Guard, and Status.
///
/// Defines a sort order to ensure that we can look up fallback directories
/// by binary search on keys.
#[derive(Debug, Clone)]
pub(super) struct Entry {
    /// The inner fallback directory.
    pub(super) fallback: crate::Guard,
    /// The status for the fallback directory.
    pub(super) status: Status,
}

impl From<FallbackDir> for Entry {
    fn from(fallback: FallbackDir) -> Self {
        let fallback = fallback.as_guard();
        let status = Status::default();
        Entry { fallback, status }
    }
}

impl Entry {
    /// Return the identity for this fallback entry.
    fn id(&self) -> &GuardId {
        self.fallback.id()
    }
}

impl From<FallbackList> for FallbackSet {
    fn from(list: FallbackList) -> Self {
        let mut fallbacks: Vec<Entry> = list.fallbacks.into_iter().map(|fb| fb.into()).collect();
        fallbacks.sort_by(|x, y| x.id().cmp(y.id()));
        fallbacks.dedup_by(|x, y| x.id() == y.id());
        FallbackSet { fallbacks }
    }
}

impl FallbackSet {
    /// Return a random member of this FallbackSet that's usable at `now`.
    pub(crate) fn choose<R: rand::Rng>(
        &self,
        rng: &mut R,
        now: Instant,
    ) -> Result<&crate::Guard, PickGuardError> {
        if self.fallbacks.is_empty() {
            return Err(PickGuardError::NoCandidatesAvailable);
        }

        self.fallbacks
            .iter()
            .filter(|ent| ent.status.usable_at(now))
            .choose(rng)
            .map(|ent| &ent.fallback)
            .ok_or_else(|| PickGuardError::AllFallbacksDown {
                retry_at: self.next_retry(),
            })
    }

    /// Return the next time at which any member of this set will become ready.
    ///
    /// Returns None if no elements are failing.
    fn next_retry(&self) -> Option<Instant> {
        self.fallbacks
            .iter()
            .filter_map(|ent| ent.status.next_retriable())
            .min()
    }

    /// Return a mutable reference to the entry whose identity is `id`, if there is one.
    fn lookup_mut(&mut self, id: &GuardId) -> Option<&mut Entry> {
        match self.fallbacks.binary_search_by(|e| e.id().cmp(id)) {
            Ok(idx) => Some(&mut self.fallbacks[idx]),
            Err(_) => None,
        }
    }

    /// Record that a success has occurred for the fallback with the given
    /// identity.
    ///
    /// Be aware that for fallbacks, we only count a successful directory
    /// operation as a success: a circuit success is not enough.
    pub(crate) fn note_success(&mut self, id: &GuardId) {
        if let Some(entry) = self.lookup_mut(id) {
            entry.status.note_success();
        }
    }

    /// Record that a failure has occurred for the fallback with the given
    /// identity.
    pub(crate) fn note_failure(&mut self, id: &GuardId, now: Instant) {
        if let Some(entry) = self.lookup_mut(id) {
            entry.status.note_failure(now);
        }
    }

    /// Consume `other` and copy all of its fallback status entries into the corresponding entries for `self`.
    pub(crate) fn take_status_from(&mut self, other: FallbackSet) {
        matching_items(
            self.fallbacks.iter_mut(),
            other.fallbacks.into_iter(),
            |a, b| a.fallback.id().cmp(b.fallback.id()),
        )
        .for_each(|(entry, other)| {
            debug_assert_eq!(entry.fallback.id(), other.fallback.id());
            entry.status = other.status;
        });
    }
}

/// Return an iterator that iterates over two sorted lists and yields all items
/// from those lists that match according to a comparison function.
///
/// Results may be incorrect if the input lists are not sorted, but the iterator
/// should not panic.
///
/// TODO: If this proves generally useful, move it to another tor-basic-utils or
/// a new crate.  If there is already functionality for this externally, use it.
fn matching_items<I1, I2, F>(iter1: I1, iter2: I2, cmp: F) -> MatchingItems<I1, I2, F>
where
    I1: Iterator,
    I2: Iterator,
    F: FnMut(&I1::Item, &I2::Item) -> std::cmp::Ordering,
{
    MatchingItems {
        iter1: iter1.peekable(),
        iter2: iter2.peekable(),
        cmp,
    }
}

/// Type to implement `matching_items()`
struct MatchingItems<I1, I2, F>
where
    I1: Iterator,
    I2: Iterator,
    F: FnMut(&I1::Item, &I2::Item) -> std::cmp::Ordering,
{
    /// The first iterator to examine
    iter1: std::iter::Peekable<I1>,
    /// The second iterator to examine
    iter2: std::iter::Peekable<I2>,
    /// A function to compare the items in the two iterators.
    cmp: F,
}

impl<I1, I2, F> Iterator for MatchingItems<I1, I2, F>
where
    I1: Iterator,
    I2: Iterator,
    F: FnMut(&I1::Item, &I2::Item) -> std::cmp::Ordering,
{
    type Item = (I1::Item, I2::Item);

    fn next(&mut self) -> Option<Self::Item> {
        use std::cmp::Ordering::*;

        loop {
            let (n1, n2) = match (self.iter1.peek(), self.iter2.peek()) {
                (Some(a), Some(b)) => (a, b),
                (_, _) => return None, // at least one iterator is exhausted.
            };

            match (self.cmp)(n1, n2) {
                Less => {
                    let _ignore = self.iter1.next();
                }
                Equal => {
                    return Some((
                        self.iter1.next().expect("Peek/Next inconsistency"),
                        self.iter2.next().expect("Peek/Next inconsistency"),
                    ))
                }
                Greater => {
                    let _ignore = self.iter2.next();
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    #[test]
    fn matching_items() {
        let odds = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
        let primes = ["2", "3", "5", "7", "11", "13", "17", "19"];

        let matches: Vec<_> = super::matching_items(odds.iter(), primes.iter(), |i, s| {
            (*i).cmp(&s.parse().unwrap())
        })
        .map(|(i, s)| (*i, *s))
        .collect();

        assert_eq!(
            matches,
            vec![
                (3, "3"),
                (5, "5"),
                (7, "7"),
                (11, "11"),
                (13, "13"),
                (17, "17"),
                (19, "19")
            ]
        );
    }
}
