//! Types and code to map circuit IDs to circuits.

// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

use crate::{Error, Result};
use tor_basic_utils::RngExt;
use tor_cell::chancell::CircId;

use crate::circuit::{CircuitRxSender, celltypes::CreateResponse};
use crate::circuit::halfcirc::HalfCirc;

use oneshot_fused_workaround as oneshot;

use rand::distributions::Distribution;
use rand::Rng;
use std::collections::{hash_map::Entry, HashMap};
use std::ops::{Deref, DerefMut};

/// Which group of circuit IDs are we allowed to allocate in this map?
///
/// If we initiated the channel, we use High circuit ids.  If we're the
/// responder, we use low circuit ids.
#[derive(Copy, Clone)]
pub(super) enum CircIdRange {
    /// Only use circuit IDs with the MSB cleared.
    #[allow(dead_code)] // Relays will need this.
    Low,
    /// Only use circuit IDs with the MSB set.
    High,
    // Historical note: There used to be an "All" range of circuit IDs
    // available to clients only.  We stopped using "All" when we moved to link
    // protocol version 4.
}

impl rand::distributions::Distribution<CircId> for CircIdRange {
    /// Return a random circuit ID in the appropriate range.
    fn sample<R: Rng + ?Sized>(&self, mut rng: &mut R) -> CircId {
        let midpoint = 0x8000_0000_u32;
        let v = match self {
            // 0 is an invalid value
            CircIdRange::Low => rng.gen_range_checked(1..midpoint),
            CircIdRange::High => rng.gen_range_checked(midpoint..=u32::MAX),
        };
        let v = v.expect("Unexpected empty range passed to gen_range_checked");
        CircId::new(v).expect("Unexpected zero value")
    }
}

/// An entry in the circuit map.  Right now, we only have "here's the
/// way to send cells to a given circuit", but that's likely to
/// change.
#[derive(Debug)]
pub(super) enum CircEnt {
    /// A circuit that has not yet received a CREATED cell.
    ///
    /// For this circuit, the CREATED* cell or DESTROY cell gets sent
    /// to the oneshot sender to tell the corresponding
    /// PendingClientCirc that the handshake is done.
    ///
    /// Once that's done, the mpsc sender will be used to send subsequent
    /// cells to the circuit.
    Opening(
        oneshot::Sender<CreateResponse>,
        CircuitRxSender,
    ),

    /// A circuit that is open and can be given relay cells.
    Open(CircuitRxSender),

    /// A circuit where we have sent a DESTROY, but the other end might
    /// not have gotten a DESTROY yet.
    DestroySent(HalfCirc),
}

/// An "smart pointer" that wraps an exclusive reference
/// of a `CircEnt`.
///
/// When being dropped, this object updates the open or opening entries
/// counter of the `CircMap`.
pub(super) struct MutCircEnt<'a> {
    /// An exclusive reference to the `CircEnt`.
    value: &'a mut CircEnt,
    /// An exclusive reference to the open or opening
    ///  entries counter.
    open_count: &'a mut usize,
    /// True if the entry was open or opening when borrowed.
    was_open: bool,
}

impl<'a> Drop for MutCircEnt<'a> {
    fn drop(&mut self) {
        let is_open = !matches!(self.value, CircEnt::DestroySent(_));
        match (self.was_open, is_open) {
            (false, true) => *self.open_count = self.open_count.saturating_add(1),
            (true, false) => *self.open_count = self.open_count.saturating_sub(1),
            (_, _) => (),
        };
    }
}

impl<'a> Deref for MutCircEnt<'a> {
    type Target = CircEnt;
    fn deref(&self) -> &Self::Target {
        self.value
    }
}

impl<'a> DerefMut for MutCircEnt<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
    }
}

/// A map from circuit IDs to circuit entries. Each channel has one.
pub(super) struct CircMap {
    /// Map from circuit IDs to entries
    m: HashMap<CircId, CircEnt>,
    /// Rule for allocating new circuit IDs.
    range: CircIdRange,
    /// Number of open or opening entry in this map.
    open_count: usize,
}

impl CircMap {
    /// Make a new empty CircMap
    pub(super) fn new(idrange: CircIdRange) -> Self {
        CircMap {
            m: HashMap::new(),
            range: idrange,
            open_count: 0,
        }
    }

    /// Add a new pair of elements (corresponding to a PendingClientCirc)
    /// to this map.
    ///
    /// On success return the allocated circuit ID.
    pub(super) fn add_ent<R: Rng>(
        &mut self,
        rng: &mut R,
        createdsink: oneshot::Sender<CreateResponse>,
        sink: CircuitRxSender,
    ) -> Result<CircId> {
        /// How many times do we probe for a random circuit ID before
        /// we assume that the range is fully populated?
        ///
        /// TODO: C tor does 64, but that is probably overkill with 4-byte circuit IDs.
        const N_ATTEMPTS: usize = 16;
        let iter = self.range.sample_iter(rng).take(N_ATTEMPTS);
        let circ_ent = CircEnt::Opening(createdsink, sink);
        for id in iter {
            let ent = self.m.entry(id);
            if let Entry::Vacant(_) = &ent {
                ent.or_insert(circ_ent);
                self.open_count += 1;
                return Ok(id);
            }
        }
        Err(Error::IdRangeFull)
    }

    /// Testing only: install an entry in this circuit map without regard
    /// for consistency.
    #[cfg(test)]
    pub(super) fn put_unchecked(&mut self, id: CircId, ent: CircEnt) {
        self.m.insert(id, ent);
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: CircId) -> Option<MutCircEnt> {
        let open_count = &mut self.open_count;
        self.m.get_mut(&id).map(move |ent| MutCircEnt {
            open_count,
            was_open: !matches!(ent, CircEnt::DestroySent(_)),
            value: ent,
        })
    }

    /// See whether 'id' is an opening circuit.  If so, mark it "open" and
    /// return a oneshot::Sender that is waiting for its create cell.
    pub(super) fn advance_from_opening(
        &mut self,
        id: CircId,
    ) -> Result<oneshot::Sender<CreateResponse>> {
        // TODO: there should be a better way to do
        // this. hash_map::Entry seems like it could be better, but
        // there seems to be no way to replace the object in-place as
        // a consuming function of itself.
        let ok = matches!(self.m.get(&id), Some(CircEnt::Opening(_, _)));
        if ok {
            if let Some(CircEnt::Opening(oneshot, sink)) = self.m.remove(&id) {
                self.m.insert(id, CircEnt::Open(sink));
                Ok(oneshot)
            } else {
                panic!("internal error: inconsistent circuit state");
            }
        } else {
            Err(Error::ChanProto(
                "Unexpected CREATED* cell not on opening circuit".into(),
            ))
        }
    }

    /// Called when we have sent a DESTROY on a circuit.  Configures
    /// a "HalfCirc" object to track how many cells we get on this
    /// circuit, and to prevent us from reusing it immediately.
    pub(super) fn destroy_sent(&mut self, id: CircId, hs: HalfCirc) {
        if let Some(replaced) = self.m.insert(id, CircEnt::DestroySent(hs)) {
            if !matches!(replaced, CircEnt::DestroySent(_)) {
                // replaced an Open/Opening entry with DestroySent
                self.open_count = self.open_count.saturating_sub(1);
            }
        }
    }

    /// Extract the value from this map with 'id' if any
    pub(super) fn remove(&mut self, id: CircId) -> Option<CircEnt> {
        self.m.remove(&id).map(|removed| {
            if !matches!(removed, CircEnt::DestroySent(_)) {
                self.open_count = self.open_count.saturating_sub(1);
            }
            removed
        })
    }

    /// Return the total number of open and opening entries in the map
    pub(super) fn open_ent_count(&self) -> usize {
        self.open_count
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // circuit IDs chosen by somebody else. But for now, we don't need those.
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
    use futures::channel::mpsc;
    use tor_basic_utils::test_rng::testing_rng;

    #[test]
    fn circmap_basics() {
        let mut map_low = CircMap::new(CircIdRange::Low);
        let mut map_high = CircMap::new(CircIdRange::High);
        let mut ids_low: Vec<CircId> = Vec::new();
        let mut ids_high: Vec<CircId> = Vec::new();
        let mut rng = testing_rng();

        assert!(map_low.get_mut(CircId::new(77).unwrap()).is_none());

        for _ in 0..128 {
            let (csnd, _) = oneshot::channel();
            let (snd, _) = mpsc::channel(8);
            let id_low = map_low.add_ent(&mut rng, csnd, snd).unwrap();
            assert!(u32::from(id_low) > 0);
            assert!(u32::from(id_low) < 0x80000000);
            assert!(!ids_low.iter().any(|x| *x == id_low));
            ids_low.push(id_low);

            assert!(matches!(
                *map_low.get_mut(id_low).unwrap(),
                CircEnt::Opening(_, _)
            ));

            let (csnd, _) = oneshot::channel();
            let (snd, _) = mpsc::channel(8);
            let id_high = map_high.add_ent(&mut rng, csnd, snd).unwrap();
            assert!(u32::from(id_high) >= 0x80000000);
            assert!(!ids_high.iter().any(|x| *x == id_high));
            ids_high.push(id_high);
        }

        // Test open / opening entry counting
        assert_eq!(128, map_low.open_ent_count());
        assert_eq!(128, map_high.open_ent_count());

        // Test remove
        assert!(map_low.get_mut(ids_low[0]).is_some());
        map_low.remove(ids_low[0]);
        assert!(map_low.get_mut(ids_low[0]).is_none());
        assert_eq!(127, map_low.open_ent_count());

        // Test DestroySent doesn't count
        map_low.destroy_sent(CircId::new(256).unwrap(), HalfCirc::new(1));
        assert_eq!(127, map_low.open_ent_count());

        // Test advance_from_opening.

        // Good case.
        assert!(map_high.get_mut(ids_high[0]).is_some());
        assert!(matches!(
            *map_high.get_mut(ids_high[0]).unwrap(),
            CircEnt::Opening(_, _)
        ));
        let adv = map_high.advance_from_opening(ids_high[0]);
        assert!(adv.is_ok());
        assert!(matches!(
            *map_high.get_mut(ids_high[0]).unwrap(),
            CircEnt::Open(_)
        ));

        // Can't double-advance.
        let adv = map_high.advance_from_opening(ids_high[0]);
        assert!(adv.is_err());

        // Can't advance an entry that is not there.  We know "77"
        // can't be in map_high, since we only added high circids to
        // it.
        let adv = map_high.advance_from_opening(CircId::new(77).unwrap());
        assert!(adv.is_err());
    }
}
