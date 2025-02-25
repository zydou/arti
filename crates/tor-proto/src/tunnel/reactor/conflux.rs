//! Conflux-related functionality

use slotmap_careful::SlotMap;

use tor_error::{bad_api_usage, internal, Bug};

use crate::util::err::ReactorError;

use super::{Circuit, LegIdKey};

/// A set of linked conflux circuits.
pub(super) struct ConfluxSet {
    /// The circuits in this conflux set.
    legs: SlotMap<LegIdKey, Circuit>,
    /// The unique identifier of the primary leg
    pub(super) primary_id: LegIdKey,
}

impl ConfluxSet {
    /// Create a new conflux set, consisting of a single leg.
    pub(super) fn new(circuit_leg: Circuit) -> Self {
        let mut legs: SlotMap<LegIdKey, Circuit> = SlotMap::with_key();
        let primary_id = legs.insert(circuit_leg);

        Self { legs, primary_id }
    }

    /// Return the only leg of this conflux set.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        if self.legs.is_empty() {
            Err(internal!("tried to get circuit leg before creating it?!"))
        } else if self.legs.len() > 1 {
            Err(internal!(
                "tried to get single circuit leg after conflux linking?!"
            ))
        } else {
            let (_circ_id, circ) = self
                .legs
                .iter_mut()
                .next()
                .ok_or_else(|| internal!("slotmap is empty but its length is one?!"))?;

            Ok(circ)
        }
    }

    /// Return the primary leg of this conflux set.
    ///
    /// Returns an error if called before any circuit legs are available.
    pub(super) fn primary_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        // TODO(conflux): support more than one leg,
        // and remove this check
        if self.legs.len() > 1 {
            return Err(internal!("multipath not currently supported"));
        }

        if self.legs.is_empty() {
            Err(internal!("tried to get circuit leg before creating it?!"))
        } else {
            // TODO(conflux): implement primary leg selection
            let circ = self
                .legs
                .get_mut(self.primary_id)
                .ok_or_else(|| internal!("slotmap is empty?!"))?;

            Ok(circ)
        }
    }

    /// Return the number of legs in this conflux set.
    pub(super) fn len(&self) -> usize {
        self.legs.len()
    }

    /// Return whether this conflux set is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.legs.len() == 0
    }

    /// Remove the specified leg from this conflux set.
    ///
    /// Returns an error if the given leg doesn't exist in the set,
    /// or if after removing the leg the set is depleted (empty).
    pub(super) fn remove(&mut self, leg: LegIdKey) -> Result<(), ReactorError> {
        let _: Circuit = self
            .legs
            .remove(leg)
            .ok_or_else(|| bad_api_usage!("leg {leg:?} not found in conflux set"))?;

        // TODO(conflux): if leg == primary_leg, reassign the next best leg to primary_leg

        if self.legs.is_empty() {
            // The last circuit in the set has just died, so the reactor should exit.
            return Err(ReactorError::Shutdown);
        }

        Ok(())
    }
}
