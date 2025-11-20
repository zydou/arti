//! Define HashX's register file, and how it's created and digested.

use crate::siphash::{SipState, siphash24_ctr};
use arrayvec::ArrayVec;
use std::fmt;

/// Number of virtual registers in the HashX machine
pub(crate) const NUM_REGISTERS: usize = 8;

/// Register `R5`
///
/// Most HashX registers have no special properties, so we don't even
/// bother naming them. Register R5 is the exception, HashX defines a
/// specific constraint there for the benefit of x86_64 code generation.
pub(crate) const R5: RegisterId = RegisterId(5);

/// Identify one register (R0 - R7) in HashX's virtual machine
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RegisterId(u8);

impl fmt::Debug for RegisterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R{}", self.0)
    }
}

impl RegisterId {
    /// Cast this RegisterId into a plain usize
    #[inline(always)]
    pub(crate) fn as_usize(&self) -> usize {
        self.0 as usize
    }

    /// Return the underlying u8 for this RegisterId.
    ///
    /// (Recall that hashx has 8 virtual registers,
    /// so the output of this method is always in range 0..=7.)
    #[inline(always)]
    #[cfg(feature = "compiler")]
    pub(crate) fn as_u8(&self) -> u8 {
        self.0
    }

    /// Create an iterator over all RegisterId
    #[inline(always)]
    pub(crate) fn all() -> impl Iterator<Item = RegisterId> {
        (0_u8..(NUM_REGISTERS as u8)).map(RegisterId)
    }
}

/// Identify a set of RegisterIds
///
/// This could be done compactly as a u8 bitfield for storage purposes, but
/// in our program generator this is never stored long-term. Instead, we want
/// something the optimizer can reason about as effectively as possible, and
/// we want to optimize for an index() implementation that doesn't branch.
/// This uses a fixed-capacity array of registers in-set, always sorted.
#[derive(Default, Clone, Eq, PartialEq)]
pub(crate) struct RegisterSet(ArrayVec<RegisterId, NUM_REGISTERS>);

impl fmt::Debug for RegisterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for n in 0..self.len() {
            if n != 0 {
                write!(f, ",")?;
            }
            self.index(n).fmt(f)?;
        }
        write!(f, "]")
    }
}

impl RegisterSet {
    /// Number of registers still contained in this set
    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Test if a register is contained in the set.
    #[inline(always)]
    pub(crate) fn contains(&self, id: RegisterId) -> bool {
        self.0.contains(&id)
    }

    /// Build a new RegisterSet from each register for which a predicate
    /// function returns `true`.
    #[inline(always)]
    pub(crate) fn from_filter<P: FnMut(RegisterId) -> bool>(mut predicate: P) -> Self {
        let mut result: Self = Default::default();
        for r in RegisterId::all() {
            if predicate(r) {
                result.0.push(r);
            }
        }
        result
    }

    /// Return a particular register within this set, counting from R0 to R7.
    ///
    /// The supplied index must be less than the [`Self::len()`] of this set.
    /// Panics if the index is out of range.
    #[inline(always)]
    pub(crate) fn index(&self, index: usize) -> RegisterId {
        self.0[index]
    }
}

/// Values for all registers in the HashX machine
///
/// Guaranteed to have a `repr(C)` layout that includes each register in order
/// with no padding and no extra fields. The compiled runtime will produce
/// functions that read or write a `RegisterFile` directly.

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct RegisterFile([u64; NUM_REGISTERS]);

impl RegisterFile {
    /// Load a word from the register file.
    #[inline(always)]
    pub(crate) fn load(&self, id: RegisterId) -> u64 {
        self.0[id.as_usize()]
    }

    /// Store a word into the register file.
    #[inline(always)]
    pub(crate) fn store(&mut self, id: RegisterId, value: u64) {
        self.0[id.as_usize()] = value;
    }

    /// Initialize a new HashX register file, given a key (derived from
    /// the seed) and the user-specified hash input word.
    #[inline(always)]
    pub(crate) fn new(key: SipState, input: u64) -> Self {
        RegisterFile(siphash24_ctr(key, input))
    }

    /// Finalize the state of the register file and generate up to 4 words of
    /// output in HashX's final result format.
    ///
    /// This splits the register file into two halves, mixes in the siphash
    /// keys again to "remove bias toward 0 caused by multiplications", and
    /// runs one siphash round on each half before recombining them.
    #[inline(always)]
    pub(crate) fn digest(&self, key: SipState) -> [u64; 4] {
        let mut x = SipState {
            v0: self.0[0].wrapping_add(key.v0),
            v1: self.0[1].wrapping_add(key.v1),
            v2: self.0[2],
            v3: self.0[3],
        };
        let mut y = SipState {
            v0: self.0[4],
            v1: self.0[5],
            v2: self.0[6].wrapping_add(key.v2),
            v3: self.0[7].wrapping_add(key.v3),
        };
        x.sip_round();
        y.sip_round();
        [x.v0 ^ y.v0, x.v1 ^ y.v1, x.v2 ^ y.v2, x.v3 ^ y.v3]
    }
}
