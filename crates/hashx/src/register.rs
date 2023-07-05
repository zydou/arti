//! Define HashX's register file, and how it's created and digested

use crate::siphash;
use std::fmt;

/// Number of virtual registers in the HashX machine
pub(crate) const NUM_REGISTERS: usize = 8;

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
}

/// Identify a set of RegisterIds
///
/// This could be done compactly as a u8 bitfield for storage purposes, but
/// in our program generator this is never stored long-term. Instead, we want
/// something the optimizer can reason about as effectively as possible, and
/// let's inline as much as possible in order to resolve special cases in
/// the program generator at compile time.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RegisterSet {
    /// Number of registers in the set
    len: usize,
    /// Array indexed by register Id, indicating registers we've excluded
    reg_not_in_set: [bool; 8],
}

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
    /// Construct the set of all registers.
    ///
    /// This is the main way to construct a new RegisterId, starting with
    /// all available registers and filtering them repeatedly.
    #[inline(always)]
    pub(crate) fn all() -> Self {
        Self {
            len: NUM_REGISTERS,
            reg_not_in_set: Default::default(),
        }
    }

    /// Number of registers still contained in this set
    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Test if a register is contained in the set
    #[inline(always)]
    pub(crate) fn contains(&self, id: RegisterId) -> bool {
        !self.reg_not_in_set[id.0 as usize]
    }

    /// Filter this register set through a predicate. Invokes the predicate only
    /// for registers in this set, and returns the set of registers for which it
    /// returned true.
    #[inline(always)]
    pub(crate) fn filter<P: FnMut(RegisterId) -> bool>(&self, mut predicate: P) -> Self {
        let mut result = Self {
            len: 0,
            reg_not_in_set: Default::default(),
        };
        self.filter_impl(0, &mut predicate, &mut result);
        self.filter_impl(1, &mut predicate, &mut result);
        self.filter_impl(2, &mut predicate, &mut result);
        self.filter_impl(3, &mut predicate, &mut result);
        self.filter_impl(4, &mut predicate, &mut result);
        self.filter_impl(5, &mut predicate, &mut result);
        self.filter_impl(6, &mut predicate, &mut result);
        self.filter_impl(7, &mut predicate, &mut result);
        result
    }

    /// Internal implementation to be unrolled by `filter`
    #[inline(always)]
    fn filter_impl<P: FnMut(RegisterId) -> bool>(
        &self,
        id: usize,
        predicate: &mut P,
        result: &mut Self,
    ) {
        if self.reg_not_in_set[id] {
            result.reg_not_in_set[id] = true;
        } else if predicate(RegisterId(id as u8)) {
            result.len += 1;
        } else {
            result.reg_not_in_set[id] = true;
        }
    }

    /// Return a particular register within this set, counting from R0 to R7.
    /// The supplied index must be less than the len() of this set.
    #[inline(always)]
    pub(crate) fn index(&self, mut index: usize) -> RegisterId {
        if let Some(result) = self.index_impl(0, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(1, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(2, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(3, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(4, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(5, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(6, &mut index) {
            return result;
        }
        if let Some(result) = self.index_impl(7, &mut index) {
            return result;
        }
        unreachable!();
    }

    /// Internal implementation to be unrolled by `index`
    #[inline(always)]
    fn index_impl(&self, id: usize, index: &mut usize) -> Option<RegisterId> {
        if self.reg_not_in_set[id] {
            None
        } else if *index == 0 {
            Some(RegisterId(id as u8))
        } else {
            *index -= 1;
            None
        }
    }
}

/// Values for all registers in the HashX machine
#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct RegisterFile {
    /// Raw register file, as a u64 array. The compiled runtime
    /// will produce functions that read or write a RegisterFile
    /// directly, so this must be the first item and the containing
    /// struct must be repr(C).
    inner: [u64; NUM_REGISTERS],
}

impl RegisterFile {
    /// Load a word from the register file
    #[inline(always)]
    pub(crate) fn load(&self, id: RegisterId) -> u64 {
        self.inner[id.as_usize()]
    }

    /// Store a word into the register file.
    #[inline(always)]
    pub(crate) fn store(&mut self, id: RegisterId, value: u64) {
        self.inner[id.as_usize()] = value;
    }

    /// Initialize a new HashX register file, given a key (derived from
    /// the seed) and the user-specified hash function input word.
    #[inline(always)]
    pub(crate) fn new(key: siphash::State, input: u64) -> Self {
        RegisterFile {
            inner: siphash::siphash24_ctr(key, input),
        }
    }

    /// Finalize the state of the register file and generate up to 4 words of
    /// output in HashX's final result format.
    ///
    /// This splits the register file into two halves, mixes in the siphash
    /// keys again to "remove bias toward 0 caused by multiplications", and
    /// runs one siphash round on each half before recombining them.
    #[inline(always)]
    pub(crate) fn digest(&self, key: siphash::State) -> [u64; 4] {
        let mut x = siphash::State {
            v0: self.inner[0].wrapping_add(key.v0),
            v1: self.inner[1].wrapping_add(key.v1),
            v2: self.inner[2],
            v3: self.inner[3],
        };
        let mut y = siphash::State {
            v0: self.inner[4],
            v1: self.inner[5],
            v2: self.inner[6].wrapping_add(key.v2),
            v3: self.inner[7].wrapping_add(key.v3),
        };
        x.sip_round();
        y.sip_round();
        [x.v0 ^ y.v0, x.v1 ^ y.v1, x.v2 ^ y.v2, x.v3 ^ y.v3]
    }
}

#[cfg(test)]
mod test {
    use super::RegisterSet;

    #[test]
    fn register_set() {
        let r = RegisterSet::all().filter(|_reg| true);
        assert_eq!(r.len(), 8);
        assert_eq!(r.index(7).as_usize(), 7);
        assert_eq!(r.index(0).as_usize(), 0);
        let r = r.filter(|reg| (reg.as_usize() & 1) != 0);
        assert_eq!(r.len(), 4);
        assert_eq!(r.index(0).as_usize(), 1);
        assert_eq!(r.index(1).as_usize(), 3);
        assert_eq!(r.index(2).as_usize(), 5);
        assert_eq!(r.index(3).as_usize(), 7);
        let r = r.filter(|reg| (reg.as_usize() & 2) != 0);
        assert_eq!(r.index(0).as_usize(), 3);
        assert_eq!(r.index(1).as_usize(), 7);
        let r = r.filter(|_reg| true);
        assert_eq!(r.len(), 2);
        let r = r.filter(|_reg| false);
        assert_eq!(r.len(), 0);
    }
}
