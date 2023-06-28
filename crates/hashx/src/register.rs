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

    /// Convert a usize into a RegisterId. Panics if out of range.
    ///
    /// This is only available within the module, so we can implement
    /// RegisterSet. The public interface to RegisterId does not allow
    /// creating new instances of specific registers.
    fn from_usize(n: usize) -> Self {
        assert!(n < NUM_REGISTERS);
        Self(
            n.try_into()
                .expect("register ID type wide enough for register file"),
        )
    }
}

/// Identify a set of RegisterIds
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RegisterSet {
    /// Bit field, in LSB-first order, tracking which registers are in the set
    bits: u8,
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
    pub(crate) fn all() -> Self {
        Self {
            bits: ((1_usize << NUM_REGISTERS) - 1)
                .try_into()
                .expect("register set is wide enough to hold all registers"),
        }
    }

    /// Number of registers still contained in this set
    pub(crate) fn len(&self) -> usize {
        self.bits
            .count_ones()
            .try_into()
            .expect("register set length always fits in usize")
    }

    /// Test if a register is contained in the set
    pub(crate) fn contains(&self, id: RegisterId) -> bool {
        (self.bits & (1 << id.0)) != 0
    }

    /// Filter this register set through a predicate. Invokes the predicate only
    /// for registers in this set, and returns the set of registers for which it
    /// returned true.
    pub(crate) fn filter<P: FnMut(RegisterId) -> bool>(&self, mut predicate: P) -> Self {
        let mut shift = 0;
        let mut result = *self;
        loop {
            if result.bits == 0 {
                break;
            }
            shift += result.bits.wrapping_shr(shift as _).trailing_zeros() as usize;
            if shift >= NUM_REGISTERS {
                break;
            }
            if !predicate(RegisterId::from_usize(shift)) {
                result.bits &= !(1 << shift);
            }
            shift += 1;
        }
        result
    }

    /// Return a particular register within this set, counting from R0 to R7.
    /// The supplied index must be less than the len() of this set.
    pub(crate) fn index(&self, mut idx: usize) -> RegisterId {
        let mut shift = 0;
        loop {
            shift += (self.bits >> shift).trailing_zeros() as usize;
            assert!(shift < NUM_REGISTERS);
            if idx == 0 {
                return RegisterId::from_usize(shift);
            }
            idx -= 1;
            shift += 1;
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
