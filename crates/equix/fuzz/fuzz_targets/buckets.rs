//! Fuzzer for the "bucket_array::mem" API.
//!
//! Since this API `unsafe`, it's not a bad idea to make sure that
//! it can't do anything untoward.

#![no_main]
use arbitrary::Arbitrary;
use arrayvec::ArrayVec;
use equix::{BucketArray, BucketArrayMemory, BucketArrayPair, Uninit};
use libfuzzer_sys::fuzz_target;
use std::ops::{Bound::*, Range, RangeBounds};

type BucketIdx = u8;
type ItemIdx = u8;
type Val = u64;

#[derive(Clone, Debug, Arbitrary)]
enum Op {
    Range(BucketIdx),
    Value(BucketIdx, ItemIdx),
    Insert(BucketIdx, Val, Val),
    DropFirst,
}

#[derive(Debug)]
struct SimulatedArray<const N: usize, const CAP: usize, T>(ArrayVec<ArrayVec<T, CAP>, N>);

impl<const N: usize, const CAP: usize, T> Default for SimulatedArray<N, CAP, T> {
    fn default() -> Self {
        let mut r = ArrayVec::new();
        for _ in 0..N {
            r.push(ArrayVec::new());
        }
        Self(r)
    }
}

impl<const N: usize, const CAP: usize, T> SimulatedArray<N, CAP, T> {
    fn push(&mut self, bucket: usize, value: T) -> Result<(), ()> {
        let a = &mut self.0[bucket];
        if a.is_full() {
            Err(())
        } else {
            a.push(value);
            Ok(())
        }
    }
}

enum Sim<'a, 'b, const N: usize, const CAP: usize> {
    Single {
        b: BucketArray<'b, N, CAP, ItemIdx, Val>,
        s: SimulatedArray<N, CAP, Val>,
    },
    Pair {
        b: BucketArrayPair<'a, 'b, N, CAP, ItemIdx, Val, Val>,
        s: SimulatedArray<N, CAP, (Val, Val)>,
    },
}

impl<'a, 'b, const N: usize, const CAP: usize> Sim<'a, 'b, N, CAP> {
    fn idx(&self, idx: BucketIdx) -> usize {
        (idx as usize) % N
    }
    fn idx2(&self, idx: BucketIdx, item: ItemIdx) -> Option<(usize, usize)> {
        let idx = self.idx(idx);
        let r = self.range(idx);
        assert_eq!(r.start_bound(), Included(&0));
        let item = match r.end_bound() {
            Included(x) => (item as usize) % (x + 1),
            Excluded(&0) => return None,
            Excluded(x) => (item as usize) % x,
            Unbounded => unimplemented!(),
        };
        Some((idx, item))
    }
    fn range(&self, idx: usize) -> Range<usize> {
        let (r1, r2) = match self {
            Sim::Single { b, s } => (b.item_range(idx), 0..s.0[idx].len()),
            Sim::Pair { b, s } => (b.item_range(idx), 0..s.0[idx].len()),
        };
        assert_eq!(r1, r2);
        r1
    }
    fn apply(mut self, op: Op) -> Self {
        match op {
            Op::Range(idx) => {
                let idx = self.idx(idx);
                let _x = self.range(idx);
                self
            }
            Op::Value(bi, ii) => {
                if let Some((bi, ii)) = self.idx2(bi, ii) {
                    match &self {
                        Sim::Single { b, s } => {
                            let v1 = b.item_value(bi, ii);
                            let v2 = s.0[bi][ii];
                            assert_eq!(v1, v2);
                        }
                        Sim::Pair { b, s } => {
                            let v1 = (b.item_value_first(bi, ii), b.item_value_second(bi, ii));
                            let v2 = s.0[bi][ii];
                            assert_eq!(v1, v2);
                        }
                    }
                }
                self
            }
            Op::Insert(bi, v1, v2) => {
                let bi = self.idx(bi);
                match &mut self {
                    Sim::Single { b, s } => {
                        let r1 = b.insert(bi, v1);
                        let r2 = s.push(bi, v1);
                        assert_eq!(r1, r2);
                    }
                    Sim::Pair { b, s } => {
                        let r1 = b.insert(bi, v1, v2);
                        let r2 = s.push(bi, (v1, v2));
                        assert_eq!(r1, r2);
                    }
                }
                self
            }
            Op::DropFirst => match self {
                Sim::Pair { b, s } => {
                    let b2 = b.drop_first();
                    let s2 = SimulatedArray(
                        s.0.into_iter()
                            .map(|a| a.into_iter().map(|(_x, y)| y).collect())
                            .collect(),
                    );
                    Sim::Single { b: b2, s: s2 }
                }
                single => single,
            },
        }
    }
}

fuzz_target!(|ex: Vec<Op>| {
    #[derive(Copy, Clone)]
    struct MemLayout {
        mem1a: BucketArrayMemory<7, 12, Val>,
        mem1b: BucketArrayMemory<7, 12, Val>,
        mem2a: BucketArrayMemory<8, 16, Val>,
        mem2b: BucketArrayMemory<8, 16, Val>,
    }

    unsafe impl Uninit for MemLayout {}
    let mut ml = MemLayout::alloc();

    // Reuse the MemLayout to run the same test inputs twice
    for _ in 0..2 {
        let mut shape1: Sim<'_, '_, 7, 12> = Sim::Pair {
            b: BucketArrayPair::new(&mut ml.mem1a, &mut ml.mem1b),
            s: Default::default(),
        };
        let mut shape2: Sim<'_, '_, 8, 16> = Sim::Pair {
            b: BucketArrayPair::new(&mut ml.mem2a, &mut ml.mem2b),
            s: Default::default(),
        };

        for o in &ex {
            shape1 = shape1.apply(o.clone());
            shape2 = shape2.apply(o.clone());
        }
    }
});
