#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tor_bytes::Reader;

#[derive(Clone, Debug, Arbitrary)]
enum Op {
    GetLen,
    GetRemaining,
    GetConsumed,
    Advance(usize),
    CheckExhausted,
    Truncate(usize),
    Peek(usize),
    ReadNestedU8(Vec<Op>),
    ReadNestedU16(Vec<Op>),
    ReadNestedU32(Vec<Op>),
    Take(usize),
    TakeRest,
    TakeU8,
    TakeU16,
    TakeU32,
    TakeU64,
    TakeU128,
    TakeUntil(u8),
    ExtractU32,
    ExtractU32N(usize),
    TakeInto(u16),
}

#[derive(Clone, Debug, Arbitrary)]
struct Example {
    input: Vec<u8>,
    ops: Vec<Op>,
}

#[cfg(not(tarpaulin_include))]
impl Example {
    fn run(self) {
        let mut b = Reader::from_slice_for_test(&self.input[..]);
        for op in self.ops {
            op.run(&mut b);
        }
        let _ignore = b.into_rest();
    }
}

#[cfg(not(tarpaulin_include))]
impl Op {
    fn run(self, b: &mut Reader) {
        use Op::*;
        match self {
            GetLen => {
                let _len = b.total_len();
            }
            GetRemaining => {
                let _rem = b.remaining();
            }
            GetConsumed => {
                let _cons = b.consumed();
            }
            Advance(n) => {
                let _ignore = b.advance(n);
            }
            CheckExhausted => {
                let _ignore = b.should_be_exhausted();
            }
            Truncate(n) => {
                b.truncate(n);
            }
            Peek(n) => {
                let _ignore = b.peek(n);
            }
            ReadNestedU8(ops) => {
                let _ignore = b.read_nested_u8len(|b_inner| {
                    ops.into_iter().for_each(|op| op.run(b_inner));
                    Ok(())
                });
            }
            ReadNestedU16(ops) => {
                let _ignore = b.read_nested_u16len(|b_inner| {
                    ops.into_iter().for_each(|op| op.run(b_inner));
                    Ok(())
                });
            }
            ReadNestedU32(ops) => {
                let _ignore = b.read_nested_u32len(|b_inner| {
                    ops.into_iter().for_each(|op| op.run(b_inner));
                    Ok(())
                });
            }
            Take(n) => {
                let _ignore = b.take(n);
            }
            TakeRest => {
                let _ignore = b.take_rest();
            }
            TakeInto(n) => {
                let n = n as usize;
                let mut v = vec![0; n];
                let _ignore = b.take_into(&mut v[..]);
            }
            TakeU8 => {
                let _u = b.take_u8();
            }
            TakeU16 => {
                let _u16 = b.take_u16();
            }
            TakeU32 => {
                let _u32 = b.take_u32();
            }
            TakeU64 => {
                let _u64 = b.take_u64();
            }
            TakeU128 => {
                let _u128 = b.take_u128();
            }
            TakeUntil(byte) => {
                let _ignore = b.take_until(byte);
            }
            ExtractU32 => {
                let _ignore: Result<u32, _> = b.extract();
            }
            ExtractU32N(n) => {
                let _ignore: Result<Vec<u32>, _> = b.extract_n(n);
            }
        }
    }
}

fuzz_target!(|ex: Example| {
    ex.run();
});
