//! Fuzzer for HashX with input injected at the pseudo-random number generator
//!
//! This tests both program generation and execution together as a unit,
//! in order to avoid requiring a stable and cross-implementation interface
//! for the program format.
//!
//! Tests all available implementations in parallel.
//! Currently assumes the compiler is always available.
//! (Requires x86_64 or aarch64 host)
//!
//! Each run compiles one program per implementation,
//! and runs a fixed number of hashes on arbitrary input values.
//!
//! The fuzzer input provides a list of replacement Rng values for HashX to use.
//! Once that replacement string is exhausted, the HashX random number generator
//! resumes normal operation, skipping all replaced values. It's important that
//! we don't provide any steady-state constant values as Rng output, or the
//! HashX program generator could easily enter a loop that never terminates.

#![no_main]
use arbitrary::Arbitrary;
use core::cell::Cell;
use core::num::NonZeroU64;
use libfuzzer_sys::fuzz_target;
use rand::RngCore;
use std::sync::Arc;

// Test a fixed number of hash inputs, to keep the time spent on each
// program relatively fair. Lower values here will let us spend more
// time on program generation, higher values could hypothetically
// help find subtle differences in behavior within one generated program.
const NUM_HASH_INPUTS: u64 = 64;

/// Operation, decoded from arbitrary fuzzer input
#[derive(Clone, Debug, Arbitrary)]
struct Op {
    /// Seed bytes, for HashX's Blake2b preprocessing stage.
    ///
    /// These become seed material for the register file state, and for the
    /// Rng values used after `rng_replacement` ends.
    seed: [u8; 32],

    /// First hash value, anywhere in the 64-bit input space
    first_hash_input: u64,

    /// Increment to each subsequent tested hash input
    input_step: NonZeroU64,

    /// Most of our input bytes drive the program generator directly
    rng_values: Vec<u64>,
}

impl Op {
    // Get an iterator over all hash input values
    fn hash_inputs(&self) -> impl Iterator<Item = u64> {
        let first = self.first_hash_input;
        let step = self.input_step.get();
        (0..NUM_HASH_INPUTS).map(move |counter| first.wrapping_add(counter.wrapping_mul(step)))
    }
}

// Common test result format
#[derive(Clone, Default, Debug, Eq, PartialEq)]
struct TestResult {
    /// List of hash outputs, in 8-byte format. Empty if the seed was bad.
    outputs: Vec<[u8; 8]>,

    /// Final counter value reached by the program generator's PRNG.
    /// Zero if the seed was bad.
    counter: usize,
}

// Test one Rust implementation, generating one program and running a set of
// hash inputs through it. Always returns a TestResult.
fn test_instance_rust(op: &Arc<Op>, option: hashx::RuntimeOption) -> TestResult {
    struct RngWrapper {
        inner: hashx::SipRand,
        counter: usize,
        op: Arc<Op>,
    }

    let (key0, key1) = hashx::SipState::pair_from_seed(&op.seed);
    let mut rng = RngWrapper {
        inner: hashx::SipRand::new(key0),
        counter: 0,
        op: op.clone(),
    };

    impl RngCore for RngWrapper {
        fn next_u64(&mut self) -> u64 {
            let original_value = self.inner.next_u64();
            let result = if self.counter < self.op.rng_values.len() {
                self.op.rng_values[self.counter]
            } else {
                original_value
            };
            self.counter += 1;
            result
        }

        fn next_u32(&mut self) -> u32 {
            unreachable!();
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unreachable!();
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
            unreachable!();
        }
    }

    let result = hashx::HashXBuilder::new()
        .runtime(option)
        .build_from_rng(&mut rng, key1);

    match result {
        Err(hashx::Error::ProgramConstraints) => Default::default(),
        Err(e) => panic!("unexpected hashx error with {:?}, {:?}", option, e),
        Ok(hashx) => TestResult {
            outputs: op
                .hash_inputs()
                .map(|input| hashx.hash_to_u64(input).to_le_bytes())
                .collect(),
            counter: rng.counter,
        },
    }
}

// Test one C implementation. Always returns a TestResult.
fn test_instance_c(op: &Arc<Op>, hashx_type: tor_c_equix::HashXType) -> TestResult {
    let mut ctx = tor_c_equix::HashX::new(hashx_type);
    let counter = Arc::new(Cell::new(0_usize));
    {
        let op = op.clone();
        let counter = counter.clone();
        ctx.rng_callback(Some(Box::new(move |original_value| {
            let result = if counter.get() < op.rng_values.len() {
                op.rng_values[counter.get()]
            } else {
                original_value
            };
            counter.set(counter.get() + 1);
            result
        })));
    }
    match ctx.make(&op.seed) {
        tor_c_equix::HashXResult::HASHX_OK => TestResult {
            outputs: op
                .hash_inputs()
                .map(|input| ctx.exec(input).unwrap())
                .collect(),
            counter: counter.get(),
        },
        tor_c_equix::HashXResult::HASHX_FAIL_SEED => Default::default(),
        e => panic!("unexpected c-tor hashx error, {:?}", e),
    }
}

fn test_all_instances(op: &Arc<Op>) {
    let ((rust_interp, rust_compiled), (c_interp, c_compiled)) = rayon::join(
        || {
            rayon::join(
                || test_instance_rust(op, hashx::RuntimeOption::InterpretOnly),
                || test_instance_rust(op, hashx::RuntimeOption::CompileOnly),
            )
        },
        || {
            rayon::join(
                || test_instance_c(op, tor_c_equix::HashXType::HASHX_TYPE_INTERPRETED),
                || test_instance_c(op, tor_c_equix::HashXType::HASHX_TYPE_COMPILED),
            )
        },
    );
    assert_eq!(rust_interp, rust_compiled);
    assert_eq!(c_interp, c_compiled);
    assert_eq!(rust_interp, c_interp);
}

fuzz_target! {|op: Op| {
    test_all_instances(&Arc::new(op))
}}
