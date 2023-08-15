//! This is a wallclock time microbenchmark for C and Rust implementations
//! of HashX using the Criterion framework.

use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup,
    Criterion,
};
use hashx::{Error, HashX, HashXBuilder, RuntimeOption};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

/// Per-runtime settings
struct Runtime {
    option: RuntimeOption,
    c_type: tor_c_equix::HashXType,
    name: &'static str,
    hashes_per_seed: u32,
}

// Benchmark each supported runtime, depending on the architecture and features
fn hashx_bench(c: &mut Criterion) {
    // Interpreted runtime is always available
    let mut runtimes = vec![];
    runtimes.push(Runtime {
        option: RuntimeOption::InterpretOnly,
        c_type: tor_c_equix::HashXType::HASHX_TYPE_INTERPRETED,
        name: "interp",
        // In slow interpreted mode, do a reduced number of
        // hashes so that tests are less cumbersome to run and measure.
        hashes_per_seed: 1 << 10,
    });

    // For testing purposes, ignore the library's fallback support and
    // require the compiler on architectures we expect to support it.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    runtimes.push(Runtime {
        option: RuntimeOption::CompileOnly,
        c_type: tor_c_equix::HashXType::HASHX_TYPE_COMPILED,
        name: std::env::consts::ARCH,
        // On compiled runtimes we can run the full 64k batch
        hashes_per_seed: 1 << 16,
    });

    runtimes_bench_generate(&mut c.benchmark_group("generate"), &runtimes);
    runtimes_bench_hash(&mut c.benchmark_group("hash"), &runtimes);
}

fn runtimes_bench_generate(group: &mut BenchmarkGroup<'_, WallTime>, runtimes: &[Runtime]) {
    for r in runtimes {
        // Normal program generation in our Rust implementation
        bench_generate(
            group,
            |seed| HashXBuilder::new().runtime(r.option).build(&seed),
            &format!("generate-{}", r.name),
        );

        // Compare with the original C implementation.
        // For fair comparison with HashX::build, doesn't reuse memory.
        bench_generate(
            group,
            |seed| tor_c_equix::HashX::new(r.c_type).make(&seed),
            &format!("generate-{}-c", r.name),
        );

        // Measure program generation with memory reuse (not supported in Rust yet)
        let ctx_cell = std::cell::RefCell::new(tor_c_equix::HashX::new(r.c_type));
        bench_generate(
            group,
            |seed| ctx_cell.borrow_mut().make(&seed),
            &format!("generate-{}-c-reuse", r.name),
        );
    }
}

fn runtimes_bench_hash(group: &mut BenchmarkGroup<'_, WallTime>, runtimes: &[Runtime]) {
    // Common builder for a HashX instance with a selected RuntimeOption,
    // and all errors fatal except for ProgramConstraints.
    #[inline(always)]
    fn hashx_build_unwrap(option: RuntimeOption, seed: &[u8]) -> Option<HashX> {
        match HashXBuilder::new().runtime(option).build(seed) {
            Ok(hashx) => Some(hashx),
            Err(Error::ProgramConstraints) => None,
            Err(e) => panic!("{:?}", e),
        }
    }

    for r in runtimes {
        // Direct u64 result from the Rust version
        bench_hash(
            group,
            r.hashes_per_seed,
            &format!("{}-u64-hash", r.name),
            |seed| hashx_build_unwrap(r.option, seed),
            |hashx, input| hashx.hash_to_u64(input),
        );

        // Full size result from the Rust version
        bench_hash(
            group,
            r.hashes_per_seed,
            &format!("{}-full-hash", r.name),
            |seed| hashx_build_unwrap(r.option, seed),
            |hashx, input| hashx.hash_to_bytes(input),
        );

        // Our build of the original C implementation only supports 8-byte
        // output. Very similar to u64, but it does always copy to a
        // serialized byte array output, and on a big endian platform there
        // would be a byte swap.
        bench_hash(
            group,
            r.hashes_per_seed,
            &format!("{}-8b-hash-c", r.name),
            |seed| {
                let mut ctx = tor_c_equix::HashX::new(r.c_type);
                match ctx.make(seed) {
                    tor_c_equix::HashXResult::HASHX_OK => Some(ctx),
                    tor_c_equix::HashXResult::HASHX_FAIL_SEED => None,
                    other => panic!("unexpected hashx result, {:?}", other),
                }
            },
            |ctx, input| ctx.exec(input).unwrap(),
        );
    }
}

fn bench_generate<F: FnMut([u8; 32]) -> T + Copy, T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    generate: F,
    name: &str,
) {
    let mut rng = StdRng::from_entropy();

    // Generate programs using precomputed batches of random seeds
    group.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed
            },
            generate,
            BatchSize::SmallInput,
        );
    });
}

fn bench_hash<F: FnMut(&[u8]) -> Option<T>, G: FnMut(&mut T, u64) -> U, T, U>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    hashes_per_seed: u32,
    name: &str,
    mut generate: F,
    mut result_fn: G,
) {
    // Performance can vary a little bit depending on both seed choice and
    // input. This test measures overall hash function performance for a random
    // seed and sequential input, similar to the Equi-X workload.

    let mut rng = StdRng::from_entropy();
    let mut seed = [0u8; 4];

    group.bench_function(name, |b| {
        b.iter_custom(|seed_iters| {
            let mut total_timer: Duration = Default::default();
            for _ in 0..seed_iters {
                let mut instance = loop {
                    rng.fill_bytes(&mut seed);
                    if let Some(instance) = generate(&seed) {
                        break instance;
                    }
                };
                let seed_timer = Instant::now();
                for input in 0..hashes_per_seed {
                    black_box(result_fn(&mut instance, black_box(input as u64)));
                }
                total_timer += seed_timer.elapsed();
            }
            total_timer / hashes_per_seed
        })
    });
}

criterion_group!(benches, hashx_bench);
criterion_main!(benches);
