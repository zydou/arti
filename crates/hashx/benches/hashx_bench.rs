use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hashx::{Error, HashX, HashXBuilder, RuntimeOption};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::{Duration, Instant};

fn hashx_bench(c: &mut Criterion) {
    bench_one_runtime(c, RuntimeOption::InterpretOnly, "interp");

    #[cfg(all(feature = "compiler", target_arch = "aarch64"))]
    bench_one_runtime(c, RuntimeOption::CompileOnly, "aarch64");

    #[cfg(all(feature = "compiler", target_arch = "x86_64"))]
    bench_one_runtime(c, RuntimeOption::CompileOnly, "x86_64");
}

fn bench_one_runtime(c: &mut Criterion, runtime: RuntimeOption, name: &str) {
    bench_generate(c, runtime, &format!("generate-{}", name));
    bench_hash(
        c,
        runtime,
        &format!("{}-u64-hash", name),
        |hash_instance, input| hash_instance.hash_to_u64(input),
    );
    bench_hash(
        c,
        runtime,
        &format!("{}-full-hash", name),
        |hash_instance, input| hash_instance.hash_to_bytes::<{ HashX::FULL_SIZE }>(input),
    );
}

fn bench_generate(c: &mut Criterion, runtime: RuntimeOption, name: &str) {
    // Generate programs using precomputed batches of random seeds
    let mut rng = StdRng::seed_from_u64(0);
    c.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                seed
            },
            |seed| HashXBuilder::new().runtime(runtime).build(&seed),
            BatchSize::SmallInput,
        );
    });
}

fn bench_hash<F: FnMut(&HashX, u64) -> T, T>(
    c: &mut Criterion,
    runtime: RuntimeOption,
    name: &str,
    mut result_fn: F,
) {
    // Performance can vary a little bit depending on both seed choice and
    // input. This test measures overall hash function performance for a random
    // seed and sequential input, similar to the Equi-X workload. On compiled
    // runtimes we can run the full 64k batch, on interpreted we reduce this
    // to avoid having individual iters take so long that the stats are noisy.

    let hashes_per_seed: u32 = match runtime {
        RuntimeOption::CompileOnly => 1 << 16,
        RuntimeOption::InterpretOnly => 1 << 10,
        _ => unreachable!(),
    };
    let mut rng = StdRng::seed_from_u64(0);
    let mut seed = [0u8; 4];

    c.bench_function(name, |b| {
        b.iter_custom(|seed_iters| {
            let mut total_timer: Duration = Default::default();
            for _ in 0..seed_iters {
                let hash_instance = loop {
                    rng.fill_bytes(&mut seed);
                    match HashXBuilder::new().runtime(runtime).build(&seed) {
                        Ok(hash_instance) => break hash_instance,
                        Err(Error::ProgramConstraints) => continue,
                        Err(e) => panic!("{:?}", e),
                    }
                };
                let seed_timer = Instant::now();
                for input in 0..hashes_per_seed {
                    black_box(result_fn(&hash_instance, black_box(input as u64)));
                }
                total_timer += seed_timer.elapsed();
            }
            total_timer / hashes_per_seed
        })
    });
}

criterion_group!(benches, hashx_bench);
criterion_main!(benches);
