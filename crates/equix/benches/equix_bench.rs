use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use equix::{EquiXBuilder, Error, HashError, RuntimeOption, SolutionByteArray};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::vec::Vec;

fn equix_bench(c: &mut Criterion) {
    bench_one_runtime(c, RuntimeOption::InterpretOnly, "interp");

    #[cfg(all(feature = "compiler", target_arch = "aarch64"))]
    bench_one_runtime(c, RuntimeOption::CompileOnly, "aarch64");

    #[cfg(all(feature = "compiler", target_arch = "x86_64"))]
    bench_one_runtime(c, RuntimeOption::CompileOnly, "x86_64");
}

fn bench_one_runtime(c: &mut Criterion, runtime: RuntimeOption, name: &str) {
    bench_solve(c, runtime, &format!("{}-solve", name));
    bench_verify(c, runtime, &format!("{}-verify", name));
}

fn bench_solve(c: &mut Criterion, runtime: RuntimeOption, name: &str) {
    // Benchmark the whole Equi-X solver, including hash function generation,
    // using batches of random challenges.

    let mut rng = StdRng::seed_from_u64(0);
    c.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut challenge = [0u8; 8];
                rng.fill_bytes(&mut challenge);
                challenge
            },
            |challenge| EquiXBuilder::new().runtime(runtime).solve(&challenge),
            BatchSize::SmallInput,
        );
    });
}

fn bench_verify(c: &mut Criterion, runtime: RuntimeOption, name: &str) {
    // Benchmark solution verification, from bytes.
    //
    // This pre-generates a set of random challenges and solutions,
    // and then selects random items from that set prior to each
    // benchmark batch.
    //
    // Currently we only bother timing successful verifications, since they
    // should take the longest.

    let mut choices = Vec::<(u32, SolutionByteArray)>::new();
    for challenge in 1000u32..1100u32 {
        match EquiXBuilder::new()
            .runtime(runtime)
            .build(&challenge.to_le_bytes())
        {
            Ok(instance) => {
                for solution in instance.solve() {
                    choices.push((challenge, solution.to_bytes()));
                }
            }
            Err(Error::Hash(HashError::ProgramConstraints)) => (),
            Err(_) => unreachable!(),
        }
    }

    let mut rng = StdRng::seed_from_u64(0);
    c.bench_function(name, |b| {
        b.iter_batched(
            || choices[rng.next_u32() as usize % choices.len()],
            |(challenge, solution_bytes)| {
                EquiXBuilder::new()
                    .runtime(runtime)
                    .verify_bytes(&challenge.to_le_bytes(), &solution_bytes)
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, equix_bench);
criterion_main!(benches);
