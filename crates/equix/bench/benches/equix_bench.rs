use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use equix::{EquiXBuilder, Error, HashError, RuntimeOption, SolutionByteArray, SolverMemory};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Per-runtime settings
struct Runtime {
    option: RuntimeOption,
    c_ctx_flags: tor_c_equix::EquiXFlags,
    name: &'static str,
}

// Benchmark each supported runtime, depending on the architecture and features
fn equix_bench(c: &mut Criterion) {
    // Interpreted runtime is always available
    let mut runtimes = vec![];
    runtimes.push(Runtime {
        option: RuntimeOption::InterpretOnly,
        c_ctx_flags: tor_c_equix::ffi::equix_ctx_flags(0),
        name: "interp",
    });

    // For testing purposes, ignore the library's fallback support and
    // require the compiler on architectures we expect to support it.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    runtimes.push(Runtime {
        option: RuntimeOption::CompileOnly,
        c_ctx_flags: tor_c_equix::EquiXFlags::EQUIX_CTX_MUST_COMPILE,
        name: std::env::consts::ARCH,
    });

    runtimes_bench_verify(&mut c.benchmark_group("verify"), &runtimes);
    runtimes_bench_solve(&mut c.benchmark_group("solve"), &runtimes);
}

#[inline(always)]
fn c_solution_from_bytes(bytes: [u8; 16]) -> tor_c_equix::EquiXSolution {
    // Convert serialized bytes to a C-tor style EquiX solution.
    // On little endian targets this is equivalent to a memcpy.
    // This method is hard on the eyes but it's fast and infallible.
    tor_c_equix::EquiXSolution {
        idx: [
            u16::from_le_bytes([bytes[0], bytes[1]]),
            u16::from_le_bytes([bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
            u16::from_le_bytes([bytes[6], bytes[7]]),
            u16::from_le_bytes([bytes[8], bytes[9]]),
            u16::from_le_bytes([bytes[10], bytes[11]]),
            u16::from_le_bytes([bytes[12], bytes[13]]),
            u16::from_le_bytes([bytes[14], bytes[15]]),
        ],
    }
}

fn runtimes_bench_verify(group: &mut BenchmarkGroup<'_, WallTime>, runtimes: &[Runtime]) {
    for r in runtimes {
        // Our Rust implementation of the verifier
        bench_verify(
            group,
            &format!("{}-verify", r.name),
            |(challenge, solution)| {
                assert!(EquiXBuilder::new()
                    .runtime(r.option)
                    .verify_bytes(&challenge, &solution)
                    .is_ok());
            },
        );

        // Comparison with original C implementation of both HashX and Equi-X.
        // No memory reuse.
        //
        // The original Equi-X library doesn't implement portable byte
        // serialization, so for a fair comparison we implement it within
        // the measured function.
        let ctx_verify = tor_c_equix::EquiXFlags::EQUIX_CTX_VERIFY;
        bench_verify(
            group,
            &format!("{}-verify-c", r.name),
            |(challenge, solution)| {
                let mut ctx = tor_c_equix::EquiX::new(ctx_verify | r.c_ctx_flags);
                assert_eq!(
                    ctx.verify(&challenge, &c_solution_from_bytes(solution)),
                    tor_c_equix::EquiXResult::EQUIX_OK
                );
            },
        );

        // Comparison with original C implementation of both HashX and Equi-X,
        // with memory reuse this time.
        let ctx_cell = std::cell::RefCell::new(tor_c_equix::EquiX::new(ctx_verify | r.c_ctx_flags));
        bench_verify(
            group,
            &format!("{}-verify-c-reuse", r.name),
            |(challenge, solution)| {
                assert_eq!(
                    ctx_cell
                        .borrow_mut()
                        .verify(&challenge, &c_solution_from_bytes(solution)),
                    tor_c_equix::EquiXResult::EQUIX_OK
                );
            },
        );
    }
}

fn runtimes_bench_solve(group: &mut BenchmarkGroup<'_, WallTime>, runtimes: &[Runtime]) {
    for r in runtimes {
        // Rust implementation of the solver, with no memory reuse.
        bench_solve(group, &format!("{}-solve", r.name), |challenge| {
            EquiXBuilder::new().runtime(r.option).solve(&challenge)
        });

        // Use this Rust implementation, and reuse the SolverMemory.
        // Doesn't support reusing the HashX program memory yet.
        let solver_cell = std::cell::RefCell::new(SolverMemory::new());
        bench_solve(group, &format!("{}-solve-reuse", r.name), |challenge| {
            EquiXBuilder::new()
                .runtime(r.option)
                .build(&challenge)
                .unwrap()
                .solve_with_memory(&mut solver_cell.borrow_mut())
        });

        // Comparison with original C implementation of both HashX and Equi-X.
        // Mo memory reuse.
        let ctx_solve = tor_c_equix::EquiXFlags::EQUIX_CTX_SOLVE;
        bench_solve(group, &format!("{}-solve-c", r.name), |challenge| {
            let mut buffer: tor_c_equix::EquiXSolutionsBuffer = Default::default();
            tor_c_equix::EquiX::new(ctx_solve | r.c_ctx_flags).solve(&challenge, &mut buffer)
        });

        // C implementation, but with full memory reuse.
        // Solver heap and executable program memory will be recycled.
        let ctx_cell = std::cell::RefCell::new(tor_c_equix::EquiX::new(ctx_solve | r.c_ctx_flags));
        bench_solve(group, &format!("{}-solve-c-reuse", r.name), |challenge| {
            let mut buffer: tor_c_equix::EquiXSolutionsBuffer = Default::default();
            ctx_cell.borrow_mut().solve(&challenge, &mut buffer)
        });
    }
}

fn bench_solve<F: FnMut([u8; 4]) -> T + Copy, T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    solve: F,
) {
    // Benchmark the whole Equi-X solver, including hash function generation.
    //
    // This pre-generates a set of random challenges, and then selects random
    // items from that set prior to each benchmark batch. The timing should not
    // include failed program generation, since those exit much earlier than a
    // full solve.

    let mut choices = Vec::<[u8; 4]>::new();
    let mut rng = StdRng::from_entropy();

    for _ in 0..1000 {
        let challenge_bytes = rng.next_u32().to_le_bytes();
        match EquiXBuilder::new()
            .runtime(RuntimeOption::InterpretOnly)
            .build(&challenge_bytes)
        {
            Ok(_instance) => {
                choices.push(challenge_bytes);
            }
            Err(Error::Hash(HashError::ProgramConstraints)) => (),
            Err(_) => unreachable!(),
        }
    }

    group.bench_function(name, |b| {
        b.iter_batched(
            || choices[rng.next_u32() as usize % choices.len()],
            solve,
            BatchSize::SmallInput,
        );
    });
}

fn bench_verify<F: FnMut(([u8; 4], [u8; 16])) -> T + Copy, T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    verify: F,
) {
    // Benchmark solution verification, from bytes.
    //
    // This pre-generates a set of random challenges and solutions,
    // and then selects random items from that set prior to each
    // benchmark batch.
    //
    // Currently we only bother timing successful verifications, since they
    // should take the longest.
    //
    // We always build these benchmark solutions using the Rust
    // implementation of Equi-X and HashX, using the compiler if possible.
    // This phase is not timed and we just want something fast and easy.

    let mut choices = Vec::<([u8; 4], SolutionByteArray)>::new();
    let mut rng = StdRng::from_entropy();

    // This is doing a full solve, keep this short
    for _ in 0..100 {
        let challenge_bytes = rng.next_u32().to_le_bytes();
        match EquiXBuilder::new().build(&challenge_bytes) {
            Ok(instance) => {
                for solution in instance.solve() {
                    choices.push((challenge_bytes, solution.to_bytes()));
                }
            }
            Err(Error::Hash(HashError::ProgramConstraints)) => (),
            Err(_) => unreachable!(),
        }
    }

    group.bench_function(name, |b| {
        b.iter_batched(
            || choices[rng.next_u32() as usize % choices.len()],
            verify,
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, equix_bench);
criterion_main!(benches);
