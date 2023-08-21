//! This is a low-level cachegrind microbenchmark for the C and Rust
//! implementations of HashX, using the Iai framework.
//!
//! Requires valgrind to be installed.
//! Requires the HashX compiler is supported. (aarch64, x86_64)
//!
//! This only includes a small subset of the tests available in hashx_bench,
//! and it only runs a small number of iterations. The focus here is on using
//! cachegrind to measure low-level cache miss behavior and instruction counts.
//! Use hashx_bench to measure real-world performance using wallclock time.

use iai::black_box;

/// Return a Rust `HashBuilder` whose `RuntimeOption` is `$runtime_option`
//
// This and mk_c_equix are macros rather than a function because it avoids us
// having to import RuntimeOption::*, etc. or clutter the calls with a local alias.
macro_rules! mk_rust { { $runtime_option:ident } => { {
    let mut builder = hashx::HashXBuilder::new();
    builder.runtime(hashx::RuntimeOption::$runtime_option);
    builder
} } }

fn generate_interp_1000x() {
    let builder = mk_rust!(InterpretOnly);
    for s in 0_u32..1000_u32 {
        let _ = black_box(builder.build(black_box(&s.to_be_bytes())));
    }
}

fn generate_interp_1000x_c() {
    let mut ctx = tor_c_equix::HashX::new(tor_c_equix::HashXType::HASHX_TYPE_INTERPRETED);
    for s in 0_u32..1000_u32 {
        let _ = black_box(ctx.make(black_box(&s.to_be_bytes())));
    }
}

fn generate_compiled_1000x() {
    let builder = mk_rust!(CompileOnly);
    for s in 0_u32..1000_u32 {
        let _ = black_box(builder.build(black_box(&s.to_be_bytes())));
    }
}

fn generate_compiled_1000x_c() {
    let mut ctx = tor_c_equix::HashX::new(tor_c_equix::HashXType::HASHX_TYPE_COMPILED);
    for s in 0_u32..1000_u32 {
        let _ = black_box(ctx.make(black_box(&s.to_be_bytes())));
    }
}

fn interp_u64_hash_1000x() {
    let builder = mk_rust!(InterpretOnly);
    let hashx = builder.build(b"abc").unwrap();
    for i in 0_u64..1000_u64 {
        let _ = black_box(hashx.hash_to_u64(black_box(i)));
    }
}

fn interp_8b_hash_1000x_c() {
    let mut ctx = tor_c_equix::HashX::new(tor_c_equix::HashXType::HASHX_TYPE_INTERPRETED);
    assert_eq!(ctx.make(b"abc"), tor_c_equix::HashXResult::HASHX_OK);
    for i in 0_u64..1000_u64 {
        let _ = black_box(ctx.exec(black_box(i)));
    }
}

fn compiled_u64_hash_100000x() {
    let builder = mk_rust!(CompileOnly);
    let hashx = builder.build(b"abc").unwrap();
    for i in 0_u64..100000_u64 {
        let _ = black_box(hashx.hash_to_u64(black_box(i)));
    }
}

fn compiled_8b_hash_100000x_c() {
    let mut ctx = tor_c_equix::HashX::new(tor_c_equix::HashXType::HASHX_TYPE_COMPILED);
    assert_eq!(ctx.make(b"abc"), tor_c_equix::HashXResult::HASHX_OK);
    for i in 0_u64..100000_u64 {
        let _ = black_box(ctx.exec(black_box(i)));
    }
}

iai::main!(
    generate_interp_1000x,
    generate_interp_1000x_c,
    generate_compiled_1000x,
    generate_compiled_1000x_c,
    interp_u64_hash_1000x,
    interp_8b_hash_1000x_c,
    compiled_u64_hash_100000x,
    compiled_8b_hash_100000x_c,
);
