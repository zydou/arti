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

/// Bind Rust `HashBuilder` whose `RuntimeOption` is `$runtime_option` to `$builder`
//
// This and mk_c_equix are macros rather than a function because it avoids us
// having to import RuntimeOption::*, etc. or clutter the calls with a local alias.
macro_rules! mk_rust { { $builder:ident = $runtime_option:ident } => {
    let mut $builder = hashx::HashXBuilder::new();
    $builder.runtime(hashx::RuntimeOption::$runtime_option);
} }

/// Bind a C `HashX` whose `HashXType` is `$hashx_type` to `$ctx`
macro_rules! mk_c_equix { { $ctx:ident = $hashx_type:ident } => {
    let mut $ctx = tor_c_equix::HashX::new(tor_c_equix::HashXType::$hashx_type);
} }

/// Evaluate `$eval` binding `$loopvar` to `0..$max`
///
/// Applies `black_box` to inputs and outputs.
///
/// If `$loopvar_map` is supplied, it is a function applied to $loopvar
/// to convert from the integer loop variable, to whatever more useful type is needed.
//
// We expect $loopvar_map:ident even though a closure would be suitable, mostly because
// we expect the actual benchmark cases to want to use a short alias like `u32be`
macro_rules! bench_loop { {
    $loopvar:ident, $max:expr $(, $loopvar_map:ident )? => $eval:expr
} => {
    for $loopvar in 0..$max {
        $(
            let $loopvar = $loopvar_map($loopvar);
        )?
        let $loopvar = black_box($loopvar);
        let _ = black_box($eval);
    }
} }

/// Convenience alias to reduce clutter in actual benchmarks
const C_HASHX_OK: tor_c_equix::ffi::hashx_result = tor_c_equix::HashXResult::HASHX_OK;

/// Helper, alias for `u32::to_be_bytes`
//
// Unfortunately, we can't just `use u32::to_be_bytes`.
fn u32be(s: u32) -> [u8; 4] {
    s.to_be_bytes()
}

fn generate_interp_1000x() {
    mk_rust!(builder = InterpretOnly);
    bench_loop! { s, 1000_u32, u32be => builder.build(&s) }
}

fn generate_interp_1000x_c() {
    mk_c_equix!(ctx = HASHX_TYPE_INTERPRETED);
    bench_loop! { s, 1000_u32, u32be => ctx.make(&s) }
}

fn generate_compiled_1000x() {
    mk_rust!(builder = CompileOnly);
    bench_loop! { s, 1000_u32, u32be => builder.build(&s) }
}

fn generate_compiled_1000x_c() {
    mk_c_equix!(ctx = HASHX_TYPE_COMPILED);
    bench_loop! { s, 1000_u32, u32be => ctx.make(&s) }
}

fn interp_u64_hash_1000x() {
    mk_rust!(builder = InterpretOnly);
    let hashx = builder.build(b"abc").unwrap();
    bench_loop! { i, 1000_u64 => hashx.hash_to_u64(i) }
}

fn interp_8b_hash_1000x_c() {
    mk_c_equix!(ctx = HASHX_TYPE_INTERPRETED);
    assert_eq!(ctx.make(b"abc"), C_HASHX_OK);
    bench_loop! { i, 1000_u64 => ctx.exec(i) }
}

fn compiled_u64_hash_100000x() {
    mk_rust!(builder = CompileOnly);
    let hashx = builder.build(b"abc").unwrap();
    bench_loop! { i, 100000_u64 => hashx.hash_to_u64(i) }
}

fn compiled_8b_hash_100000x_c() {
    mk_c_equix!(ctx = HASHX_TYPE_COMPILED);
    assert_eq!(ctx.make(b"abc"), C_HASHX_OK);
    bench_loop! { i, 100000_u64 => ctx.exec(i) }
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
