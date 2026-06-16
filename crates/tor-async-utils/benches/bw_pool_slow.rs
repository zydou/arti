//! Slow-path benchmarks for the [`BandwidthPool`] which is lockless.
//!
//! The slow path is what happens on an empty pool. Each acquire enqueues a request that
//! the refiller serves.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use futures::task::noop_waker_ref;
use std::hint::black_box;
use std::task::{Context, Poll};

use tor_async_utils::bw_pool::{BandwidthAcquirer, BandwidthPool, BandwidthRefiller, Permit};

/// Benchmark group name
const BENCH_GROUP_NAME: &str = "bw_pool_slow_path";

/// Tokens claimed per acquire. Lets go for a cell size.
const CLAIM: u64 = 514;

/// Helper: Poll the fast path once expecting it to immediately yield a permit.
fn acquire_fast_path(acq: &mut BandwidthAcquirer, cx: &mut Context<'_>, tokens: u64) -> Permit {
    match acq.poll_acquire(cx, tokens) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("fast path did not grant a permit"),
    }
}

/// Helper: Drain the pool with the given `capacity`.
fn drain_pool(acq: &mut BandwidthAcquirer, cx: &mut Context<'_>, capacity: u64) {
    let mut permit = acquire_fast_path(acq, cx, capacity);
    permit.claim_all();
}

/// One full slow-path round-trip:
///
///     1. Enqueue a request.
///     2. Refiller serve it.
///     3. Collect the granted permit.
///
/// The pool starts and ends drained. So the pool can be re-used between iteration.
fn slow_path_roundtrip(
    acq: &mut BandwidthAcquirer,
    refiller: &mut BandwidthRefiller,
    cx: &mut Context<'_>,
) {
    // Miss the fast path and thus enqueue the request.
    match acq.poll_acquire(cx, black_box(CLAIM)) {
        Poll::Pending => {} // Good, we are in the queue.
        other => panic!("expected the acquire to queue but got {other:?}"),
    }

    // The refiller serves the queue and grants it. No deficit.
    assert!(
        refiller.refill(black_box(CLAIM)).is_none(),
        "refill should serve the only queued request",
    );

    // Acquire again to get the permit. This completes the queued roundtrip.
    match acq.poll_acquire(cx, black_box(CLAIM)) {
        Poll::Ready(Ok(mut permit)) => permit.claim_all(),
        other => panic!("expected a granted permit but got {other:?}"),
    }
}

/// The slow path bench.
///
/// It only measures an enqueud request roundtrip.
fn slow_path(c: &mut Criterion) {
    let mut group = c.benchmark_group(BENCH_GROUP_NAME);

    // Capacity only needs to cover a single claim.
    let (pool, mut refiller) = BandwidthPool::new(CLAIM);
    let mut acq = pool.new_acquirer();
    let mut cx = Context::from_waker(noop_waker_ref());
    // Empty the pool before we start.
    drain_pool(&mut acq, &mut cx, CLAIM);

    // Useful so we get the number of roundtrip per second.
    group.throughput(Throughput::Elements(1));
    group.bench_function("roundtrip", |b| {
        b.iter(|| slow_path_roundtrip(&mut acq, &mut refiller, &mut cx));
    });
    group.finish();
}

criterion_group!(benches, slow_path);
criterion_main!(benches);
