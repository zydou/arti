//! Fast-path benchmarks for the [`BandwidthPool`] which is lockless.
//!
//! In normal operation, on a very fast relay, this is the path that matter and is likely
//! to get hit the most. We allow a thundering herd to hit that fast-path concurrently.
//!
//! This bench measures the cost of operations to acquire a permit in such conditions.
//! That fast path is allocation free.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use futures::task::noop_waker_ref;
use std::hint::black_box;
use std::sync::Barrier;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use tor_async_utils::bw_pool::{BandwidthAcquirer, BandwidthPool, BandwidthRefiller};
use web_time_compat::{Instant, InstantExt as _};

/// Benchmark group name
const BENCH_GROUP_NAME: &str = "bw_pool_fast_path";

/// Tokens claimed per acquire. Lets go for a cell size.
const CLAIM: u64 = 514;

/// Helper: Return a pool with enough capacity for `n_iter` iteration of CLAIM.
fn new_bandwidth_pool(n_iter: u64) -> (BandwidthPool, BandwidthRefiller) {
    // Number of iteration times the claim size plus an extra.
    let capacity = n_iter.saturating_mul(CLAIM).saturating_add(CLAIM);
    BandwidthPool::new(capacity)
}

/// Helper: Get the number of cores available and return a list of power of 2 up to that
/// number of cores.
///
/// For example, with 8 cores, the returned list is [2, 4, 8].
fn get_cores_count() -> Vec<usize> {
    // Cap contention at the parallelism actually available to this process. We want to
    // measure CPU cache-line contention, not the OS scheduler timings.
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .expect("Unable to figure out the number of cores");
    // This trick comes from the Internet for the power of 2 list. Kind of neat.
    std::iter::successors(Some(2), |n| Some(n * 2))
        .take_while(|&n| n <= cores)
        .collect()
}

/// Start measuring the fast path acquire that is given an acquirer, a context and the
/// number of iteration to measure.
///
/// Returns the elasped time of the fast path acquisition.
fn measure(acq: &mut BandwidthAcquirer, cx: &mut Context<'_>, n_iter: u64) -> Duration {
    // Start the measurement.
    let start = Instant::get();
    for _ in 0..n_iter {
        // Black box the claim value because it is a constant and to avoid compiler
        // optimization. More of a precautionnary mesure than real problem.
        let mut permit = match acq.poll_acquire(cx, black_box(CLAIM)) {
            Poll::Ready(Ok(permit)) => permit,
            _ => panic!("fast path did not grant a permit"),
        };
        // Claim all so we do not refund on drop.
        permit.claim_all();
        // Insurance that no optimization happens on this unused Permit.
        black_box(&permit);
    }
    // End measurement.
    start.elapsed()
}

/// Run `iters` uncontended claims with a single acquirer and return the measured time.
fn run_uncontended(n_iter: u64) -> Duration {
    // Setup stays outside the measurement.
    //
    // Make sure the pool capacity will cover every claim so all iteration hit
    // the fast path.
    let (pool, _refiller) = new_bandwidth_pool(n_iter);
    let mut acq = pool.new_acquirer();
    let mut cx = Context::from_waker(noop_waker_ref());

    measure(&mut acq, &mut cx, n_iter)
}

/// Single acquirer on a pool without contention because single claimer.
fn fast_path_uncontended(c: &mut Criterion) {
    let mut group = c.benchmark_group(BENCH_GROUP_NAME);
    // Useful so we get the number of acquire per second.
    group.throughput(Throughput::Elements(1));
    group.bench_function("uncontended", |b| {
        b.iter_custom(run_uncontended);
    });
    group.finish();
}

/// Run one contended job.
///
/// The `n_thread` acquirers each claim their share of `iters` from a shared bandwidth
/// pool. All threads start synchronize with a [`Barrier`] in order to maximize the
/// thundering herd effect.
///
/// Returns the slowest measurement from all threads.
fn run_contended(n_iter: u64, n_thread: usize) -> Duration {
    // Split the work equally across all threads. The integer division might drop a bit
    // of work but negligeable.
    let n_permit = n_iter / n_thread as u64;
    let (pool, _refiller) = new_bandwidth_pool(n_iter);
    // The barrier only aligns the start of every thread so they can start
    // racing against each other a.k.a the famously known thundering herd.
    let ready = Barrier::new(n_thread);

    // Ref so we can use them in the move below.
    let pool_ref = &pool;
    let ready_ref = &ready;

    thread::scope(|s| {
        let threads: Vec<_> = (0..n_thread)
            .map(|_| {
                s.spawn(move || {
                    let mut acq = pool_ref.new_acquirer();
                    let mut cx = Context::from_waker(noop_waker_ref());
                    // Once this returns, all threads unblock.
                    ready_ref.wait();
                    measure(&mut acq, &mut cx, n_permit)
                })
            })
            .collect();

        // Each time is one thread's own contended loop time. The herd is
        // done when the slowest finishes so the max value is our baseline.
        threads
            .into_iter()
            .map(|w| w.join().expect("thread panicked"))
            .max()
            .expect("Zero thread count")
    })
}

/// The thundering herd acquirer that is N threads each with its own
/// [`BandwidthAcquirer`] racing to the bandwidth pool.
///
/// Measures how the lockless fast path holds up under contention.
fn fast_path_contended(c: &mut Criterion) {
    let mut group = c.benchmark_group(BENCH_GROUP_NAME);
    // Useful so we get the number of acquire per second.
    group.throughput(Throughput::Elements(1));

    let threads_count = get_cores_count();
    for n_thread in threads_count {
        group.bench_function(format!("contended/{n_thread}"), |b| {
            b.iter_custom(|n_iter| run_contended(n_iter, n_thread));
        });
    }
    group.finish();
}

criterion_group!(benches, fast_path_uncontended, fast_path_contended);
criterion_main!(benches);
