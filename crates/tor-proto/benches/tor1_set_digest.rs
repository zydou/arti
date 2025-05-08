use criterion::{criterion_group, criterion_main, Criterion};
use digest::Digest;
use rand::prelude::*;

use tor_cell::relaycell::msg::SendmeTag;
use tor_llcrypto::d::{Sha1, Sha3_256};
use tor_proto::bench_utils::{tor1::set_digest, RelayBody};

mod cpu_time;
use cpu_time::*;

/// Create a random inbound cell with the digest computed.
fn create_random_cell(rng: &mut ThreadRng) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    cell.into()
}

/// Benchmark the `client_decrypt` function.
pub fn tor1_set_digest_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("tor1_set_digest");
    group.throughput(criterion::Throughput::Bytes(509));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();

                let cell = create_random_cell(&mut rng);
                (cell, Sha1::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, used_digest)| {
                set_digest::<_>(cell, d, used_digest);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();

                let cell = create_random_cell(&mut rng);
                (cell, Sha3_256::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, used_digest)| {
                set_digest::<_>(cell, d, used_digest);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = tor1_set_digest;
   config = Criterion::default()
      .with_measurement(CpuTime)
      .sample_size(5000);
   targets = tor1_set_digest_benchmark);
criterion_main!(tor1_set_digest);
