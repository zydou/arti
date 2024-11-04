use criterion::{criterion_group, criterion_main, Criterion};
use digest::{generic_array::GenericArray, Digest};
use rand::prelude::*;

use tor_cell::relaycell::RelayCellFormatV0;
use tor_llcrypto::d::{Sha1, Sha3_256};
use tor_proto::bench_utils::RelayBody;

mod cpu_time;
use cpu_time::*;

/// Create a random inbound cell with the digest computed.
fn create_random_cell(rng: &mut ThreadRng) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    cell.into()
}

/// Benchmark the `client_decrypt` function.
pub fn cell_set_digest_benchmark(c: &mut Criterion<CPUTime>) {
    let mut group = c.benchmark_group("cell_set_digest");
    group.throughput(criterion::Throughput::Bytes(509));

    group.bench_function("cell_set_digest_Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();

                let cell = create_random_cell(&mut rng);
                (cell, Sha1::new(), GenericArray::default())
            },
            |(cell, d, used_digest)| {
                cell.set_digest::<_, RelayCellFormatV0>(d, used_digest);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("cell_set_digest_Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();

                let cell = create_random_cell(&mut rng);
                (cell, Sha3_256::new(), GenericArray::default())
            },
            |(cell, d, used_digest)| {
                cell.set_digest::<_, RelayCellFormatV0>(d, used_digest);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = cell_set_digest;
   config = Criterion::default()
      .with_measurement(CPUTime)
      .sample_size(5000);
   targets = cell_set_digest_benchmark);
criterion_main!(cell_set_digest);
