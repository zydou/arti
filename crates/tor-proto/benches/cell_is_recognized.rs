use criterion::{criterion_group, criterion_main, Criterion};
use digest::{generic_array::GenericArray, Digest};
use rand::prelude::*;

use tor_cell::relaycell::{RelayCellFormatTrait, RelayCellFormatV0};
use tor_llcrypto::d::{Sha1, Sha3_256};
use tor_proto::bench_utils::RelayBody;

mod cpu_time;
use cpu_time::*;

/// Create a random inbound cell with the digest computed.
fn create_digested_cell<D: Digest + Clone, RCF: RelayCellFormatTrait>(
    rng: &mut ThreadRng,
    d: &mut D,
) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    let mut cell: RelayBody = cell.into();
    let mut used_digest = GenericArray::default();

    cell.set_digest::<_, RCF>(d, &mut used_digest);

    cell
}

/// Benchmark the `client_decrypt` function.
pub fn cell_is_recognized_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("cell_is_recognized");
    group.throughput(criterion::Throughput::Bytes(509));

    group.bench_function("cell_is_recognized_Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();
                let mut d = Sha1::new();

                let cell = create_digested_cell::<_, RelayCellFormatV0>(&mut rng, &mut d);
                (cell, Sha1::new(), GenericArray::default())
            },
            |(cell, d, rcvd)| {
                cell.is_recognized::<_, RelayCellFormatV0>(d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("cell_is_recognized_Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();
                let mut d = Sha3_256::new();

                let cell = create_digested_cell::<_, RelayCellFormatV0>(&mut rng, &mut d);
                (cell, Sha3_256::new(), GenericArray::default())
            },
            |(cell, d, rcvd)| {
                cell.is_recognized::<_, RelayCellFormatV0>(d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = cell_is_recognized;
   config = Criterion::default()
      .with_measurement(CpuTime)
      .sample_size(5000);
   targets = cell_is_recognized_benchmark);
criterion_main!(cell_is_recognized);
