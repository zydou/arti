use criterion::{Criterion, criterion_group, criterion_main, measurement::Measurement};
use digest::Digest;
use rand::prelude::*;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use criterion::measurement::WallTime as Meas;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use criterion_cycles_per_byte::CyclesPerByte as Meas;

use tor_cell::relaycell::msg::SendmeTag;
use tor_llcrypto::d::{Sha1, Sha3_256};
use tor_proto::bench_utils::{RelayCellBody, tor1};

/// Create a random inbound cell with the digest computed.
fn create_digested_cell<D: Digest + Clone>(rng: &mut ThreadRng, d: &mut D) -> RelayCellBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    let mut cell: RelayCellBody = Box::new(cell).into();
    let mut used_digest = SendmeTag::from([0_u8; 20]);

    cell.set_digest(d, &mut used_digest);

    cell
}

/// Benchmark the `is_recognized` method.
pub fn tor1_is_recognized_benchmark(c: &mut Criterion<impl Measurement>) {
    let mut group = c.benchmark_group("tor1_is_recognized");
    group.throughput(criterion::Throughput::Bytes(tor1::TOR1_THROUGHPUT));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();
                let mut d = Sha1::new();

                let cell = create_digested_cell::<_>(&mut rng, &mut d);
                (cell, Sha1::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, rcvd)| {
                cell.is_recognized(d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::rng();
                let mut d = Sha3_256::new();

                let cell = create_digested_cell::<_>(&mut rng, &mut d);
                (cell, Sha3_256::new(), SendmeTag::from([0_u8; 20]))
            },
            |(cell, d, rcvd)| {
                cell.is_recognized(d, rcvd);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = tor1_is_recognized;
   config = Criterion::default()
      .with_measurement(Meas)
      .sample_size(5000);
   targets = tor1_is_recognized_benchmark);
criterion_main!(tor1_is_recognized);
