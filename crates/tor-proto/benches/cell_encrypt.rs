use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::prelude::*;

use tor_bytes::SecretBuf;
use tor_cell::relaycell::RelayCellFormatV0;
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha256},
};
use tor_proto::bench_utils::{client_encrypt, OutboundCryptWrapper, RelayBody};

mod cpu_time;
use cpu_time::*;

const HOP_NUM: u8 = 2;

/// Create a random outbound cell.
fn create_outbound_cell(rng: &mut ThreadRng) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    cell.into()
}

/// Benchmark the `client_encrypt` function.
pub fn cell_encrypt_benchmark(c: &mut Criterion<CpuTime>) {
    let seed1: SecretBuf = b"hidden we are free".to_vec().into();
    let seed2: SecretBuf = b"free to speak, to free ourselves".to_vec().into();
    let seed3: SecretBuf = b"free to hide no more".to_vec().into();

    let mut group = c.benchmark_group("cell_encrypt");
    group.throughput(Throughput::Bytes(509));

    group.bench_function("cell_encrypt_Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();

                let mut cc_out = OutboundCryptWrapper::new();
                cc_out
                    .add_layer_from_seed::<Aes128Ctr, Sha1, RelayCellFormatV0>(seed1.clone())
                    .unwrap();
                cc_out
                    .add_layer_from_seed::<Aes128Ctr, Sha1, RelayCellFormatV0>(seed2.clone())
                    .unwrap();
                cc_out
                    .add_layer_from_seed::<Aes128Ctr, Sha1, RelayCellFormatV0>(seed3.clone())
                    .unwrap();

                let cell = create_outbound_cell(&mut rng);

                (cell, cc_out)
            },
            |(cell, cc_out)| {
                client_encrypt(cell, cc_out, HOP_NUM).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("cell_encrypt_Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                let mut rng = rand::thread_rng();

                let mut cc_out = OutboundCryptWrapper::new();
                cc_out
                    .add_layer_from_seed::<Aes256Ctr, Sha256, RelayCellFormatV0>(seed1.clone())
                    .unwrap();
                cc_out
                    .add_layer_from_seed::<Aes256Ctr, Sha256, RelayCellFormatV0>(seed2.clone())
                    .unwrap();
                cc_out
                    .add_layer_from_seed::<Aes256Ctr, Sha256, RelayCellFormatV0>(seed3.clone())
                    .unwrap();

                let cell = create_outbound_cell(&mut rng);

                (cell, cc_out)
            },
            |(cell, cc_out)| {
                client_encrypt(cell, cc_out, HOP_NUM).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = cell_encrypt;
   config = Criterion::default()
      .with_measurement(CpuTime)
      .sample_size(5000);
   targets = cell_encrypt_benchmark);
criterion_main!(cell_encrypt);
