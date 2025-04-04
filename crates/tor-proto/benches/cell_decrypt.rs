use cipher::{KeyIvInit, StreamCipher};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use digest::Digest;

use tor_bytes::SecretBuf;
use tor_cell::relaycell::{RelayCellFormatTrait, RelayCellFormatV0};
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha256},
};
use tor_proto::bench_utils::{
    client_decrypt, encrypt_inbound, HopCryptState, InboundCryptWrapper, RelayBody,
};

mod cpu_time;
use cpu_time::*;

// Helper macro to setup a full circuit decryption benchmark.
macro_rules! full_circuit_inbound_setup {
    ($sc:ty, $d:ty, $f:ty) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();
        let seed2: SecretBuf = b"free to speak, to free ourselves".to_vec().into();
        let seed3: SecretBuf = b"free to hide no more".to_vec().into();

        let mut rng = rand::rng();

        let mut circuit_sates = [
            HopCryptState::construct(seed1.clone()).unwrap(),
            HopCryptState::construct(seed2.clone()).unwrap(),
            HopCryptState::construct(seed3.clone()).unwrap(),
        ];

        let mut cc_in = InboundCryptWrapper::new();
        cc_in.add_layer_from_seed::<$sc, $d, $f>(seed1).unwrap();
        cc_in.add_layer_from_seed::<$sc, $d, $f>(seed2).unwrap();
        cc_in.add_layer_from_seed::<$sc, $d, $f>(seed3).unwrap();

        let cell = create_inbound_cell::<$sc, $d, $f>(&mut rng, &mut circuit_sates);
        (cell, cc_in)
    }};
}

/// Encrypt a random cell using the given circuit crypt states
/// as if it were an inbound cell encrypted by each router in the circuit.
fn create_inbound_cell<
    SC: StreamCipher + KeyIvInit,
    D: Digest + Clone,
    RCF: RelayCellFormatTrait,
>(
    rng: &mut impl rand::Rng,
    circuit_crypt_states: &mut [HopCryptState<SC, D, RCF>],
) -> RelayBody {
    let mut cell = [0u8; 509];
    rng.fill(&mut cell[..]);
    let mut cell: RelayBody = cell.into();

    encrypt_inbound(&mut cell, circuit_crypt_states);

    cell
}

/// Benchmark the `client_decrypt` function.
pub fn cell_decrypt_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("cell_decrypt");
    group.throughput(Throughput::Bytes(509));

    group.bench_function("cell_decrypt_Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || full_circuit_inbound_setup!(Aes128Ctr, Sha1, RelayCellFormatV0),
            |(cell, cc_in)| {
                client_decrypt(cell, cc_in).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("cell_decrypt_Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || full_circuit_inbound_setup!(Aes256Ctr, Sha256, RelayCellFormatV0),
            |(cell, cc_in)| {
                client_decrypt(cell, cc_in).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
   name = cell_decrypt;
   config = Criterion::default()
      .with_measurement(CpuTime)
      .sample_size(5000);
   targets = cell_decrypt_benchmark);
criterion_main!(cell_decrypt);
