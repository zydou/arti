use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::prelude::*;

#[cfg(feature = "counter-galois-onion")]
use aes::{Aes128Enc, Aes256Enc};
use tor_bytes::SecretBuf;
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha3_256},
};
#[cfg(feature = "counter-galois-onion")]
use tor_proto::bench_utils::cgo;
use tor_proto::bench_utils::{tor1, RelayBody, RelayCryptState};

mod cpu_time;
use cpu_time::*;

/// Helper macro to set up a relay encryption benchmark.
macro_rules! relay_encrypt_setup {
    ($relay_state_construct: path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();

        // No need to simulate other relays since we are only benchmarking one relay.
        let relay_state = $relay_state_construct(seed1.clone()).unwrap();

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let cell: RelayBody = cell.into();
        (cell, relay_state)
    }};
}

/// Benchmark a relay encrypting a relay cell to send to the client.
pub fn relay_encrypt_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("relay_encrypt");
    group.throughput(Throughput::Bytes(509));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(tor1::Tor1RelayCryptState::<Aes128Ctr, Sha1>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(tor1::Tor1RelayCryptState::<Aes256Ctr, Sha3_256>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes128", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(cgo::CgoRelayCryptState::<Aes128Enc, Aes128Enc>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes256", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(cgo::CgoRelayCryptState::<Aes256Enc, Aes256Enc>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    name = relay_encrypt;
    config = Criterion::default()
       .with_measurement(CpuTime)
       .sample_size(5000);
    targets = relay_encrypt_benchmark);
criterion_main!(relay_encrypt);
