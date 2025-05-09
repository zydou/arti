use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::prelude::*;

#[cfg(feature = "counter-galois-onion")]
use aes::{Aes128Dec, Aes128Enc, Aes256Dec, Aes256Enc};
use tor_bytes::SecretBuf;
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha3_256},
};
#[cfg(feature = "counter-galois-onion")]
use tor_proto::bench_utils::cgo;
use tor_proto::bench_utils::{tor1, OutboundClientCryptWrapper, RelayBody, RelayCryptState};

mod cpu_time;
use cpu_time::*;

const HOP_NUM: u8 = 0;

/// Helper macro to set up an exit decryption benchmark.
macro_rules! exit_decrypt_setup {
    ($client_state_construct: path, $relay_state_construct: path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();

        // No need to simulate other relays since we are only benchmarking the exit relay.
        let exit_state = $relay_state_construct(seed1.clone()).unwrap();

        let mut cc_out = OutboundClientCryptWrapper::new();
        let state1 = $client_state_construct(seed1).unwrap();
        cc_out.add_layer(state1);

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let mut cell: RelayBody = cell.into();
        cc_out.encrypt(&mut cell, HOP_NUM).unwrap();
        (cell, exit_state)
    }};
}

/// Benchmark an exit decrypting a relay cell coming from the client.
/// Unlike the relay decrypt benchmark, this one should also recognize the relay cell.
pub fn exit_decrypt_benchmark(c: &mut Criterion<CpuTime>) {
    let mut group = c.benchmark_group("exit_decrypt");
    group.throughput(Throughput::Bytes(509));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    tor1::Tor1ClientCryptState::<Aes128Ctr, Sha1>::construct,
                    tor1::Tor1RelayCryptState::<Aes128Ctr, Sha1>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    tor1::Tor1ClientCryptState::<Aes256Ctr, Sha3_256>::construct,
                    tor1::Tor1RelayCryptState::<Aes256Ctr, Sha3_256>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes128", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    cgo::CgoClientCryptState::<Aes128Dec, Aes128Enc>::construct,
                    cgo::CgoRelayCryptState::<Aes128Enc, Aes128Enc>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    #[cfg(feature = "counter-galois-onion")]
    group.bench_function("CGO_Aes256", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    cgo::CgoClientCryptState::<Aes256Dec, Aes256Enc>::construct,
                    cgo::CgoRelayCryptState::<Aes256Enc, Aes256Enc>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt(cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    name = exit_decrypt;
    config = Criterion::default()
       .with_measurement(CpuTime)
       .sample_size(5000);
    targets = exit_decrypt_benchmark);
criterion_main!(exit_decrypt);
