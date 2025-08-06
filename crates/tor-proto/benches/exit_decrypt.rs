use criterion::{Criterion, Throughput, criterion_group, criterion_main, measurement::Measurement};

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use criterion::measurement::WallTime as Meas;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use criterion_cycles_per_byte::CyclesPerByte as Meas;

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
use tor_proto::bench_utils::{
    BENCH_CHAN_CMD, CryptInit, KGen, OutboundClientCrypt, OutboundRelayLayer, RelayCellBody,
    RelayLayer, tor1,
};

const HOP_NUM: u8 = 0;

/// Helper macro to set up an exit decryption benchmark.
macro_rules! exit_decrypt_setup {
    ($client_state_construct: path, $relay_state_construct: path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();

        // No need to simulate other relays since we are only benchmarking the exit relay.
        let exit_state = $relay_state_construct(KGen::new(seed1.clone())).unwrap();
        let (exit_state, _, _) = exit_state.split_relay_layer();

        let mut cc_out = OutboundClientCrypt::new();
        let state1 = $client_state_construct(KGen::new(seed1)).unwrap();
        cc_out.add_layer_from_pair(state1);

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let mut cell: RelayCellBody = Box::new(cell).into();
        cc_out
            .encrypt(BENCH_CHAN_CMD, &mut cell, HOP_NUM.into())
            .unwrap();
        (cell, exit_state)
    }};
}

/// Benchmark an exit decrypting a relay cell coming from the client.
/// Unlike the relay decrypt benchmark, this one should also recognize the relay cell.
pub fn exit_decrypt_benchmark(c: &mut Criterion<impl Measurement>) {
    // Group for the Tor1 relay crypto with 498 bytes of data per relay cell.
    let mut group = c.benchmark_group("exit_decrypt");
    group.throughput(Throughput::Bytes(tor1::TOR1_THROUGHPUT));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    tor1::CryptStatePair::<Aes128Ctr, Sha1>::construct,
                    tor1::CryptStatePair::<Aes128Ctr, Sha1>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt_outbound(BENCH_CHAN_CMD, cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || {
                exit_decrypt_setup!(
                    tor1::CryptStatePair::<Aes256Ctr, Sha3_256>::construct,
                    tor1::CryptStatePair::<Aes256Ctr, Sha3_256>::construct
                )
            },
            |(cell, exit_state)| {
                exit_state.decrypt_outbound(BENCH_CHAN_CMD, cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();

    #[cfg(feature = "counter-galois-onion")]
    {
        // Group for the Counter-Galois-Onion relay crypto with ~488 bytes of data per relay cell.
        let mut group = c.benchmark_group("exit_decrypt");
        group.throughput(Throughput::Bytes(cgo::CGO_THROUGHPUT));

        group.bench_function("CGO_Aes128", |b| {
            b.iter_batched_ref(
                || {
                    exit_decrypt_setup!(
                        cgo::CryptStatePair::<Aes128Dec, Aes128Enc>::construct,
                        cgo::CryptStatePair::<Aes128Enc, Aes128Enc>::construct
                    )
                },
                |(cell, exit_state)| {
                    exit_state.decrypt_outbound(BENCH_CHAN_CMD, cell);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_function("CGO_Aes256", |b| {
            b.iter_batched_ref(
                || {
                    exit_decrypt_setup!(
                        cgo::CryptStatePair::<Aes256Dec, Aes256Enc>::construct,
                        cgo::CryptStatePair::<Aes256Enc, Aes256Enc>::construct
                    )
                },
                |(cell, exit_state)| {
                    exit_state.decrypt_outbound(BENCH_CHAN_CMD, cell);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(
    name = exit_decrypt;
    config = Criterion::default()
       .with_measurement(Meas)
       .sample_size(5000);
    targets = exit_decrypt_benchmark);
criterion_main!(exit_decrypt);
