use criterion::{Criterion, Throughput, criterion_group, criterion_main, measurement::Measurement};
use rand::prelude::*;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use criterion::measurement::WallTime as Meas;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use criterion_cycles_per_byte::CyclesPerByte as Meas;

#[cfg(feature = "counter-galois-onion")]
use aes::{Aes128Enc, Aes256Enc};
use tor_bytes::SecretBuf;
use tor_llcrypto::{
    cipher::aes::{Aes128Ctr, Aes256Ctr},
    d::{Sha1, Sha3_256},
};
#[cfg(feature = "counter-galois-onion")]
use tor_proto::bench_utils::cgo;
use tor_proto::bench_utils::{
    BENCH_CHAN_CMD, CryptInit, InboundRelayLayer, KGen, RelayCellBody, RelayLayer, tor1,
};

/// Helper macro to set up a relay encryption benchmark.
macro_rules! relay_encrypt_setup {
    ($relay_state_construct: path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();

        let relay_state = $relay_state_construct(KGen::new(seed1)).unwrap();
        let (_, relay_state, _) = relay_state.split_relay_layer();

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let cell: RelayCellBody = Box::new(cell).into();
        (cell, relay_state)
    }};
}

/// Benchmark a relay encrypting a relay cell to send to the client.
pub fn relay_encrypt_benchmark(c: &mut Criterion<impl Measurement>) {
    // Group for the Tor1 relay crypto with 498 bytes of data per relay cell.
    let mut group = c.benchmark_group("relay_encrypt");
    group.throughput(Throughput::Bytes(tor1::TOR1_THROUGHPUT));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(tor1::CryptStatePair::<Aes128Ctr, Sha1>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt_inbound(BENCH_CHAN_CMD, cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || relay_encrypt_setup!(tor1::CryptStatePair::<Aes256Ctr, Sha3_256>::construct),
            |(cell, relay_state)| {
                relay_state.encrypt_inbound(BENCH_CHAN_CMD, cell);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();

    #[cfg(feature = "counter-galois-onion")]
    {
        // Group for the Counter-Galois-Onion relay crypto with ~488 bytes of data per relay cell.
        let mut group = c.benchmark_group("relay_encrypt");
        group.throughput(Throughput::Bytes(cgo::CGO_THROUGHPUT));

        group.bench_function("CGO_Aes128", |b| {
            b.iter_batched_ref(
                || relay_encrypt_setup!(cgo::CryptStatePair::<Aes128Enc, Aes128Enc>::construct),
                |(cell, relay_state)| {
                    relay_state.encrypt_inbound(BENCH_CHAN_CMD, cell);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_function("CGO_Aes256", |b| {
            b.iter_batched_ref(
                || relay_encrypt_setup!(cgo::CryptStatePair::<Aes256Enc, Aes256Enc>::construct),
                |(cell, relay_state)| {
                    relay_state.encrypt_inbound(BENCH_CHAN_CMD, cell);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(
    name = relay_encrypt;
    config = Criterion::default()
       .with_measurement(Meas)
       .sample_size(5000);
    targets = relay_encrypt_benchmark);
criterion_main!(relay_encrypt);
