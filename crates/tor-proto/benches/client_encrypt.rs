use criterion::{Criterion, Throughput, criterion_group, criterion_main, measurement::Measurement};
use rand::prelude::*;

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
use criterion::measurement::WallTime as Meas;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use criterion_cycles_per_byte::CyclesPerByte as Meas;

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
    BENCH_CHAN_CMD, CryptInit, KGen, OutboundClientCrypt, RelayCellBody, tor1,
};

const HOP_NUM: u8 = 2;

/// Helper macro to set up a client encryption benchmark.
macro_rules! client_encrypt_setup {
    ($client_state_construct:path) => {{
        let seed1: SecretBuf = b"hidden we are free".to_vec().into();
        let seed2: SecretBuf = b"free to speak, to free ourselves".to_vec().into();
        let seed3: SecretBuf = b"free to hide no more".to_vec().into();

        let mut cc_out = OutboundClientCrypt::new();
        let state1 = $client_state_construct(KGen::new(seed1)).unwrap();
        cc_out.add_layer_from_pair(state1);
        let state2 = $client_state_construct(KGen::new(seed2)).unwrap();
        cc_out.add_layer_from_pair(state2);
        let state3 = $client_state_construct(KGen::new(seed3)).unwrap();
        cc_out.add_layer_from_pair(state3);

        let mut rng = rand::rng();
        let mut cell = [0u8; 509];
        rng.fill(&mut cell[..]);
        let cell: RelayCellBody = Box::new(cell).into();
        (cell, cc_out)
    }};
}

/// Benchmark a client encrypting a relay cell to send to a circuit.
pub fn client_encrypt_benchmark(c: &mut Criterion<impl Measurement>) {
    // Group for the Tor1 relay crypto with 498 bytes of data per relay cell.
    let mut group = c.benchmark_group("client_encrypt");
    group.throughput(Throughput::Bytes(tor1::TOR1_THROUGHPUT));

    group.bench_function("Tor1RelayCrypto", |b| {
        b.iter_batched_ref(
            || client_encrypt_setup!(tor1::CryptStatePair::<Aes128Ctr, Sha1>::construct),
            |(cell, cc_out)| {
                cc_out
                    .encrypt(BENCH_CHAN_CMD, cell, HOP_NUM.into())
                    .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Tor1Hsv3RelayCrypto", |b| {
        b.iter_batched_ref(
            || client_encrypt_setup!(tor1::CryptStatePair::<Aes256Ctr, Sha3_256>::construct),
            |(cell, cc_out)| {
                cc_out
                    .encrypt(BENCH_CHAN_CMD, cell, HOP_NUM.into())
                    .unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();

    #[cfg(feature = "counter-galois-onion")]
    {
        // Group for the Counter-Galois-Onion relay crypto with ~488 bytes of data per relay cell.
        let mut group = c.benchmark_group("client_encrypt");
        group.throughput(Throughput::Bytes(cgo::CGO_THROUGHPUT));

        group.bench_function("CGO_Aes128", |b| {
            b.iter_batched_ref(
                || client_encrypt_setup!(cgo::CryptStatePair::<Aes128Dec, Aes128Enc>::construct),
                |(cell, cc_out)| {
                    cc_out
                        .encrypt(BENCH_CHAN_CMD, cell, HOP_NUM.into())
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.bench_function("CGO_Aes256", |b| {
            b.iter_batched_ref(
                || client_encrypt_setup!(cgo::CryptStatePair::<Aes256Dec, Aes256Enc>::construct),
                |(cell, cc_out)| {
                    cc_out
                        .encrypt(BENCH_CHAN_CMD, cell, HOP_NUM.into())
                        .unwrap();
                },
                criterion::BatchSize::SmallInput,
            );
        });

        group.finish();
    }
}

criterion_group!(
   name = client_encrypt;
   config = Criterion::default()
      .with_measurement(Meas)
      .sample_size(5000);
   targets = client_encrypt_benchmark);
criterion_main!(client_encrypt);
