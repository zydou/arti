#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::netstatus::PlainConsensus;

fuzz_target!(|data: &str| {
    let _ = PlainConsensus::parse(data);
});
