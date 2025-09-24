#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::netstatus::NsConsensus;

fuzz_target!(|data: &str| {
    let _ = NsConsensus::parse(data);
});
