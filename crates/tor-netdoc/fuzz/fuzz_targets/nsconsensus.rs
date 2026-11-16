#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::netstatus::{PlainConsensus, plain};
use tor_netdoc::parse2::{parse_netdoc,ParseInput};

fuzz_target!(|data: &str| {
    let _ = PlainConsensus::parse(data);

    let input = ParseInput::new(data, "<none>");
    let _ = parse_netdoc::<plain::NetworkStatusUnverified>(&input);
});
