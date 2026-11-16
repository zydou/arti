#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::netstatus::{MdConsensus, md};
use tor_netdoc::parse2::{parse_netdoc, ParseInput};

fuzz_target!(|s: &str| {
    let _ = MdConsensus::parse(s);

    let input = ParseInput::new(s, "<none>");
    let _ = parse_netdoc::<md::NetworkStatusUnverified>(&input);
});
