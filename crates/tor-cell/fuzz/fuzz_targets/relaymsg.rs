#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cell::relaycell::AnyRelayCell;
use tor_bytes::Reader;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::from_slice(data);
    let _ = AnyRelayCell::decode_from_reader(&mut r);
});
