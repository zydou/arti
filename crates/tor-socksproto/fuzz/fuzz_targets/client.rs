#![no_main]
use libfuzzer_sys::fuzz_target;

use tor_socksproto::{SocksClientHandshake, SocksRequest};

fuzz_target!(|data: (SocksRequest, Vec<Vec<u8>>)| {
    let (request, data) = data;
    let mut hs = SocksClientHandshake::new(request);
    for d in data {
        let _ = hs.handshake(&d);
    }
});
