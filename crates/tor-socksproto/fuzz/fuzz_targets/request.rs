#![no_main]
use libfuzzer_sys::fuzz_target;

use tor_socksproto::SocksProxyHandshake;

fuzz_target!(|data: Vec<Vec<u8>>| {
    let mut hs = SocksProxyHandshake::new();
    for d in data {
        let _ = hs.handshake(&d);
    }
});
