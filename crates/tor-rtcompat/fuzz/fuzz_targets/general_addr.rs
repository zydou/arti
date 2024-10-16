#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use tor_rtcompat::general;

fuzz_target!(|data: &str| {
    if let Ok(addr1) = general::SocketAddr::from_str(data) {
        // 1: If we can parse it, we can represent it.
        let data2 = addr1.try_to_string().unwrap();
        // 2: If we represent it, we can parse it again and get the same thing.
        let addr2 = general::SocketAddr::from_str(&data2).unwrap();
        assert_eq!(addr1, addr2);
    }
});
