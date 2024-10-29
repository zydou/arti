#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_general_addr::general;

fuzz_target!(|addr: general::SocketAddr| {
    // There is no encoding for flowinfo, so we have to clear it.
    let mut addr = addr;
    match &mut addr {
        general::SocketAddr::Inet(std::net::SocketAddr::V6(v6)) => v6.set_flowinfo(0),
        _ => {}
    }

    if let Some(encoded) = addr.try_to_string() {
        let parsed: general::SocketAddr = encoded.parse().unwrap();
        assert_eq!(addr, parsed);

        // Since this was encodeable, its lossy encoding should be the same.
        assert_eq!(encoded, format!("{}", addr.display_lossy()))
    }
});
