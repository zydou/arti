#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::authcert::AuthCert;

fuzz_target!(|data: &str| {
    if let Ok(certs) = AuthCert::parse_multiple(data) {
        for _ in certs {}
    }
});
