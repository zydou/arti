#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::hsdesc::{HsDescInner, HsDescMiddle, HsDescOuter};

fuzz_target!(|data: &[u8]| {
    if data.len() > 0 {
        if let Ok(s) = std::str::from_utf8(&data[1..]) {
            match data[0] % 3 {
                0 => {
                    let _ = HsDescInner::parse(s);
                }
                1 => {
                    let _ = HsDescMiddle::parse(s);
                }
                2 => {
                    let _ = HsDescOuter::parse(s);
                }
                _ => panic!("uh oh, math broke"),
            }
        }
    }
});
