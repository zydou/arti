#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use tor_ptmgr::ipc::PtMessage;

fuzz_target!(|data: &str| {
    let _ = PtMessage::from_str(data);
});
