#![no_main]
use libfuzzer_sys::fuzz_target;

use tor_socksproto::{Buffer, Handshake, NextStep, SocksProxyHandshake};

fuzz_target!(|data: Vec<&[u8]>| {
    let mut data = data;

    let mut hs = SocksProxyHandshake::new();
    let mut buf = Buffer::new();

    loop {
        match hs.step(&mut buf) {
            Ok(NextStep::Send(_)) => {}
            Ok(NextStep::Recv(mut rs)) => {
                let Some(v) = data.pop() else { break };

                let l = v.len().min(rs.buf().len());
                rs.buf()[..l].copy_from_slice(&v[..l]);
                let Ok(()) = rs.note_received(l) else { break };
            }
            Ok(NextStep::Finished(_)) | Err(_) => {
                break;
            }
        }
    }
});
