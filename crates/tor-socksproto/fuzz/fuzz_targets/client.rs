#![no_main]
use libfuzzer_sys::fuzz_target;

use tor_socksproto::{Buffer, Handshake, NextStep, SocksClientHandshake, SocksRequest};

fuzz_target!(|data: (SocksRequest, Vec<&[u8]>)| {
    let (request, mut data) = data;

    let mut buf = Buffer::new();

    let mut hs = SocksClientHandshake::new(request);

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
