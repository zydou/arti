#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cell::{
    chancell::{BoxedCellBody, CELL_DATA_LEN},
    relaycell::{AnyRelayMsgOuter, RelayCellFormat},
};

fuzz_target!(|data: &[u8]| {
    let mut body: BoxedCellBody = Box::new([0_u8; CELL_DATA_LEN]);
    let copy_len = std::cmp::min(data.len(), body.len());
    body[..copy_len].copy_from_slice(&data[..copy_len]);
    let _ = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, body);
});
