// Test for encoding/decoding channel cells.
//
// Reminder: you can think of a cell as an message plus a circuitid.
#![allow(clippy::uninlined_format_args)]

use tor_cell::Error;
use tor_cell::chancell::msg::AnyChanMsg;
use tor_cell::chancell::{AnyChanCell, ChanCmd, ChanMsg, CircId, codec, msg};

use bytes::BytesMut;
use hex_literal::hex;

const FIXED_BODY_LEN: usize = 514;

fn decode(body: &str, pad_body: bool) -> Vec<u8> {
    let mut body = body.to_string();
    body.retain(|c| !c.is_whitespace());
    let mut body = hex::decode(body).unwrap();
    if pad_body {
        body.resize(FIXED_BODY_LEN, 0);
    }
    body
}

fn cell(body: &str, msg: msg::AnyChanMsg, id: Option<CircId>, pad_body: bool) {
    let body = decode(body, pad_body);

    let cell = AnyChanCell::new(id, msg);
    let mut codec = codec::ChannelCodec::new(4);

    let decoded = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        bm.extend_from_slice(&b"next thing"[..]);
        let decoded = codec.decode_cell::<AnyChanMsg>(&mut bm).unwrap();
        assert_eq!(bm.len(), 10);
        decoded.unwrap()
    };

    let decoded2 = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        // no extra bytes this time.
        let decoded = codec.decode_cell::<AnyChanMsg>(&mut bm).unwrap();
        assert_eq!(bm.len(), 0);
        decoded.unwrap()
    };

    assert_eq!(format!("{:?}", decoded), format!("{:?}", cell));
    assert_eq!(format!("{:?}", decoded2), format!("{:?}", cell));

    let mut encoded1 = BytesMut::new();
    let mut encoded2 = BytesMut::new();
    codec.write_cell(cell, &mut encoded1).unwrap();
    codec.write_cell(decoded, &mut encoded2).unwrap();

    assert_eq!(encoded1, encoded2);
    assert_eq!(encoded1, body);
}

fn fcell(body: &str, msg: msg::AnyChanMsg, id: Option<CircId>) {
    cell(body, msg, id, true);
}

fn vcell(body: &str, msg: msg::AnyChanMsg, id: Option<CircId>) {
    cell(body, msg, id, false);
}

#[test]
fn test_simple_cells() {
    fcell("", msg::Padding::new().into(), None);

    vcell(
        "12345678 ff 0019 7765206c697374656e20726f756e642074686520636c6f636b",
        msg::Unrecognized::new(255.into(), &b"we listen round the clock"[..]).into(),
        CircId::new(0x12345678),
    );

    fcell(
        "20201122 03 666f72206120636f64652063616c6c656420706561636574696d65",
        msg::Relay::new(b"for a code called peacetime").into(),
        CircId::new(0x20201122),
    );

    // Now try some accessors.
    let m = decode(
        "20201122 03 666f72206120636f64652063616c6c656420706561636574696d65",
        true,
    );
    let cell = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&m);
        codec::ChannelCodec::new(4)
            .decode_cell::<AnyChanMsg>(&mut bm)
            .unwrap()
            .unwrap()
    };
    assert_eq!(cell.circid(), CircId::new(0x20201122));
    assert_eq!(cell.msg().cmd(), ChanCmd::RELAY);
    let (id, msg) = cell.into_circid_and_msg();
    assert_eq!(id, CircId::new(0x20201122));
    assert_eq!(msg.cmd(), ChanCmd::RELAY);
}

fn short_cell(body: &str) {
    let body = decode(body, false);

    let mut codec = codec::ChannelCodec::new(4);

    let mut bm = BytesMut::new();
    bm.extend_from_slice(&body[..]);
    let len_orig = bm.len();
    let d = codec.decode_cell::<AnyChanMsg>(&mut bm);
    assert!(d.unwrap().is_none()); // "Ok(None)" means truncated.
    assert_eq!(bm.len(), len_orig);
}

#[test]
fn test_truncated_cells() {
    // short relay (fixed)
    short_cell("00000001 03 1234");
    short_cell("00000001 03 12");
    short_cell("00000001 03 ");
    short_cell("00000001");
    short_cell("000000");
    short_cell("");

    // short certs (varlen)
    short_cell("00000000 81 0003 1234");
    short_cell("00000000 81 0003 12");
    short_cell("00000000 81 0003 ");
    short_cell("00000000 81 00 ");
    short_cell("00000000 81 ");
}

fn bad_cell(body: &str, err: Error, pad_body: bool) {
    let body = decode(body, pad_body);

    let mut codec = codec::ChannelCodec::new(4);

    let decoded = {
        let mut bm = BytesMut::new();
        bm.extend_from_slice(&body[..]);
        bm.extend_from_slice(&b"next thing"[..]);
        codec.decode_cell::<AnyChanMsg>(&mut bm).err().unwrap()
    };

    assert_eq!(format!("{:?}", decoded), format!("{:?}", err));
}

#[test]
fn bad_circid_cells() {
    // relay, no circid
    bad_cell(
        "00000000 03 123456",
        Error::ChanProto("Invalid circuit ID 0 for cell command RELAY".into()),
        true,
    );

    // relay, unexpected circid
    bad_cell(
        "00000010 08 123456",
        Error::ChanProto("Invalid circuit ID 16 for cell command NETINFO".into()),
        true,
    );
}

#[test]
fn versions() {
    // Test the special encoding of the versions cell.  (It's special
    // because it uses a 2-byte circid.
    let v = msg::Versions::new([4, 5, 6]).unwrap();
    let encoded = v.clone().encode_for_handshake().unwrap();
    assert_eq!(encoded, hex!("0000 07 0006 0004 0005 0006"));

    // Test the best_shared_protocol function.
    assert_eq!(v.best_shared_link_protocol(&[1, 2, 3, 77]), None);
    assert_eq!(v.best_shared_link_protocol(&[]), None);
    assert_eq!(v.best_shared_link_protocol(&[4, 5, 6, 7]), Some(6));
    assert_eq!(v.best_shared_link_protocol(&[4, 5, 11]), Some(5));
    assert_eq!(v.best_shared_link_protocol(&[4, 5]), Some(5));

    // Try converting into a ChanCell.
    let cc: AnyChanCell = v.into();
    assert_eq!(cc.circid(), None);
}
