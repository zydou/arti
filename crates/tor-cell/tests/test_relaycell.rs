// Tests for encoding/decoding relay messages into relay cell bodies.
#![allow(clippy::uninlined_format_args)]

use tor_bytes::Error;
use tor_cell::relaycell::{
    AnyRelayMsgOuter, RelayCellFormat, RelayCmd, RelayMsg, StreamId, UnparsedRelayMsg,
    msg::{self, AnyRelayMsg},
};

#[cfg(feature = "experimental-udp")]
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
#[cfg(feature = "experimental-udp")]
use tor_cell::relaycell::udp::Address;

const CELL_BODY_LEN: usize = 509;

struct BadRng;
impl rand::RngCore for BadRng {
    fn next_u32(&mut self) -> u32 {
        0xf0f0f0f0
    }
    fn next_u64(&mut self) -> u64 {
        0xf0f0f0f0f0f0f0f0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0xf0);
    }
}

// I won't tell if you don't.
impl rand::CryptoRng for BadRng {}

fn decode(body: &str) -> Box<[u8; CELL_BODY_LEN]> {
    let mut body = body.to_string();
    body.retain(|c| !c.is_whitespace());
    let mut body = hex::decode(body).unwrap();
    body.resize(CELL_BODY_LEN, 0xf0); // see BadRng

    let mut result = [0; CELL_BODY_LEN];
    result.copy_from_slice(&body[..]);
    Box::new(result)
}

// Run several tests, requiring that that `body`, is the default encdoding of `msg` with `version`.
fn cell(version: RelayCellFormat, body: &str, id: Option<StreamId>, msg: AnyRelayMsg) {
    let body = decode(body);
    let mut bad_rng = BadRng;

    // encode the cell msg so that we can get its length
    let mut encoded_msg = Vec::new();
    msg.clone().encode_onto(&mut encoded_msg).unwrap();

    let expected = AnyRelayMsgOuter::new(id, msg);

    let decoded = AnyRelayMsgOuter::decode_singleton(version, body.clone()).unwrap();

    let unparsed = UnparsedRelayMsg::from_singleton_body(version, body).unwrap();

    // check the accessors for `UnparsedRelayMsg`
    assert_eq!(unparsed.cmd(), decoded.cmd());
    assert_eq!(unparsed.stream_id(), decoded.stream_id());
    if unparsed.cmd() == RelayCmd::DATA {
        assert_eq!(unparsed.data_len().map(usize::from), Ok(encoded_msg.len()));
    } else {
        // if not a DATA cell, then there are no data bytes
        assert_eq!(unparsed.data_len(), Ok(0));
    }

    let decoded_from_partial = unparsed.decode::<AnyRelayMsg>().unwrap();
    assert_eq!(decoded_from_partial.stream_id(), decoded.stream_id());
    assert_eq!(decoded_from_partial.cmd(), decoded.cmd());

    assert_eq!(format!("{:?}", expected), format!("{:?}", decoded));
    assert_eq!(
        format!("{:?}", expected),
        format!("{:?}", decoded_from_partial)
    );

    let encoded1 = decoded.encode(version, &mut bad_rng).unwrap();
    let encoded2 = expected.encode(version, &mut bad_rng).unwrap();

    assert_eq!(&encoded1[..], &encoded2[..]);
}

#[test]
fn bad_rng() {
    use rand::RngCore;
    let mut rng = BadRng;

    assert_eq!(rng.next_u32(), 0xf0f0f0f0);
    assert_eq!(rng.next_u64(), 0xf0f0f0f0f0f0f0f0);
    let mut buf = [0u8; 19];
    rng.fill_bytes(&mut buf);
    assert_eq!(
        &buf,
        &[
            0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
            0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
        ]
    );
}

#[test]
fn test_cells_v0() {
    cell(
        RelayCellFormat::V0,
        "02 0000 9999 12345678 000c 6e6565642d746f2d6b6e6f77 00000000",
        StreamId::new(0x9999),
        msg::Data::new(&b"need-to-know"[..]).unwrap().into(),
    );

    // length too big: 0x1f3 is one byte too many.
    let m = decode("02 0000 9999 12345678 01f3 6e6565642d746f2d6b6e6f77 00000000");
    assert_eq!(
        AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, m).err(),
        Some(Error::InvalidMessage(
            "Insufficient data in relay cell".into()
        ))
    );

    // check accessors.
    let m = decode("02 0000 9999 12345678 01f2 6e6565642d746f2d6b6e6f77 00000000");
    let c = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V0, m).unwrap();
    assert_eq!(c.cmd(), RelayCmd::from(2));
    assert_eq!(c.msg().cmd(), RelayCmd::from(2));
    let (s, _) = c.into_streamid_and_msg();
    assert_eq!(s, StreamId::new(0x9999));

    // check accessors on `UnparsedRelayMsg`.
    let m = decode("02 0000 9999 12345678 01f2 6e6565642d746f2d6b6e6f77 00000000");
    let c = UnparsedRelayMsg::from_singleton_body(RelayCellFormat::V0, m).unwrap();
    assert_eq!(c.cmd(), RelayCmd::from(2));
    assert_eq!(c.stream_id(), StreamId::new(0x9999));
    assert_eq!(c.data_len(), Ok(0x01f2));

    // check `data_len()` with a cell that has an invalid length.
    let m = decode("02 0000 9999 12345678 04f2 6e6565642d746f2d6b6e6f77 00000000");
    let c = UnparsedRelayMsg::from_singleton_body(RelayCellFormat::V0, m).unwrap();
    assert!(c.data_len().is_err());
}

#[test]
fn test_valid_cells_v1() {
    // Correct DATA message, with stream ID.
    cell(
        RelayCellFormat::V1,
        "00000000000000000000000000000000 02 000c 3230 6e6565642d746f2d6b6e6f77 00000000",
        StreamId::new(0x3230),
        msg::Data::new(b"need-to-know").unwrap().into(),
    );
    // Correct Extended2 message, without stream ID.
    cell(
        RelayCellFormat::V1,
        "00000000000000000000000000000000 0f 001f 001d
              686f7720646f20796f7520646f20616e64207368616b652068616e6473 00000000",
        None,
        msg::Extended2::new(b"how do you do and shake hands".to_vec()).into(),
    );
    // Correct SENDME message, without stream ID.
    //
    // (Note that a 20-byte tag won't actually be used with the V1 format,
    // but the encoding still allows it.
    cell(
        RelayCellFormat::V1,
        "00000000000000000000000000000000 05 0017 01 0014
              326e64206c656e20697320726564756e64616e74 00000000",
        None,
        msg::Sendme::new_tag(*b"2nd len is redundant").into(),
    );

    // Check accessors on `UnparsedRelayMsg`.
    let m =
        decode("00000000000000000000000000000000 02 000c 3230 6e6565642d746f2d6b6e6f77 00000000");
    let c = UnparsedRelayMsg::from_singleton_body(RelayCellFormat::V1, m).unwrap();
    assert_eq!(c.cmd(), RelayCmd::from(2));
    assert_eq!(c.stream_id(), StreamId::new(0x3230));
    assert_eq!(c.data_len(), Ok(0x000c));

    // Check `data_len()` with a cell that has an invalid length.
    let m =
        decode("00000000000000000000000000000000 02 050c 3230 6e6565642d746f2d6b6e6f77 00000000");
    let c = UnparsedRelayMsg::from_singleton_body(RelayCellFormat::V1, m).unwrap();
    assert!(c.data_len().is_err());
}

#[test]
fn test_invalid_cells_v1() {
    // zero-valued stream ID on data message (which needs a stream.)
    {
        let body = decode("00000000000000000000000000000000 02 0001 0000 ff");
        let err = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V1, body).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidMessage("Zero-valued stream ID with relay command DATA".into(),),
        );
    }

    // Message too long to fit in cell
    {
        // 489 bytes (0x1e9) is one over the limit.
        let body = decode("00000000000000000000000000000000 02 01e9 3231 00");
        let err = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V1, body).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidMessage("Insufficient data in relay cell".into())
        );

        // Note that 0x01e8 succeeds.
        let body = decode("00000000000000000000000000000000 02 01e8 3231 00");
        let m = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V1, body).unwrap();
        assert_eq!(m.cmd(), RelayCmd::DATA)
    }

    // Unrecognized command (not allowed in V1)
    {
        let body = decode("00000000000000000000000000000000 f0 0000 00000000");
        let err = AnyRelayMsgOuter::decode_singleton(RelayCellFormat::V1, body).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidMessage("Unrecognized relay command 240".into())
        );
    }
}

#[test]
fn test_streamid() {
    let zero: Option<StreamId> = StreamId::new(0);
    let two: Option<StreamId> = StreamId::new(2);

    assert!(zero.is_none());
    assert!(two.is_some());

    assert_eq!(format!("{}", two.unwrap()), "2");

    assert_eq!(StreamId::get_or_zero(zero), 0_u16);
    assert_eq!(StreamId::get_or_zero(two), 2_u16);

    assert!(RelayCmd::DATA.accepts_streamid_val(two));
    assert!(!RelayCmd::DATA.accepts_streamid_val(zero));

    assert!(RelayCmd::EXTEND2.accepts_streamid_val(zero));
    assert!(!RelayCmd::EXTEND2.accepts_streamid_val(two));
}

#[cfg(feature = "experimental-udp")]
#[test]
fn test_address() {
    // IPv4
    let ipv4 = Ipv4Addr::from_str("1.2.3.4").expect("Unable to parse IPv4");
    let addr = Address::from_str("1.2.3.4").expect("Unable to parse Address");
    assert!(matches!(addr, Address::Ipv4(_)));
    assert_eq!(addr, Address::Ipv4(ipv4));

    // Wrong IPv4 should result in a hostname.
    let addr = Address::from_str("1.2.3.372").expect("Unable to parse Address");
    assert!(addr.is_hostname());

    // Common bad IPv4 patterns
    let addr = Address::from_str("0x23.42.42.42").expect("Unable to parse Address");
    assert!(addr.is_hostname());
    let addr = Address::from_str("0x7f000001").expect("Unable to parse Address");
    assert!(addr.is_hostname());
    let addr = Address::from_str("10.0.23").expect("Unable to parse Address");
    assert!(addr.is_hostname());
    let addr = Address::from_str("2e3:4::10.0.23").expect("Unable to parse Address");
    assert!(addr.is_hostname());

    // IPv6
    let ipv6 = Ipv6Addr::from_str("4242::9").expect("Unable to parse IPv6");
    let addr = Address::from_str("4242::9").expect("Unable to parse Address");
    assert!(matches!(addr, Address::Ipv6(_)));
    assert_eq!(addr, Address::Ipv6(ipv6));

    // Wrong IPv6 should result in a hostname.
    let addr = Address::from_str("4242::9::5").expect("Unable to parse Address");
    assert!(addr.is_hostname());

    // Hostname
    let hostname = "www.torproject.org";
    let addr = Address::from_str(hostname).expect("Unable to parse Address");
    assert!(addr.is_hostname());
    assert_eq!(addr, Address::Hostname(hostname.to_string().into_bytes()));

    // Empty hostname
    let hostname = "";
    let addr = Address::from_str(hostname).expect("Unable to parse Address");
    assert!(addr.is_hostname());
    assert_eq!(addr, Address::Hostname(hostname.to_string().into_bytes()));

    // Too long hostname.
    let hostname = "a".repeat(256);
    let addr = Address::from_str(hostname.as_str());
    assert!(addr.is_err());
    assert_eq!(
        addr.err(),
        Some(Error::InvalidMessage("Hostname too long".into()))
    );

    // Some Unicode emojis (go Gen-Z!).
    let hostname = "👍️👍️👍️";
    let addr = Address::from_str(hostname).expect("Unable to parse Address");
    assert!(addr.is_hostname());
    assert_eq!(addr, Address::Hostname(hostname.to_string().into_bytes()));

    // Address with nul byte. Not allowed.
    let hostname = "aaa\0aaa";
    let addr = Address::from_str(hostname);
    assert!(addr.is_err());
    assert_eq!(
        addr.err(),
        Some(Error::InvalidMessage("Nul byte not permitted".into()))
    );
}
