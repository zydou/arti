#![allow(clippy::uninlined_format_args)]

use tor_bytes::Error as BytesError;
use tor_cell::chancell::msg::HandshakeType;
/// Example channel messages to encode and decode.
///
/// Except where noted, these were taken by instrumenting Tor
/// 0.4.5.0-alpha-dev to dump all of its cells to the logs, and
/// running in a chutney network with "test-network-all".
use tor_cell::chancell::{ChanCmd, ChanMsg, msg};
use tor_units::IntegerMilliseconds;

use std::net::IpAddr;

use hex_literal::hex;

const CELL_SIZE: usize = 509;

fn unhex(s: &str, pad_to_len: bool) -> Vec<u8> {
    let mut s = s.to_string();
    s.retain(|c| !c.is_whitespace());
    let mut body = hex::decode(s).unwrap();
    if pad_to_len {
        assert!(body.len() <= CELL_SIZE);
        body.resize(CELL_SIZE, 0);
    }
    body
}

fn decode_err(cmd: ChanCmd, s: &str, pad_to_len: bool) -> BytesError {
    let body = unhex(s, pad_to_len);
    let mut r = tor_bytes::Reader::from_slice(&body[..]);
    msg::AnyChanMsg::decode_from_reader(cmd, &mut r).unwrap_err()
}

fn test_decode(cmd: ChanCmd, s: &str, pad_to_len: bool) -> (Vec<u8>, msg::AnyChanMsg) {
    let body = unhex(s, pad_to_len);
    let mut r = tor_bytes::Reader::from_slice(&body[..]);
    let msg = msg::AnyChanMsg::decode_from_reader(cmd, &mut r).unwrap();

    (body, msg)
}

/// check whether a cell body encoded in a hex string matches a given message.
fn test_body(cmd: ChanCmd, s: &str, m: &msg::AnyChanMsg, pad_to_len: bool) {
    assert_eq!(cmd, m.cmd());

    let (body, decoded) = test_decode(cmd, s, pad_to_len);

    // This is a bit kludgey: we don't implement PartialEq for
    // messages, but we do implement Debug.  That actually seems a
    // saner arrangement to me as of this writing.
    assert_eq!(format!("{:?}", decoded), format!("{:?}", m));

    let mut encoded1 = Vec::new();
    let mut encoded2 = Vec::new();
    decoded.encode_onto(&mut encoded1).expect("encode error");
    m.clone().encode_onto(&mut encoded2).expect("encode error");
    if pad_to_len {
        assert!(encoded1.len() <= CELL_SIZE);
        assert!(encoded2.len() <= CELL_SIZE);
        encoded1.resize(CELL_SIZE, 0);
        encoded2.resize(CELL_SIZE, 0);
    }
    assert_eq!(encoded1, encoded2);
    assert_eq!(body, encoded2);
}

/// version for variable-length cells
fn vbody(cmd: ChanCmd, s: &str, m: &msg::AnyChanMsg) {
    test_body(cmd, s, m, false)
}

/// version for fixed-length cells
fn fbody(cmd: ChanCmd, s: &str, m: &msg::AnyChanMsg) {
    test_body(cmd, s, m, true)
}

#[test]
fn test_auth_challenge() {
    let cmd = ChanCmd::AUTH_CHALLENGE;
    assert_eq!(Into::<u8>::into(cmd), 130_u8);

    let challenge = hex!("00DA5C085DEE4F3656710DA3B73652E48ACD5BAE608335FCA3FB6C4DEE104A51");
    vbody(
        cmd,
        "00DA5C085DEE4F3656710DA3B73652E48ACD5BAE608335FCA3FB6C4DEE104A51
         0002 0001 0003",
        &msg::AuthChallenge::new(challenge, vec![1_u16, 3_u16]).into(),
    );
}

#[test]
fn test_authenticate() {
    let cmd = ChanCmd::AUTHENTICATE;
    assert_eq!(Into::<u8>::into(cmd), 131_u8);
    let authentication = hex!(
        "4155544830303033ED6B2ACBAC868D87D1500505BF59196FD38DEF15E1078C46BF97C7EBCC26C2A26AAF7E6B8FF0C27AB8F0047426017D03A413D8C1D00077ED441112C3E88EEE535BA78B2FD74C3910C5FECBD700677DCA931F4B90EA5CD24D4E64F7E9EC9E0F38E4E1E55E42BC72F59E9224E328EB1BBE3D079013B2A04CDBCEB43B7135D365E81B01B6845D789F66F0F62AAF52D906D2252E5F105215A627123C05AF782D7B0D64C41C30AFB6660B3DB1028868104E2560CB527568241992B80855101D3BF6EFA987F7A56C132A0CF38B0097AA215CC58FF089AFCC15C0ABB3947E68137CD8554E336C435E4633F88909919E5448F80CDDBD5987D85407A95A2BBC898C7004318265719D99C7B549C276CDEE38CE9202395CB7E1EBD9B3D47C1F4BC254AA12798BA1480400A3CC8067518A9BBDD453E601579429CF2E72D6C175DA0A412D99ECA1079015651E95E8F40AD8BEC3CB496E83C0C66D10F4C606"
    );

    vbody(
        cmd,
        "0003 0160 4155544830303033ED6B2ACBAC868D87D1500505BF59196FD38DEF15E1078C46BF97C7EBCC26C2A26AAF7E6B8FF0C27AB8F0047426017D03A413D8C1D00077ED441112C3E88EEE535BA78B2FD74C3910C5FECBD700677DCA931F4B90EA5CD24D4E64F7E9EC9E0F38E4E1E55E42BC72F59E9224E328EB1BBE3D079013B2A04CDBCEB43B7135D365E81B01B6845D789F66F0F62AAF52D906D2252E5F105215A627123C05AF782D7B0D64C41C30AFB6660B3DB1028868104E2560CB527568241992B80855101D3BF6EFA987F7A56C132A0CF38B0097AA215CC58FF089AFCC15C0ABB3947E68137CD8554E336C435E4633F88909919E5448F80CDDBD5987D85407A95A2BBC898C7004318265719D99C7B549C276CDEE38CE9202395CB7E1EBD9B3D47C1F4BC254AA12798BA1480400A3CC8067518A9BBDD453E601579429CF2E72D6C175DA0A412D99ECA1079015651E95E8F40AD8BEC3CB496E83C0C66D10F4C606",
        &msg::Authenticate::new(3, &authentication[..]).into(),
    );

    // TODO: when we generate or parse these, we should parse the actual
    // structure of the authentication string.
}

#[test]
fn test_certs() {
    // can't do this trivially; have to go by hand.
    let cmd = ChanCmd::CERTS;
    assert_eq!(Into::<u8>::into(cmd), 129_u8);

    let body =
        "05
         01 023E 3082023A308201A3A003020102020872AB0FE86C771604300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303632373030303030305A170D3231303231363233353935395A301C311A301806035504030C117777772E617775676863646E732E6E657430820122300D06092A864886F70D01010105000382010F003082010A0282010100FE255E99E10BE986DDA5DFB4AD7C39E8EFE4E5D79E105AB976942B6829386EB1D7B7AFB5ED4FCBEC8C1A34C34FD2ED182F8B42A0363453B55EE371F21347235277E2357F28AA10DD82D4248F7D1894AB5D2979654F71C350F73AD9F918D71F34F1505F77EC16391C8340F392F3684BA4BB6A7B022C3954C1158F152F9E3B4E328FAB2E4E881903CA0E32204B0FDA8AB62B6E215A7BDEC3F2AE41DC58EEC1252F643A1812A5D71802F48D6133DF79955E01F0287BB4AB8CF95BEBCD2EC66EF5B38C7B5EC08DED3D6E2A1D57289D773D5CB932803B6D97784D1DA36AE71C073ADBB7393714001CD7A082512772A7076DC01166417AF7C50AEF7F15FD0806EB07FF0203010001300D06092A864886F70D01010B050003818100CDA4E06BB6BB238B91188A077EEB0A4722518090FD116AF6CDEEB0E85CF6D8E242CF861F973A252EB5116709373B5AC817E6F848E2CBD76AEF684350D3416AEE5F33D56B96982509CDAF11CCA7260E5ADF6DDD0D017AE9A575C999ADAE50B3FB7027E810D47C8C5C14618C0AA10D307E304FBE50E868ADECB2C9536E2DB51BE0
         02 01BD 308201B930820122A0030201020208607C28BE6C390943300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303831303030303030305A170D3231303831303030303030305A301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100D38B1E6CEB946E0DB0751F4CBACE3DCB9688B6C25304227B4710C35AFB73627E50500F5913E158B621802612D1C75827003703338375237552EB3CD3C12F6AB3604E60C1A2D26BB1FBAD206FF023969A90909D6A65A5458A5312C26EBD3A3DAD30302D4515CDCD264146AC18E6FC60A04BD3EC327F04294D96BA5AA25B464C3F0203010001300D06092A864886F70D01010B0500038181003BCE561EA7F95CC00B78AAB5D69573FF301C282A751D4A651921D042F1BECDBA24D918A6D8A5E138DC07BBA0B335478AE37ABD2C93A93932442AE9084329E846170FE0FC4A50AAFC804F311CC3CA4F41D845A7BA5901CBBC3E021E9794AAC70CE1F37B0A951592DB1B64F2B4AFB81AE52DBD9B6FEDE96A5FB8125EB6251EE50A
         04 008C 01040006CC2A01F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B00100200400DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602
         05 0068 01050006C98A03B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8007173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF72171BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C
         07 00A5 DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E90006DA3A805CF6006F9179066534DE6B45AD47A5C469063EE462762723396DC9F25452A0A52DA3F5087DD239F2A311F6B0D4DFEFF4ABD089DC3D0237A0ABAB19EB2045B91CDCAF04BE0A72D548A27BF2E77BD876ECFE5E1BE622350DA6BF31F6E306ED896488DD5B39409B23FC3EB7B2C9F7328EB18DA36D54D80575899EA6507CCBFCDF1F";

    // yeah, that's kinda big!
    let cert1body = hex::decode(
        "3082023A308201A3A003020102020872AB0FE86C771604300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303632373030303030305A170D3231303231363233353935395A301C311A301806035504030C117777772E617775676863646E732E6E657430820122300D06092A864886F70D01010105000382010F003082010A0282010100FE255E99E10BE986DDA5DFB4AD7C39E8EFE4E5D79E105AB976942B6829386EB1D7B7AFB5ED4FCBEC8C1A34C34FD2ED182F8B42A0363453B55EE371F21347235277E2357F28AA10DD82D4248F7D1894AB5D2979654F71C350F73AD9F918D71F34F1505F77EC16391C8340F392F3684BA4BB6A7B022C3954C1158F152F9E3B4E328FAB2E4E881903CA0E32204B0FDA8AB62B6E215A7BDEC3F2AE41DC58EEC1252F643A1812A5D71802F48D6133DF79955E01F0287BB4AB8CF95BEBCD2EC66EF5B38C7B5EC08DED3D6E2A1D57289D773D5CB932803B6D97784D1DA36AE71C073ADBB7393714001CD7A082512772A7076DC01166417AF7C50AEF7F15FD0806EB07FF0203010001300D06092A864886F70D01010B050003818100CDA4E06BB6BB238B91188A077EEB0A4722518090FD116AF6CDEEB0E85CF6D8E242CF861F973A252EB5116709373B5AC817E6F848E2CBD76AEF684350D3416AEE5F33D56B96982509CDAF11CCA7260E5ADF6DDD0D017AE9A575C999ADAE50B3FB7027E810D47C8C5C14618C0AA10D307E304FBE50E868ADECB2C9536E2DB51BE0").unwrap();
    let cert2body = hex::decode(
        "308201B930820122A0030201020208607C28BE6C390943300D06092A864886F70D01010B0500301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D301E170D3230303831303030303030305A170D3231303831303030303030305A301F311D301B06035504030C147777772E74636A76356B766A646472322E636F6D30819F300D06092A864886F70D010101050003818D0030818902818100D38B1E6CEB946E0DB0751F4CBACE3DCB9688B6C25304227B4710C35AFB73627E50500F5913E158B621802612D1C75827003703338375237552EB3CD3C12F6AB3604E60C1A2D26BB1FBAD206FF023969A90909D6A65A5458A5312C26EBD3A3DAD30302D4515CDCD264146AC18E6FC60A04BD3EC327F04294D96BA5AA25B464C3F0203010001300D06092A864886F70D01010B0500038181003BCE561EA7F95CC00B78AAB5D69573FF301C282A751D4A651921D042F1BECDBA24D918A6D8A5E138DC07BBA0B335478AE37ABD2C93A93932442AE9084329E846170FE0FC4A50AAFC804F311CC3CA4F41D845A7BA5901CBBC3E021E9794AAC70CE1F37B0A951592DB1B64F2B4AFB81AE52DBD9B6FEDE96A5FB8125EB6251EE50A"
    ).unwrap();
    let cert3body = hex::decode("01040006CC2A01F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B00100200400DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
    ).unwrap();
    let cert4body = hex::decode("01050006C98A03B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8007173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF72171BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C").unwrap();
    let cert5body = hex::decode("DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E90006DA3A805CF6006F9179066534DE6B45AD47A5C469063EE462762723396DC9F25452A0A52DA3F5087DD239F2A311F6B0D4DFEFF4ABD089DC3D0237A0ABAB19EB2045B91CDCAF04BE0A72D548A27BF2E77BD876ECFE5E1BE622350DA6BF31F6E306ED896488DD5B39409B23FC3EB7B2C9F7328EB18DA36D54D80575899EA6507CCBFCDF1F").unwrap();

    let mut certs = msg::Certs::new_empty();
    certs.push_cert_body(1.into(), cert1body);
    certs.push_cert_body(2.into(), cert2body);
    certs.push_cert_body(4.into(), &cert3body[..]);
    certs.push_cert_body(5.into(), cert4body);
    certs.push_cert_body(7.into(), cert5body.clone());

    vbody(cmd, body, &certs.clone().into());

    // Test some accessors.
    let body3 = certs.cert_body(4.into());
    assert_eq!(body3, Some(&cert3body[..]));
    let body_not_present = certs.cert_body(66.into());
    assert_eq!(body_not_present, None);

    let cert3 = certs.parse_ed_cert(4.into());
    assert!(cert3.is_ok());

    // Try a mismatched cell.
    let mut badcerts = msg::Certs::new_empty();
    badcerts.push_cert_body(5.into(), cert5body); // not the correct cert type
    assert!(badcerts.parse_ed_cert(5.into()).is_err());
}

#[test]
fn test_create() {
    let cmd = ChanCmd::CREATE;
    assert_eq!(Into::<u8>::into(cmd), 1_u8);
    let body = "07780DBE97D62D392E0DF2286C78386C49464154A8EDE46EECA1753AA49391200F33F22DF0128CCEC3339434D436551930C95338693EEFAD3964D53184C58AF6C0D838EE3893FAE650DAC89BB12EBB6A882E572C9EA079ACD3E51063296E52ABC875D7A31F8965A6BA9CE54F16AD5C746FEE7D9EF2D41CF4399D818567599D2A0FA8E27F31838F80D80E2D03C040FB954B2AD8872530FFB2AA50531B2BB40C7CB4BF1E8946A50C7622A2916C679AD11577EB4EC414BF8F287085";
    let handshake = hex::decode(body).unwrap();
    fbody(cmd, body, &msg::Create::new(handshake).into());
}

#[test]
fn test_create2() {
    let cmd = ChanCmd::CREATE2;
    assert_eq!(Into::<u8>::into(cmd), 10_u8);
    let body = "0002 0054 09164430E84D3BC56EC7E1D22734742345E2DECE0DE535B66B8E8A0EBBDAE3263C53E02EC2215685CD3A977DC7946FF47F84CD7025F75D252D1B35DEA28F32FA912513889A207E5049992DBC9BC541194C13624A";
    let handshake = hex::decode("09164430E84D3BC56EC7E1D22734742345E2DECE0DE535B66B8E8A0EBBDAE3263C53E02EC2215685CD3A977DC7946FF47F84CD7025F75D252D1B35DEA28F32FA912513889A207E5049992DBC9BC541194C13624A").unwrap();

    fbody(
        cmd,
        body,
        &msg::Create2::new(HandshakeType::NTOR, handshake.clone()).into(),
    );
    let create2 = msg::Create2::new(HandshakeType::NTOR, handshake.clone());
    assert_eq!(create2.handshake_type(), HandshakeType::NTOR);
    assert_eq!(create2.body(), &handshake[..]);
}

#[test]
fn test_create_fast() {
    let cmd = ChanCmd::CREATE_FAST;
    assert_eq!(Into::<u8>::into(cmd), 5_u8);
    let body = "0DC2A5EB921EF4B71F41184A99F4FAD99620A648";
    let handshake = hex::decode(body).unwrap();

    fbody(cmd, body, &msg::CreateFast::new(handshake.clone()).into());
    let create_fast = msg::CreateFast::new(handshake.clone());
    assert_eq!(create_fast.handshake(), &handshake[..]);
}

#[test]
fn test_created() {
    let cmd = ChanCmd::CREATED;
    assert_eq!(Into::<u8>::into(cmd), 2_u8);
    let body = "0AC85AFA82E14BD661A4BEB3F6420508F21336455326442D9D34B41F4F4E1283751B681C83AB6C06089C6CB5AC857509B4CF185DD044C6B66A53B6FA7E48F8728DC7CC114E38E9258058A0D7C3603335E6812AB3687076DC82F2D4E9872D6787587CBAACF2BC962DFB3A0FCD313D86EC0572DEC12C5D113C78A7B34EF3C209260E48AB5C6E1DAB0D68617B76CC408A93DC0E26C0";
    let handshake = hex::decode(body).unwrap();

    fbody(cmd, body, &msg::Created::new(handshake).into());
}

#[test]
fn test_created2() {
    let cmd = ChanCmd::CREATED2;
    assert_eq!(Into::<u8>::into(cmd), 11_u8);

    let body = "0040 0108907A701030ADB6CA9C6AF097DC4855614655659B6A7BF21C1097DCE7C66EE0E4EF287DE7CED40BEECA8B90140C05DB6138AEB551CE0C037068C315E307A0";
    let handshake = hex::decode("0108907A701030ADB6CA9C6AF097DC4855614655659B6A7BF21C1097DCE7C66EE0E4EF287DE7CED40BEECA8B90140C05DB6138AEB551CE0C037068C315E307A0").unwrap();

    fbody(cmd, body, &msg::Created2::new(handshake.clone()).into());
    let created2 = msg::Created2::new(handshake.clone());
    assert_eq!(created2.into_body(), handshake);
}

#[test]
fn test_created_fast() {
    let cmd = ChanCmd::CREATED_FAST;
    assert_eq!(Into::<u8>::into(cmd), 6_u8);
    let body = "03B74250B01D09FDA72B70D63AE7994926F13055BED23485F6B3C8C3CEAFE1DF48A9FF8BAC4993FC";
    let handshake = hex::decode(body).unwrap();

    fbody(cmd, body, &msg::CreatedFast::new(handshake.clone()).into());
    let created_fast = msg::CreatedFast::new(handshake.clone());
    assert_eq!(created_fast.into_handshake(), handshake);
}

#[test]
fn test_destroy() {
    let cmd = ChanCmd::DESTROY;
    assert_eq!(Into::<u8>::into(cmd), 4_u8);

    fbody(cmd, "04", &msg::Destroy::new(4.into()).into());
    fbody(cmd, "0000", &msg::Destroy::new(0.into()).into());
}

#[test]
fn test_netinfo() {
    let cmd = ChanCmd::NETINFO;
    assert_eq!(Into::<u8>::into(cmd), 8_u8);

    // example client netinfo.
    let localhost = "127.0.0.1".parse::<IpAddr>().unwrap();
    fbody(
        cmd,
        "00000000 04 04 7F000001 00",
        &msg::Netinfo::from_client(Some(localhost)).into(),
    );

    // example relay netinfo
    fbody(
        cmd,
        "5F6F80E1 04 04 7F000001 01 04 04 7F000001",
        &msg::Netinfo::from_relay(0x5f6f80e1, Some(localhost), &[localhost][..]).into(),
    );

    // example ipv6 relay netinfo
    let localhost_v6 = "::1".parse::<IpAddr>().unwrap();
    fbody(
        cmd,
        "5F6F859C 06 10 00000000000000000000000000000001
         02
         04 04 7F000001
         06 10 00000000000000000000000000000001",
        &msg::Netinfo::from_relay(
            0x5f6f859c,
            Some(localhost_v6),
            &[localhost, localhost_v6][..],
        )
        .into(),
    );

    // Bogus addresses get ignored. (hand-generated from above)
    let (_, netinfo) = test_decode(
        cmd,
        "5F6F859C 06 09 000000000000000000
         03
         04 06 7F0000010000
         BB 02 FFFF
         06 10 00000000000000000000000000000001",
        false,
    );
    let expect: msg::AnyChanMsg =
        msg::Netinfo::from_relay(0x5f6f859c, None, &[localhost_v6][..]).into();
    assert_eq!(format!("{:?}", netinfo), format!("{:?}", expect));

    // Zero-valued their_address are None (hand-generated from above)
    fbody(
        cmd,
        "00000000 04 04 00000000 00",
        &msg::Netinfo::from_client(None).into(),
    );
}

#[test]
fn test_padding() {
    let cmd = ChanCmd::PADDING;
    assert_eq!(Into::<u8>::into(cmd), 0_u8);

    fbody(cmd, "", &msg::Padding::default().into());
}

#[test]
fn test_versions() {
    let cmd = ChanCmd::VERSIONS;
    assert_eq!(Into::<u8>::into(cmd), 7_u8);

    vbody(
        cmd,
        "000300040005",
        &msg::Versions::new(vec![3, 4, 5]).unwrap().into(),
    );
}

#[test]
fn test_unspecified() {
    let cmd = 101.into(); // not a specified fixed-length cell

    // generated by hand, since there is no alternative.

    let mut text: Vec<u8> = b"A mage's name is better hidden than a herring in the sea"[..].into();
    text.resize(CELL_SIZE, 0);
    fbody(
        cmd,
        "41206d6167652773206e616d65206973206265747465722068696464656e207468616e20612068657272696e6720696e2074686520736561",
        &msg::Unrecognized::new(cmd, text).into(),
    );

    let cmd = 244.into(); // not a specified variable-length cell
    vbody(
        cmd,
        "6265747465722067756172646564207468616e206120647261676f6e27732064656e",
        &msg::Unrecognized::new(cmd, &b"better guarded than a dragon's den"[..]).into(),
    );

    // quote from Ursula K. Le Guin, _A Wizard Of EarthSea_
}

#[test]
fn test_relay() {
    // This is hand-generated.
    let cmd = ChanCmd::RELAY;
    assert_eq!(Into::<u8>::into(cmd), 3_u8);

    let mut body: Vec<u8> = b"not validated at this stage"[..].into();
    body.resize(CELL_SIZE, 0);
    fbody(
        cmd,
        "6e6f742076616c6964617465642061742074686973207374616765",
        &msg::Relay::new(&body).into(),
    );

    let cmd = ChanCmd::RELAY_EARLY;
    assert_eq!(Into::<u8>::into(cmd), 9_u8);
    fbody(
        cmd,
        "6e6f742076616c6964617465642061742074686973207374616765",
        &msg::Relay::new(&body).into_early(),
    );

    // Try converting to/from raw bodies.
    let body = [3_u8; 509];
    let cell = msg::Relay::from_raw(body);
    let body2 = cell.into_relay_body();
    assert_eq!(&body2[..], &body[..]);
}

#[test]
fn test_vpadding() {
    // Generated by hand
    let cmd = ChanCmd::VPADDING;
    assert_eq!(Into::<u8>::into(cmd), 128_u8);

    vbody(cmd, "", &msg::Vpadding::new(0).into());
    vbody(cmd, "00000000000000000000", &msg::Vpadding::new(10).into());
}

#[test]
fn test_padding_negotiate() {
    // Generated by hand since we don't have it from the Chutney run.
    let cmd = ChanCmd::PADDING_NEGOTIATE;
    assert_eq!(Into::<u8>::into(cmd), 12_u8);

    fbody(
        cmd,
        "00 02 0100 0200",
        &msg::PaddingNegotiate::start(IntegerMilliseconds::new(256), IntegerMilliseconds::new(512))
            .into(),
    );

    fbody(
        cmd,
        "00 01 0000 0000",
        &msg::PaddingNegotiate::stop().into(),
    );

    assert_eq!(
        decode_err(cmd, "90 0303", true),
        BytesError::InvalidMessage("Unrecognized padding negotiation version".into())
    );
}
