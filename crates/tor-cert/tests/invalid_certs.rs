use tor_bytes::Error;
use tor_cert::CertError;
//use tor_cert::rsa::RsaCrosscert;
use tor_cert::Ed25519Cert;
use tor_llcrypto::pk::ed25519;
//use tor_checkable::{ExternallySigned, SelfSigned, Timebound};

//use std::time::{Duration, SystemTime};

use hex_literal::hex;

#[test]
fn cant_parse() {
    fn decode_err(inp: &[u8]) -> Error {
        Ed25519Cert::decode(inp).err().unwrap()
    }

    assert_eq!(
        decode_err(&hex!("03")),
        Error::InvalidMessage("Unrecognized certificate version".into())
    );

    assert_eq!(
        decode_err(&hex!(
            "
       01 04 0006CC2A 01
       F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
       01 0021 04 00
       DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9FF
       FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
       094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
        )),
        Error::InvalidMessage("wrong length on Ed25519 key".into())
    );

    assert_eq!(
        decode_err(&hex!(
            "
       01 04 0006CC2A 01
       F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
       01 0020 09 01
       DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9
       FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
       094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
        )),
        Error::InvalidMessage(
            "unrecognized certificate extension, with 'affects_validation' flag set.".into()
        )
    );
}

#[test]
fn mismatched_signing_key() {
    // from testvec_certs.
    let c = hex!(
        "01 04 0006CC2A 01
         F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
         01 0020 04 00
         DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9
         FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
         094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
    );
    let cert = Ed25519Cert::decode(&c[..]).unwrap();
    let not_that_key = ed25519::Ed25519Identity::from_bytes(&hex!(
        "DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96CC"
    ))
    .unwrap();

    // We give the wrong key to check_key, so it will tell us that
    // wasn't what the cert contained.
    assert_eq!(
        cert.should_be_signed_with(&not_that_key).err().unwrap(),
        CertError::KeyMismatch
    );

    // from testvec_certs.
    let c = hex!(
        "01 05 0006C98A 03
         B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8
         00
         7173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF7217
         1BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C"
    );
    let cert = Ed25519Cert::decode(&c[..]).unwrap();

    // We give no key to check_key, which will tell us that there wasn't
    // a signing-key extension in the cert.
    assert_eq!(
        cert.should_have_signing_key().err().unwrap(),
        CertError::MissingPubKey
    );
}

#[test]
fn expired_cert() {
    use humantime::parse_rfc3339;
    use std::time::Duration;
    use tor_cert::Ed25519Cert;
    use tor_checkable::TimeValidityError;
    use tor_checkable::{SelfSigned, Timebound};

    // The certificate in this test is taken from `testvec_certs.rs`

    // This is the notion time of the certificate, exactly one day after its expiry
    let expired_time = parse_rfc3339("2020-10-27T18:00:00Z").unwrap();

    // signing cert signed with signing key, type 4, one extension.
    let c = hex!(
        "01 04 0006CC2A 01
         F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0
         01 0020 04 00
         DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9
         FF1A5203FA27F86EF7528D89A0845D2520166E340754FFEA2AAE0F612B7CE5DA
         094A0236CDAC45034B0B6842C18E7F6B51B93A3CF7E60663B8AD061C30A62602"
    );
    let cert = Ed25519Cert::decode(&c[..]).unwrap();
    let error = cert
        .should_have_signing_key()
        .unwrap()
        .check_signature()
        .unwrap()
        .check_valid_at(&expired_time)
        .unwrap_err();

    assert_eq!(
        error,
        TimeValidityError::Expired(Duration::from_secs(60 * 60 * 24))
    );
}
