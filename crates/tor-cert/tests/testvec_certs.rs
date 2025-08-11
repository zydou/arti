use tor_cert::rsa::RsaCrosscert;
use tor_cert::{Ed25519Cert, KeyType};
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};

use hex_literal::hex;

#[test]
fn test_valid_ed() {
    use humantime::parse_rfc3339;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    // These are taken from a CERTS cell in a chutney network.
    let signing_key = hex!("F82294B866A31F01FC5D0DA8572850A9B929545C3266558D7D2316E3B74172B0");
    let identity_key = hex!("DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9");
    let signing_key = Ed25519Identity::from_bytes(&signing_key[..]).unwrap();
    let identity_key = Ed25519Identity::from_bytes(&identity_key[..]).unwrap();

    let notional_time = parse_rfc3339("2020-09-25T02:13:20Z").unwrap();

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
    assert_eq!(cert.peek_cert_type(), 4.into());
    assert_eq!(cert.peek_subject_key().as_ed25519(), Some(&signing_key));
    let cert = cert
        .should_have_signing_key()
        .unwrap()
        .check_signature()
        .unwrap()
        .check_valid_at(&notional_time)
        .unwrap();

    assert_eq!(cert.subject_key().key_type(), KeyType::ED25519_KEY);
    assert_eq!(cert.subject_key().as_ed25519(), Some(&signing_key));
    assert_eq!(cert.signing_key().unwrap(), &identity_key);
    assert_eq!(cert.cert_type(), 4.into());
    assert_eq!(
        cert.expiry(),
        parse_rfc3339("2020-10-26T18:00:00Z").unwrap()
    );

    // link cert signed with signing key, type 5, no extensions.
    let c = hex!(
        "01 05 0006C98A 03
         B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8
         00
         7173E5F8068431D0D3F5EE16B4C9FFD59DF373E152A87281BAE744AA5FCF7217
         1BF4B27C4E8FC1C6A9FC5CA11058BC49647063D7903CFD9F512F89099B27BC0C"
    );
    let tls_cert_digest = hex!("B4FD606B64E4CBD466B8D76CB131069BAE6F3AA1878857C9F624E31D77A799B8");
    let cert = Ed25519Cert::decode(&c[..]).unwrap();
    assert_eq!(cert.peek_cert_type(), 5.into());
    assert_eq!(cert.peek_subject_key().as_bytes(), &tls_cert_digest[..]);
    let cert = cert
        .should_be_signed_with(&signing_key)
        .unwrap()
        .check_signature()
        .unwrap()
        .check_valid_at(&notional_time)
        .unwrap();
    assert_eq!(cert.subject_key().key_type(), KeyType::SHA256_OF_X509);
    assert_eq!(cert.subject_key().as_bytes(), &tls_cert_digest[..]);
    assert_eq!(cert.subject_key().as_ed25519(), None);
    assert_eq!(cert.signing_key().unwrap(), &signing_key);
    assert_eq!(cert.cert_type(), 5.into());
    assert_eq!(
        cert.expiry(),
        parse_rfc3339("2020-09-28T18:00:00Z").unwrap()
    );
}

#[test]
fn test_valid_rsa_cc() {
    let notional_time = humantime::parse_rfc3339("2020-09-25T02:13:20Z").unwrap();

    let pk = hex!(
        "30818902818100d38b1e6ceb946e0db0751f4cbace3dcb9688b6c25304227b4710c35afb73627e50500f5913e158b621802612d1c75827003703338375237552eb3cd3c12f6ab3604e60c1a2d26bb1fbad206ff023969a90909d6a65a5458a5312c26ebd3a3dad30302d4515cdcd264146ac18e6fc60a04bd3ec327f04294d96ba5aa25b464c3f0203010001"
    );
    let pk = tor_llcrypto::pk::rsa::PublicKey::from_der(&pk[..]).unwrap();

    let wrong_pk = hex!(
        "30818902818100d38b1e6ceb946e0db0751f4cbace3dcb9688b6c25304227b4710c35afb73627e50500f5913e158b621802612d1c75827003703338375237552eb3cd3c12f6ab3604e60c1a2d26bb1fbad206ff023969a90909d6a65a5458a5312c26ebd6a3dad30302d4515cdcd264146ac18e6fc60a04bd3ec327f04294d96ba5aa25b464c3f0203010001"
    );
    let wrong_pk = tor_llcrypto::pk::rsa::PublicKey::from_der(&wrong_pk[..]).unwrap();

    let ed_identity = hex!("DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9");
    let ed_identity = tor_llcrypto::pk::ed25519::PublicKey::from_bytes(&ed_identity).unwrap();

    let c = hex!(
        "DCB604DB2034B00FD16986D4ADB9D16B21CB4E4457A33DEC0F538903683E96E9
         0006DA3A 80
         5CF6006F9179066534DE6B45AD47A5C469063EE462762723396DC9F25452A0A5
         2DA3F5087DD239F2A311F6B0D4DFEFF4ABD089DC3D0237A0ABAB19EB2045B91C
         DCAF04BE0A72D548A27BF2E77BD876ECFE5E1BE622350DA6BF31F6E306ED8964
         88DD5B39409B23FC3EB7B2C9F7328EB18DA36D54D80575899EA6507CCBFCDF1F"
    );
    let cert = RsaCrosscert::decode(&c[..]).unwrap();

    // This returns correct for all keys.
    assert!(cert.key_is_correct(&pk).is_ok());
    assert!(cert.key_is_correct(&wrong_pk).is_ok());

    // But it isn't well-signed with the wrong pk.
    assert!(cert.is_well_signed(&wrong_pk).is_err());

    let cert = cert
        .check_signature(&pk)
        .unwrap()
        .check_valid_at(&notional_time)
        .unwrap();
    assert!(cert.subject_key_matches(&ed_identity.into()));
}
