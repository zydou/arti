#![allow(clippy::uninlined_format_args)]

use hex_literal::hex;
use tor_llcrypto as ll;

#[test]
fn test_ed25519_identity() {
    use ll::pk::ed25519::{Ed25519Identity, PublicKey};
    let example_key = hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    // bad key, but length is okay.
    let bad_pk = hex!("000aaafaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000");

    assert_eq!(Ed25519Identity::from_bytes(&example_key[0..31]), None);
    let ex1 = Ed25519Identity::from_bytes(&example_key[0..32]).unwrap();
    assert_eq!(ex1, Ed25519Identity::new(example_key));

    let ex2: Ed25519Identity = bad_pk.into();

    assert_ne!(ex1, ex2);

    let pk: PublicKey = ex1.try_into().unwrap();
    let no_pk: Result<PublicKey, _> = ex2.try_into();
    assert!(no_pk.is_err());

    let ex3: Ed25519Identity = pk.into();
    assert_eq!(ex3, ex1);

    assert_eq!(
        format!("<<{}>>", ex3),
        "<<11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo>>"
    );
    assert_eq!(
        format!("{:?}", ex1),
        "Ed25519Identity { 11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo }"
    );

    assert_eq!(ex3.as_bytes(), &example_key[..]);
}

#[test]
fn test_rsa_formatting() {
    use ll::pk::rsa::RsaIdentity;

    let id = RsaIdentity::from_hex("5696ab38cb3852afa476a5c07b2d4788963d5567").unwrap();

    assert_eq!(
        format!("<<{}>>", id),
        "<<$5696ab38cb3852afa476a5c07b2d4788963d5567>>"
    );
    assert_eq!(
        format!("{:?}", id),
        "RsaIdentity { $5696ab38cb3852afa476a5c07b2d4788963d5567 }"
    );

    assert_eq!(
        id.as_hex_upper(),
        "5696ab38cb3852afa476a5c07b2d4788963d5567".to_uppercase()
    );
}

#[test]
fn test_wrong_hex_rsa_ids() {
    use ll::pk::rsa::RsaIdentity;
    assert!(RsaIdentity::from_hex("5696ab38cb3852afa476a5c07b2d4788963d5567").is_some());
    assert!(RsaIdentity::from_hex("5696AB38CB3852AFA476A5C07b2d4788963d5567").is_some());
    assert!(RsaIdentity::from_hex("5696ab38cb3852afa476a5c07b2d4788963d").is_none());
    assert!(RsaIdentity::from_hex("5696ab38cb3852afa476a5c07b2d4788963d5567A").is_none());
    assert!(RsaIdentity::from_hex("5696ab38cb3852afa476a5c07b2d4788963d5567AB").is_none());
    assert!(RsaIdentity::from_hex("").is_none());
    assert!(RsaIdentity::from_hex("listen carefully, spider of destiny  -FZ").is_none());
}

#[test]
fn test_rsa_is_zero() {
    use ll::pk::rsa::RsaIdentity;
    assert!(
        RsaIdentity::from_hex("0000000000000000000000000000000000000000")
            .unwrap()
            .is_zero()
    );
    assert!(
        !RsaIdentity::from_hex("000000000000000000000000000000000000000F")
            .unwrap()
            .is_zero()
    );
    assert!(
        !RsaIdentity::from_hex("F000000000000000000000000000000000000000")
            .unwrap()
            .is_zero()
    );
}

// TODO: Proper tests for RSA keys

#[test]
fn batch_verify() {
    use ll::pk::ed25519::*;
    use rand_core::RngCore;
    use tor_basic_utils::test_rng::testing_rng;

    let mut rng = testing_rng();
    let mut sigs = Vec::new();
    for _ in 0..3 {
        let kp = Keypair::generate(&mut rng);

        let mut bytes = [0_u8; 128];
        rng.fill_bytes(&mut bytes[..]);

        let sig = kp.sign(&bytes[..]);

        let val = ValidatableEd25519Signature::new(kp.verifying_key(), sig, &bytes[..]);

        sigs.push(val);
    }

    let sigrefs: Vec<_> = sigs.iter().collect();

    for n in 0..=3 {
        assert!(validate_batch(&sigrefs[0..n]));
    }

    // Now add a junk signature.
    let kp = Keypair::generate(&mut rng);
    let sig = kp.sign(&b"Apples"[..]);
    sigs.push(ValidatableEd25519Signature::new(
        kp.verifying_key(),
        sig,
        &b"Oranges!"[..],
    ));
    let sigrefs: Vec<_> = sigs.iter().collect();
    assert!(!validate_batch(&sigrefs[..]));
}

#[test]
fn serde_rsaid() {
    use serde_test::{Configure, Token, assert_tokens};

    let rsa_id = ll::pk::rsa::RsaIdentity::from_bytes(b"example key id here!").unwrap();

    assert_tokens(
        &rsa_id.readable(),
        &[Token::Str("6578616d706c65206b6579206964206865726521")],
    );
    assert_tokens(&rsa_id.compact(), &[Token::Bytes(b"example key id here!")]);
}

#[test]
fn serde_edid() {
    use serde_test::{Configure, Token, assert_tokens};

    let rsa_id =
        ll::pk::ed25519::Ed25519Identity::from_bytes(b"this is another key. not valid..").unwrap();

    assert_tokens(
        &rsa_id.readable(),
        &[Token::Str("dGhpcyBpcyBhbm90aGVyIGtleS4gbm90IHZhbGlkLi4")],
    );

    assert_tokens(
        &rsa_id.compact(),
        &[Token::Bytes(b"this is another key. not valid..")],
    );
}
