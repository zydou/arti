//! Edge case tests for the program generator
//!
//! These seeds and outputs were found using the original implementation
//! of HashX, in a search for seeds that trigger unusual conditions within
//! the generator.
//!
//! I was looking for source and destination register allocation fails, overall
//! fails, and cases where we reach the end of the schedule array.
//!
//! After iterating seeds for a while I've still only found two types of
//! edge cases, both related to destination register allocations failing.
//! With one failure it seems to always ultimately succeed. Every constraint
//! failure I've seen has been caused by a dest register allocation failure
//! on the retry pass.
//!
//! I'm not sure at this point whether source register allocation errors are not
//! possible or if they're just exceedingly rare.
//!
//! I've tried longer blobs of these test vectors with no problem but there are
//! clearly diminishing returns, so keeping it small for now.

use hashx::{Error, HashX};
use hex_literal::hex;

#[test]
fn overall_failure() {
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"cflngib"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"qzdfsbb"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"klwysfa"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"ijuorca"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"naivvwc"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"nnbved"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"mhelht"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"pjkzbyc"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"hnpzsn"),
        Err(Error::ProgramConstraints)
    ));
    assert!(matches!(
        /* dst-retry dst-stall fail */ HashX::new(b"qfjsfv"),
        Err(Error::ProgramConstraints)
    ));
}

#[test]
fn dst_retry_and_succeed() {
    assert_eq!(
        /* dst-retry */
        HashX::new(b"llompmb")
            .unwrap()
            .hash_to_bytes(0xce3917d056269f6e),
        hex!("cafda60c4c351be4ccdc8a9375fd9aea830200dc472da04651150868591bd32f")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"nqgxgl")
            .unwrap()
            .hash_to_bytes(0x502d1f959c141a1b),
        hex!("73c0aa53b1c6a667e85c5c4d4263e0029b6c117ff29ca3d6f7c89db87500feea")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"yatmebd")
            .unwrap()
            .hash_to_bytes(0xc431100bf283cd89),
        hex!("3792c60a2616b04a8eebfb76ce11f7cb7786fd3d767a47f10a4f63db50a36e11")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"jvanmtb")
            .unwrap()
            .hash_to_bytes(0x399b83de5eb85d81),
        hex!("24d1ce6019c3ceb4be0af9ea57ee636472902cce04c10cee97b07eb141904e2d")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"amftbk")
            .unwrap()
            .hash_to_bytes(0x81d20d7110e3c280),
        hex!("04458aa05b54322ca87cd773d0177f223df0c930b4db6e0371ecb3c2cc653770")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"ebrazua")
            .unwrap()
            .hash_to_bytes(0xebc19ba9cafb0863),
        hex!("41cb0b4b24551d26b0a98a57b4da5d22d03883a0626ed674995a6d8688b38bf9")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"zsakied")
            .unwrap()
            .hash_to_bytes(0xd190bb98e2d7ebdf),
        hex!("1c4b22f9710ef2a8fc54296e64b62580a1aaadc66ab4031549e9e30c57c2cc18")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"wlmaqhb")
            .unwrap()
            .hash_to_bytes(0xf9b239ca5919578c),
        hex!("1cf2a67e5836a0486580bde5a7e51551cf269eb05d53c8872375e11137f41937")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"ezfvvx")
            .unwrap()
            .hash_to_bytes(0x06b4a7079456083b),
        hex!("c0d2d29ce6d67d0ae6bf178b4d61359dd0e4631d7f2aab936b04c480c7259603")
    );
    assert_eq!(
        /* dst-retry */
        HashX::new(b"jxzoddc")
            .unwrap()
            .hash_to_bytes(0x1e37c61f64bb59c6),
        hex!("c3a9c90b17a74be31ad538d5d569dca7e77332ff92e4f68793ca0049b7a1a0cd")
    );
}
