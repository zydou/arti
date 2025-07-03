//! Test vectors from the original HashX unit tests

use hashx::{self, HashX, HashXBuilder};
use hex_literal::hex;

const SEED1: &[u8] = b"This is a test\0";
const HASH_SEED1_0: [u8; 32] =
    hex!("2b2f54567dcbea98fdb5d5e5ce9a65983c4a4e35ab1464b1efb61e83b7074bb2");
const HASH_SEED1_123456: [u8; 32] =
    hex!("aebdd50aa67c93afb82a4c534603b65e46decd584c55161c526ebc099415ccf1");

const SEED2: &[u8] = b"Lorem ipsum dolor sit amet\0";
const HASH_SEED2_123456: [u8; 32] =
    hex!("ab3d155bf4bbb0aa3a71b7801089826186e44300e6932e6ffd287cf302bbb0ba");
const HASH_SEED2_987654321123456789: [u8; 32] =
    hex!("8dfef0497c323274a60d1d93292b68d9a0496379ba407b4341cf868a14d30113");

#[test]
fn seed1() {
    let func = HashX::new(SEED1).unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_u64(0), 0x98eacb7d56542f2b);
    assert_eq!(func.hash_to_u64(123456), 0xaf937ca60ad5bdae);
    assert_eq!(func.hash_to_bytes(0), HASH_SEED1_0);
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED1_123456);
}

#[test]
fn seed2() {
    let func = HashX::new(SEED2).unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_u64(123456), 0xaab0bbf45b153dab);
    assert_eq!(func.hash_to_u64(987654321123456789), 0x7432327c49f0fe8d);
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED2_123456);
    assert_eq!(
        func.hash_to_bytes(987654321123456789),
        HASH_SEED2_987654321123456789
    );
}

#[test]
fn seed1_interp() {
    let func = HashXBuilder::new()
        .runtime(hashx::RuntimeOption::InterpretOnly)
        .build(SEED1)
        .unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_bytes(0), HASH_SEED1_0);
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED1_123456);
}

#[test]
fn seed2_interp() {
    let func = HashXBuilder::new()
        .runtime(hashx::RuntimeOption::InterpretOnly)
        .build(SEED2)
        .unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED2_123456);
    assert_eq!(
        func.hash_to_bytes(987654321123456789),
        HASH_SEED2_987654321123456789
    );
}

#[cfg(not(all(
    feature = "compiler",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn compiler_not_available() {
    let result = HashXBuilder::new()
        .runtime(hashx::RuntimeOption::CompileOnly)
        .build(SEED1);
    assert!(result.is_err());
    match result {
        Err(hashx::Error::Compiler(hashx::CompilerError::NotAvailable)) => (),
        result => panic!(
            "expected compiler not to be available (instead: {:?})",
            result
        ),
    }
}

#[cfg(all(
    feature = "compiler",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn seed1_compile() {
    let func = HashXBuilder::new()
        .runtime(hashx::RuntimeOption::CompileOnly)
        .build(SEED1)
        .unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_bytes(0), HASH_SEED1_0);
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED1_123456);
}

#[cfg(all(
    feature = "compiler",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn seed2_compile() {
    let func = HashXBuilder::new()
        .runtime(hashx::RuntimeOption::CompileOnly)
        .build(SEED2)
        .unwrap();
    println!("{func:?}\n");
    assert_eq!(func.hash_to_bytes(123456), HASH_SEED2_123456);
    assert_eq!(
        func.hash_to_bytes(987654321123456789),
        HASH_SEED2_987654321123456789
    );
}

#[test]
fn bad_seeds() {
    // Sandwiched between two control seeds, this case has two seeds which must
    // result in a program constraint error. Both seeds result in register
    // allocation failures that persist through one retry pass, causing a timing
    // stall, which ends up causing the generator to reach the end of its
    // schedule before enough instructions or multiplies have been emitted.
    //
    // The root cause of the register allocation failure in both these test
    // vectors is a code sequence in which every available register is occupied
    // with a calculation that has one source operand in common. This should
    // cause our RegisterWriter constraints to disallow reuse, and a retry won't
    // relax these constraints.

    assert!(HashX::new(b"\xf8\x05\x00\x00").is_ok());
    assert!(matches!(
        HashX::new(b"\xf9\x05\x00\x00"),
        Err(hashx::Error::ProgramConstraints)
    ));
    assert!(matches!(
        HashX::new(b"\x5d\x93\x02\x00"),
        Err(hashx::Error::ProgramConstraints)
    ));
    assert!(HashX::new(b"\x5e\x93\x02\x00").is_ok());
}
