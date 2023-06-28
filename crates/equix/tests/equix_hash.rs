//! Additional tests for Equi-X's usage of HashX

use equix::{EquiX, Error, HashError};

#[test]
fn bad_hashx_seeds() {
    // The hashx crate has a lot more vectors, we just need to test the API.
    assert!(matches!(
        EquiX::new(b"tvfdrjb"),
        Err(Error::Hash(HashError::ProgramConstraints)),
    ));
    assert!(matches!(
        EquiX::new(b"zuneuh"),
        Err(Error::Hash(HashError::ProgramConstraints)),
    ));
    assert!(matches!(
        EquiX::new(b"augbcgc"),
        Err(Error::Hash(HashError::ProgramConstraints)),
    ));
    assert!(matches!(
        EquiX::new(b"ldspzed"),
        Err(Error::Hash(HashError::ProgramConstraints)),
    ));
}

#[test]
fn edge_case_hashx_seeds() {
    // A few seeds that hit register allocation retries inside HashX
    assert!(EquiX::new(b"aeloscc").is_ok());
    assert!(EquiX::new(b"fysixgb").is_ok());
    assert!(EquiX::new(b"snxunsc").is_ok());
    assert!(EquiX::new(b"sdbwwmb").is_ok());
}
