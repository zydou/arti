//! Convenience implementation of a SelfSigned object.

use tor_llcrypto::pk::{self, ValidatableSignature};

/// A SignatureGated object is a self-signed object that's well-signed
/// when one or more ValidatableSignature objects are correct.
pub struct SignatureGated<T> {
    /// The underlying object, which we only want to expose if the
    /// signature(s) are right.
    obj: T,
    /// A list of ValidatableSignature; these all must be valid, or the
    /// underlying object is incorrect.
    signatures: Vec<Box<dyn ValidatableSignature>>,
}

impl<T> SignatureGated<T> {
    /// Return a new SignatureGated object that will be treated as
    /// correct if every one if the given set of signatures is valid.
    pub fn new(obj: T, signatures: Vec<Box<dyn ValidatableSignature>>) -> Self {
        SignatureGated { obj, signatures }
    }
}

impl<T> super::SelfSigned<T> for SignatureGated<T> {
    type Error = signature::Error;
    fn dangerously_assume_wellsigned(self) -> T {
        self.obj
    }
    fn is_well_signed(&self) -> Result<(), Self::Error> {
        if pk::validate_all_sigs(&self.signatures[..]) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::SelfSigned;
    use tor_llcrypto::pk::ValidatableSignature;

    struct BadSig;
    struct GoodSig;
    impl ValidatableSignature for BadSig {
        fn is_valid(&self) -> bool {
            false
        }
    }
    impl ValidatableSignature for GoodSig {
        fn is_valid(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_sig_gated() {
        // no signature objects means it's valid
        let sg = SignatureGated::new(3_u32, Vec::new());
        assert_eq!(sg.check_signature().unwrap(), 3_u32);

        // any bad signature means it's bad.
        let sg = SignatureGated::new(77_u32, vec![Box::new(BadSig)]);
        assert!(sg.check_signature().is_err());
        let sg = SignatureGated::new(
            77_u32,
            vec![Box::new(GoodSig), Box::new(BadSig), Box::new(GoodSig)],
        );
        assert!(sg.check_signature().is_err());

        // All good signatures means it's good.
        let sg = SignatureGated::new(103_u32, vec![Box::new(GoodSig)]);
        assert_eq!(sg.check_signature().unwrap(), 103_u32);
        let sg = SignatureGated::new(
            104_u32,
            vec![Box::new(GoodSig), Box::new(GoodSig), Box::new(GoodSig)],
        );
        assert_eq!(sg.check_signature().unwrap(), 104_u32);
    }
}
