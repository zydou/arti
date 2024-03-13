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
    /// correct if every one of the given set of signatures is valid.
    pub fn new(obj: T, signatures: Vec<Box<dyn ValidatableSignature>>) -> Self {
        SignatureGated { obj, signatures }
    }

    /// Consume this [`SignatureGated`], and return a new one with the same
    /// bounds, applying `f` to its protected value.
    ///
    /// The caller must ensure that `f` does not make any assumptions about the
    /// well-signedness of the protected value, or leak any of its contents in
    /// an inappropriate way.
    #[must_use]
    pub fn dangerously_map<F, U>(self, f: F) -> SignatureGated<U>
    where
        F: FnOnce(T) -> U,
    {
        SignatureGated {
            obj: f(self.obj),
            signatures: self.signatures,
        }
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
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
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

    #[test]
    fn test_map() {
        let good = SignatureGated::new("hello world...", vec![Box::new(GoodSig)]);
        let good = good.dangerously_map(|s| &s[..11]);
        let s = good.check_signature().unwrap();
        assert_eq!(s, "hello world");

        let bad = SignatureGated::new("hello world...", vec![Box::new(BadSig)]);
        let still_bad = bad.dangerously_map(|s| &s[..11]);
        assert!(still_bad.check_signature().is_err());
    }
}
