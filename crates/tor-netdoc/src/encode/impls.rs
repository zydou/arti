//! Implementations of our useful traits, on external and parsing-mode types
// XXXX move the other impls from encode.rs here

use super::*;

/// Types related to RSA keys
mod rsa {
    use super::*;
    use tor_llcrypto::pk::rsa::PublicKey;

    impl ItemObjectEncodable for PublicKey {
        fn label(&self) -> &str {
            "RSA PUBLIC KEY"
        }
        fn write_object_onto(&self, b: &mut Vec<u8>) -> Result<(), Bug> {
            b.extend(self.to_der());
            Ok(())
        }
    }

    impl ItemValueEncodable for PublicKey {
        fn write_item_value_onto(&self, out: ItemEncoder) -> Result<(), Bug> {
            out.object(self);
            Ok(())
        }
    }
}
