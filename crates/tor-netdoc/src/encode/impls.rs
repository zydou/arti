//! Implementations of our useful traits, on external and parsing-mode types

use super::*;

impl ItemArgument for str {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        // Implements this
        // https://gitlab.torproject.org/tpo/core/torspec/-/merge_requests/106
        if self.is_empty() || self.chars().any(|c| !c.is_ascii_graphic()) {
            return Err(internal!(
                "invalid netdoc keyword line argument syntax {:?}",
                self
            ));
        }
        out.args_raw_nonempty(&self);
        Ok(())
    }
}

impl ItemArgument for &str {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        <str as ItemArgument>::write_arg_onto(self, out)
    }
}

impl ItemArgument for Iso8601TimeSp {
    // Unlike the macro'd formats, contains a space while still being one argument
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        let arg = self.to_string();
        out.args_raw_nonempty(&arg.as_str());
        Ok(())
    }
}

impl ItemValueEncodable for Void {
    fn write_item_value_onto(&self, _out: ItemEncoder) -> Result<(), Bug> {
        void::unreachable(*self)
    }
}

impl ItemObjectEncodable for Void {
    fn label(&self) -> &str {
        void::unreachable(*self)
    }
    fn write_object_onto(&self, _: &mut Vec<u8>) -> Result<(), Bug> {
        void::unreachable(*self)
    }
}

impl<T: NetdocEncodable> NetdocEncodable for Arc<T> {
    fn encode_unsigned(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
        <T as NetdocEncodable>::encode_unsigned(self, out)
    }
}

impl<T: NetdocEncodableFields> NetdocEncodableFields for Arc<T> {
    fn encode_fields(&self, out: &mut NetdocEncoder) -> Result<(), Bug> {
        <T as NetdocEncodableFields>::encode_fields(self, out)
    }
}

impl<T: ItemValueEncodable> ItemValueEncodable for Arc<T> {
    fn write_item_value_onto(&self, out: ItemEncoder) -> Result<(), Bug> {
        <T as ItemValueEncodable>::write_item_value_onto(self, out)
    }
}

impl<T: ItemArgument> ItemArgument for Arc<T> {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        <T as ItemArgument>::write_arg_onto(self, out)
    }
}

impl<T: ItemObjectEncodable> ItemObjectEncodable for Arc<T> {
    fn label(&self) -> &str {
        <T as ItemObjectEncodable>::label(self)
    }
    fn write_object_onto(&self, b: &mut Vec<u8>) -> Result<(), Bug> {
        <T as ItemObjectEncodable>::write_object_onto(self, b)
    }
}

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

/// HS POW
#[cfg(feature = "hs-pow-full")]
mod hs_pow {
    use super::*;
    use tor_hscrypto::pow::v1;

    impl ItemArgument for v1::Seed {
        fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
            let mut seed_bytes = vec![];
            tor_bytes::Writer::write(&mut seed_bytes, &self)?;
            out.add_arg(&Base64Unpadded::encode_string(&seed_bytes));
            Ok(())
        }
    }

    impl ItemArgument for v1::Effort {
        fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
            out.add_arg(&<Self as Into<u32>>::into(*self));
            Ok(())
        }
    }
}
