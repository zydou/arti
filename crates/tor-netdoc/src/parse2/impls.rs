//! Implementations of our useful traits, on external and parsing-mode types

use super::*;

/// Types related to RSA keys
mod rsa {
    use super::*;
    use tor_llcrypto::pk::rsa::PublicKey;

    /// An item which contains an RSA public key as an Object, and no extra arguments
    #[derive(Deftly)]
    #[derive_deftly(ItemValueParseable)]
    #[deftly(netdoc(no_extra_args))]
    struct ParsePublicKey {
        /// The public key data
        #[deftly(netdoc(object))]
        key: PublicKey,
    }

    impl ItemObjectParseable for PublicKey {
        fn check_label(label: &str) -> Result<(), EP> {
            match label {
                "RSA PUBLIC KEY" => Ok(()),
                _ => Err(EP::ObjectIncorrectLabel),
            }
        }
        fn from_bytes(input: &[u8]) -> Result<Self, EP> {
            PublicKey::from_der(input).ok_or(EP::ObjectInvalidData)
        }
    }

    impl ItemValueParseable for PublicKey {
        fn from_unparsed(item: UnparsedItem) -> Result<Self, EP> {
            Ok(ParsePublicKey::from_unparsed(item)?.key)
        }
    }
}

/// Types related to times
pub(crate) mod times {
    use super::*;

    /// Date and time in deprecated ISO8601-with-space separate arguments syntax
    ///
    /// Eg `dir-key-published` in a dir auth key cert.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::Deref)]
    #[allow(clippy::exhaustive_structs)]
    pub struct NdaSystemTimeDeprecatedSyntax(#[deref] pub SystemTime);

    impl ItemArgumentParseable for NdaSystemTimeDeprecatedSyntax {
        fn from_args<'s>(
            args: &mut ArgumentStream<'s>,
            field: &'static str,
        ) -> Result<Self, ErrorProblem> {
            let t;
            (t, *args) = (|| {
                let args = args.clone().into_remaining();
                let spc2 = args
                    .match_indices(WS)
                    .nth(1)
                    .map(|(spc2, _)| spc2)
                    .unwrap_or_else(|| args.len());
                let (t, rest) = args.split_at(spc2);
                let t: crate::types::misc::Iso8601TimeSp =
                    t.parse().map_err(|_| EP::InvalidArgument { field })?;
                let t = NdaSystemTimeDeprecatedSyntax(t.into());
                Ok::<_, EP>((t, ArgumentStream::new(rest)))
            })()?;
            Ok(t)
        }
    }
}

/// Implementations on `Void`
pub(crate) mod void_impls {
    use super::*;

    impl ItemValueParseable for Void {
        fn from_unparsed(_item: UnparsedItem<'_>) -> Result<Self, ErrorProblem> {
            Err(EP::ItemForbidden)
        }
    }
}

/// Conversion module for `Vec<u8>` as Object with [`ItemValueParseable`]
pub mod raw_data_object {
    use super::*;

    /// "Parse" the data
    pub fn try_from(data: Vec<u8>) -> Result<Vec<u8>, Void> {
        Ok(data)
    }
}
