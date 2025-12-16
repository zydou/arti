//! Implementations of our useful traits, on external and parsing-mode types

use super::*;

/// Types related to RSA keys
mod rsa {
    use super::*;
    use crate::types;
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
            (|| {
                let key = PublicKey::from_der(input).ok_or(())?;

                if !key.exponent_is(types::misc::RSA_FIXED_EXPONENT) {
                    return Err(());
                }
                if key.bits() < types::misc::RSA_MIN_BITS {
                    return Err(());
                }

                Ok(key)
            })()
            .map_err(|()| EP::ObjectInvalidData)
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
    use crate::types::misc::Iso8601TimeSp;

    /// Date and time in deprecated ISO8601-with-space separate arguments syntax
    ///
    /// Eg `dir-key-published` in a dir auth key cert.
    // TODO this should be
    //   #[deprecated = "use the Iso8601TimeSp name instead"]
    // but right now we have too much outstanding work in flight to do that.
    pub type NdaSystemTimeDeprecatedSyntax = Iso8601TimeSp;

    impl ItemArgumentParseable for NdaSystemTimeDeprecatedSyntax {
        fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, ArgumentError> {
            let t;
            (t, *args) = (|| {
                let whole_line_len = args.whole_line_len();
                let options = args.parse_options();
                let args = args.clone().into_remaining();
                let spc2 = args
                    .match_indices(WS)
                    .nth(1)
                    .map(|(spc2, _)| spc2)
                    .unwrap_or_else(|| args.len());
                let (t, rest) = args.split_at(spc2);
                let t: crate::types::misc::Iso8601TimeSp =
                    t.parse().map_err(|_| ArgumentError::Invalid)?;
                Ok::<_, AE>((t, ArgumentStream::new(rest, whole_line_len, options)))
            })()?;
            Ok(t)
        }
    }
}

/// Protocol versions (from `tor-protover`)
pub(crate) mod protovers {
    use super::*;
    use tor_protover::Protocols;

    impl ItemValueParseable for Protocols {
        fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, ErrorProblem> {
            item.check_no_object()?;
            item.args_copy()
                .into_remaining()
                .parse()
                .map_err(item.invalid_argument_handler("protocols"))
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

    #[cfg(feature = "parse2")]
    impl ItemObjectParseable for Void {
        fn check_label(_label: &str) -> Result<(), ErrorProblem> {
            Ok(())
        }

        fn from_bytes(_input: &[u8]) -> Result<Self, ErrorProblem> {
            Err(EP::ObjectUnexpected)
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
