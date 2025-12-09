//! Support for encoding the network document meta-format
//!
//! Implements writing documents according to
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//! section 1.2 and 1.3.
//!
//! This facility processes output that complies with the meta-document format,
//! (`dir-spec.txt` section 1.2) -
//! unless `raw` methods are called with improper input.
//!
//! However, no checks are done on keyword presence/absence, multiplicity, or ordering,
//! so the output may not necessarily conform to the format of the particular intended document.
//! It is the caller's responsibility to call `.item()` in the right order,
//! with the right keywords and arguments.

mod multiplicity;
#[macro_use]
mod derive;

use std::cmp;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::iter;
use std::marker::PhantomData;

use base64ct::{Base64, Base64Unpadded, Encoding};
use educe::Educe;
use itertools::Itertools;
use paste::paste;
use rand::{CryptoRng, RngCore};
use tor_bytes::EncodeError;
use tor_error::internal;
use void::Void;

use crate::KeywordEncodable;
use crate::parse::tokenize::tag_keywords_ok;
use crate::types::misc::Iso8601TimeSp;

// Exports used by macros, which treat this module as a prelude
#[doc(hidden)]
pub use {
    derive::{DisplayHelper, RestMustComeLastMarker},
    multiplicity::{
        MultiplicityMethods, MultiplicitySelector, OptionalityMethods,
        SingletonMultiplicitySelector,
    },
    std::fmt::{self, Display},
    std::result::Result,
    tor_error::{Bug, into_internal},
};

/// Encoder, representing a partially-built document.
///
/// For example usage, see the tests in this module, or a descriptor building
/// function in tor-netdoc (such as `hsdesc::build::inner::HsDescInner::build_sign`).
#[derive(Debug, Clone)]
pub struct NetdocEncoder {
    /// The being-built document, with everything accumulated so far
    ///
    /// If an [`ItemEncoder`] exists, it will add a newline when it's dropped.
    ///
    /// `Err` means bad values passed to some builder function.
    /// Such errors are accumulated here for the benefit of handwritten document encoders.
    built: Result<String, Bug>,
}

/// Encoder for an individual item within a being-built document
///
/// Returned by [`NetdocEncoder::item()`].
#[derive(Debug)]
pub struct ItemEncoder<'n> {
    /// The document including the partial item that we're building
    ///
    /// We will always add a newline when we're dropped
    doc: &'n mut NetdocEncoder,
}

/// Position within a (perhaps partially-) built document
///
/// This is provided mainly to allow the caller to perform signature operations
/// on the part of the document that is to be signed.
/// (Sometimes this is only part of it.)
///
/// There is no enforced linkage between this and the document it refers to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cursor {
    /// The offset (in bytes, as for `&str`)
    ///
    /// Can be out of range if the corresponding `NetdocEncoder` is contains an `Err`.
    offset: usize,
}

/// Types that can be added as argument(s) to item keyword lines
///
/// Implemented for strings, and various other types.
///
/// This is a separate trait so we can control the formatting of (eg) [`Iso8601TimeSp`],
/// without having a method on `ItemEncoder` for each argument type.
//
// TODO consider renaming this to ItemArgumentEncodable to mirror all the other related traits.
pub trait ItemArgument {
    /// Format as a string suitable for including as a netdoc keyword line argument
    ///
    /// The implementation is responsible for checking that the syntax is legal.
    /// For example, if `self` is a string, it must check that the string is
    /// in legal as a single argument.
    ///
    /// Some netdoc values (eg times) turn into several arguments; in that case,
    /// one `ItemArgument` may format into multiple arguments, and this method
    /// is responsible for writing them all, with the necessary spaces.
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug>;
}

impl NetdocEncoder {
    /// Start encoding a document
    pub fn new() -> Self {
        NetdocEncoder {
            built: Ok(String::new()),
        }
    }

    /// Adds an item to the being-built document
    ///
    /// The item can be further extended with arguments or an object,
    /// using the returned `ItemEncoder`.
    pub fn item(&mut self, keyword: impl KeywordEncodable) -> ItemEncoder {
        self.raw(&keyword.to_str());
        ItemEncoder { doc: self }
    }

    /// Internal name for `push_raw_string()`
    fn raw(&mut self, s: &dyn Display) {
        self.write_with(|b| {
            write!(b, "{}", s).expect("write! failed on String");
            Ok(())
        });
    }

    /// Extend the being-built document with a fallible function `f`
    ///
    /// Doesn't call `f` if the building has already failed,
    /// and handles the error if `f` fails.
    fn write_with(&mut self, f: impl FnOnce(&mut String) -> Result<(), Bug>) {
        let Ok(build) = &mut self.built else {
            return;
        };
        match f(build) {
            Ok(()) => (),
            Err(e) => {
                self.built = Err(e);
            }
        }
    }

    /// Adds raw text to the being-built document
    ///
    /// `s` is added as raw text, after the newline ending the previous item.
    /// If `item` is subsequently called, the start of that item
    /// will immediately follow `s`.
    ///
    /// It is the responsibility of the caller to obey the metadocument syntax.
    /// In particular, `s` should end with a newline.
    /// No checks are performed.
    /// Incorrect use might lead to malformed documents, or later errors.
    pub fn push_raw_string(&mut self, s: &dyn Display) {
        self.raw(s);
    }

    /// Return a cursor, pointing to just after the last item (if any)
    pub fn cursor(&self) -> Cursor {
        let offset = match &self.built {
            Ok(b) => b.len(),
            Err(_) => usize::MAX,
        };
        Cursor { offset }
    }

    /// Obtain the text of a section of the document
    ///
    /// Useful for making a signature.
    pub fn slice(&self, begin: Cursor, end: Cursor) -> Result<&str, Bug> {
        self.built
            .as_ref()
            .map_err(Clone::clone)?
            .get(begin.offset..end.offset)
            .ok_or_else(|| internal!("NetdocEncoder::slice out of bounds, Cursor mismanaged"))
    }

    /// Build the document into textual form
    pub fn finish(self) -> Result<String, Bug> {
        self.built
    }
}

impl Default for NetdocEncoder {
    fn default() -> Self {
        // We must open-code this because the actual encoder contains Result, which isn't Default
        NetdocEncoder::new()
    }
}

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

impl<T: crate::NormalItemArgument> ItemArgument for T {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        (*self.to_string()).write_arg_onto(out)
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

#[cfg(feature = "hs-pow-full")]
impl ItemArgument for tor_hscrypto::pow::v1::Seed {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        let mut seed_bytes = vec![];
        tor_bytes::Writer::write(&mut seed_bytes, &self)?;
        out.add_arg(&Base64Unpadded::encode_string(&seed_bytes));
        Ok(())
    }
}

#[cfg(feature = "hs-pow-full")]
impl ItemArgument for tor_hscrypto::pow::v1::Effort {
    fn write_arg_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        out.add_arg(&<Self as Into<u32>>::into(*self));
        Ok(())
    }
}

impl<'n> ItemEncoder<'n> {
    /// Add a single argument.
    ///
    /// Convenience method that defers error handling, for use in infallible contexts.
    /// Consider whether to use `ItemArgument::write_arg_onto` directly, instead.
    ///
    /// If the argument is not in the correct syntax, a `Bug`
    /// error will be reported (later).
    //
    // This is not a hot path.  `dyn` for smaller code size.
    pub fn arg(mut self, arg: &dyn ItemArgument) -> Self {
        self.add_arg(arg);
        self
    }

    /// Add a single argument, to a borrowed `ItemEncoder`
    ///
    /// If the argument is not in the correct syntax, a `Bug`
    /// error will be reported (later).
    //
    // Needed for implementing `ItemArgument`
    pub(crate) fn add_arg(&mut self, arg: &dyn ItemArgument) {
        let () = arg
            .write_arg_onto(self)
            .unwrap_or_else(|err| self.doc.built = Err(err));
    }

    /// Add zero or more arguments, supplied as a single string.
    ///
    /// `args` should zero or more valid argument strings,
    /// separated by (single) spaces.
    /// This is not (properly) checked.
    /// Incorrect use might lead to malformed documents, or later errors.
    pub fn args_raw_string(&mut self, args: &dyn Display) {
        let args = args.to_string();
        if !args.is_empty() {
            self.args_raw_nonempty(&args);
        }
    }

    /// Add one or more arguments, supplied as a single string, without any checking
    fn args_raw_nonempty(&mut self, args: &dyn Display) {
        self.doc.raw(&format_args!(" {}", args));
    }

    /// Add an object to the item
    ///
    /// Checks that `keywords` is in the correct syntax.
    /// Doesn't check that it makes semantic sense for the position of the document.
    /// `data` will be PEM (base64) encoded.
    //
    // If keyword is not in the correct syntax, a `Bug` is stored in self.doc.
    pub fn object(
        self,
        keywords: &str,
        // Writeable isn't dyn-compatible
        data: impl tor_bytes::WriteableOnce,
    ) {
        use crate::parse::tokenize::object::*;

        self.doc.write_with(|out| {
            if keywords.is_empty() || !tag_keywords_ok(keywords) {
                return Err(internal!("bad object keywords string {:?}", keywords));
            }
            let data = {
                let mut bytes = vec![];
                data.write_into(&mut bytes)?;
                Base64::encode_string(&bytes)
            };
            let mut data = &data[..];
            writeln!(out, "\n{BEGIN_STR}{keywords}{TAG_END}").expect("write!");
            while !data.is_empty() {
                let (l, r) = if data.len() > BASE64_PEM_MAX_LINE {
                    data.split_at(BASE64_PEM_MAX_LINE)
                } else {
                    (data, "")
                };
                writeln!(out, "{l}").expect("write!");
                data = r;
            }
            // final newline will be written by Drop impl
            write!(out, "{END_STR}{keywords}{TAG_END}").expect("write!");
            Ok(())
        });
    }

    /// Finish encoding this item
    ///
    /// The item will also automatically be finished if the `ItemEncoder` is dropped.
    pub fn finish(self) {}
}

impl Drop for ItemEncoder<'_> {
    fn drop(&mut self) {
        self.doc.raw(&'\n');
    }
}

/// Ordering, to be used when encoding network documents
///
/// Implemented for anything `Ord`.
///
/// Can also be implemented manually, for if a type cannot be `Ord`
/// (perhaps for trait coherence reasons).
pub trait EncodeOrd {
    /// Compare `self` and `other`
    ///
    /// As `Ord::cmp`.
    fn encode_cmp(&self, other: &Self) -> cmp::Ordering;
}
impl<T: Ord> EncodeOrd for T {
    fn encode_cmp(&self, other: &Self) -> cmp::Ordering {
        self.cmp(other)
    }
}

/// Documents (or sub-documents) that can be encoded in the netdoc metaformat
pub trait NetdocEncodable {
    /// Append the document onto `out`
    fn encode_unsigned(&self, out: &mut NetdocEncoder) -> Result<(), Bug>;
}

/// Collections of fields that can be encoded in the netdoc metaformat
///
/// Whole documents have structure; a `NetdocEncodableFields` does not.
pub trait NetdocEncodableFields {
    /// Append the document onto `out`
    fn encode_fields(&self, out: &mut NetdocEncoder) -> Result<(), Bug>;
}

/// Items that can be encoded in network documents
pub trait ItemValueEncodable {
    /// Write the item's arguments, and any object, onto `out`
    ///
    /// `out` will have been freshly returned from [`NetdocEncoder::item`].
    fn write_item_value_onto(&self, out: ItemEncoder) -> Result<(), Bug>;
}

/// An Object value that be encoded into a netdoc
pub trait ItemObjectEncodable {
    /// The label (keyword(s) in `BEGIN` and `END`)
    fn label(&self) -> &str;

    /// Represent the actual value as bytes.
    ///
    /// The caller, not the object, is responsible for base64 encoding.
    //
    // This is not a tor_bytes::Writeable supertrait because tor_bytes's writer argument
    // is generic, which prevents many deisrable manipulations of an `impl Writeable`.
    fn write_object_onto(&self, b: &mut Vec<u8>) -> Result<(), Bug>;
}

/// Builders for network documents.
///
/// This trait is a bit weird, because its `Self` type must contain the *private* keys
/// necessary to sign the document!
///
/// So it is implemented for "builders", not for documents themselves.
/// Some existing documents can be constructed only via these builders.
/// The newer approach is for documents to be transparent data, at the Rust level,
/// and to derive an encoder.
/// TODO this derive approach is not yet implemented!
///
/// Actual document types, which only contain the information in the document,
/// don't implement this trait.
pub trait NetdocBuilder {
    /// Build the document into textual form.
    fn build_sign<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<String, EncodeError>;
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

/// implement [`ItemValueEncodable`] for a particular tuple size
macro_rules! item_value_encodable_for_tuple {
    { $($i:literal)* } => { paste! {
        impl< $( [<T$i>]: ItemArgument, )* > ItemValueEncodable for ( $( [<T$i>], )* ) {
            fn write_item_value_onto(
                &self,
                #[allow(unused)]
                mut out: ItemEncoder,
            ) -> Result<(), Bug> {
                $(
                    <[<T$i>] as ItemArgument>::write_arg_onto(&self.$i, &mut out)?;
                )*
                Ok(())
            }
        }
    } }
}

item_value_encodable_for_tuple! {}
item_value_encodable_for_tuple! { 0 }
item_value_encodable_for_tuple! { 0 1 }
item_value_encodable_for_tuple! { 0 1 2 }
item_value_encodable_for_tuple! { 0 1 2 3 }
item_value_encodable_for_tuple! { 0 1 2 3 4 }
item_value_encodable_for_tuple! { 0 1 2 3 4 5 }
item_value_encodable_for_tuple! { 0 1 2 3 4 5 6 }
item_value_encodable_for_tuple! { 0 1 2 3 4 5 6 7 }
item_value_encodable_for_tuple! { 0 1 2 3 4 5 6 7 8 }
item_value_encodable_for_tuple! { 0 1 2 3 4 5 6 7 8 9 }

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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use std::str::FromStr;

    use crate::types::misc::Iso8601TimeNoSp;
    use base64ct::{Base64Unpadded, Encoding};

    #[test]
    fn time_formats_as_args() {
        use crate::doc::authcert::AuthCertKwd as ACK;
        use crate::doc::netstatus::NetstatusKwd as NK;

        let t_sp = Iso8601TimeSp::from_str("2020-04-18 08:36:57").unwrap();
        let t_no_sp = Iso8601TimeNoSp::from_str("2021-04-18T08:36:57").unwrap();

        let mut encode = NetdocEncoder::new();
        encode.item(ACK::DIR_KEY_EXPIRES).arg(&t_sp);
        encode
            .item(NK::SHARED_RAND_PREVIOUS_VALUE)
            .arg(&"3")
            .arg(&"bMZR5Q6kBadzApPjd5dZ1tyLt1ckv1LfNCP/oyGhCXs=")
            .arg(&t_no_sp);

        let doc = encode.finish().unwrap();
        println!("{}", doc);
        assert_eq!(
            doc,
            r"dir-key-expires 2020-04-18 08:36:57
shared-rand-previous-value 3 bMZR5Q6kBadzApPjd5dZ1tyLt1ckv1LfNCP/oyGhCXs= 2021-04-18T08:36:57
"
        );
    }

    #[test]
    fn authcert() {
        use crate::doc::authcert::AuthCertKwd as ACK;
        use crate::doc::authcert::{AuthCert, UncheckedAuthCert};

        // c&p from crates/tor-llcrypto/tests/testvec.rs
        let pk_rsa = {
            let pem = "
MIGJAoGBANUntsY9boHTnDKKlM4VfczcBE6xrYwhDJyeIkh7TPrebUBBvRBGmmV+
PYK8AM9irDtqmSR+VztUwQxH9dyEmwrM2gMeym9uXchWd/dt7En/JNL8srWIf7El
qiBHRBGbtkF/Re5pb438HC/CGyuujp43oZ3CUYosJOfY/X+sD0aVAgMBAAE";
            Base64Unpadded::decode_vec(&pem.replace('\n', "")).unwrap()
        };

        let mut encode = NetdocEncoder::new();
        encode.item(ACK::DIR_KEY_CERTIFICATE_VERSION).arg(&3);
        encode
            .item(ACK::FINGERPRINT)
            .arg(&"9367f9781da8eabbf96b691175f0e701b43c602e");
        encode
            .item(ACK::DIR_KEY_PUBLISHED)
            .arg(&Iso8601TimeSp::from_str("2020-04-18 08:36:57").unwrap());
        encode
            .item(ACK::DIR_KEY_EXPIRES)
            .arg(&Iso8601TimeSp::from_str("2021-04-18 08:36:57").unwrap());
        encode
            .item(ACK::DIR_IDENTITY_KEY)
            .object("RSA PUBLIC KEY", &*pk_rsa);
        encode
            .item(ACK::DIR_SIGNING_KEY)
            .object("RSA PUBLIC KEY", &*pk_rsa);
        encode
            .item(ACK::DIR_KEY_CROSSCERT)
            .object("ID SIGNATURE", []);
        encode
            .item(ACK::DIR_KEY_CERTIFICATION)
            .object("SIGNATURE", []);

        let doc = encode.finish().unwrap();
        eprintln!("{}", doc);
        assert_eq!(
            doc,
            r"dir-key-certificate-version 3
fingerprint 9367f9781da8eabbf96b691175f0e701b43c602e
dir-key-published 2020-04-18 08:36:57
dir-key-expires 2021-04-18 08:36:57
dir-identity-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANUntsY9boHTnDKKlM4VfczcBE6xrYwhDJyeIkh7TPrebUBBvRBGmmV+
PYK8AM9irDtqmSR+VztUwQxH9dyEmwrM2gMeym9uXchWd/dt7En/JNL8srWIf7El
qiBHRBGbtkF/Re5pb438HC/CGyuujp43oZ3CUYosJOfY/X+sD0aVAgMBAAE=
-----END RSA PUBLIC KEY-----
dir-signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANUntsY9boHTnDKKlM4VfczcBE6xrYwhDJyeIkh7TPrebUBBvRBGmmV+
PYK8AM9irDtqmSR+VztUwQxH9dyEmwrM2gMeym9uXchWd/dt7En/JNL8srWIf7El
qiBHRBGbtkF/Re5pb438HC/CGyuujp43oZ3CUYosJOfY/X+sD0aVAgMBAAE=
-----END RSA PUBLIC KEY-----
dir-key-crosscert
-----BEGIN ID SIGNATURE-----
-----END ID SIGNATURE-----
dir-key-certification
-----BEGIN SIGNATURE-----
-----END SIGNATURE-----
"
        );

        let _: UncheckedAuthCert = AuthCert::parse(&doc).unwrap();
    }
}
