//! Building support for the network document meta-format
//!
//! Implements building documents according to
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//! section 1.2 and 1.3.
//!
//! This facility proces output that complies with the meta-document format,
//! (`dir-spec.txt` section 1.2) -
//! unless `raw` methods are called with improper input.
//!
//! However, no checks are done on keyword presence/absence, multiplicity, or ordering,
//! so the output may not necessarily conform to the format of the particular intended document.
//! It is the caller's responsibility to call `.item()` in the right order,
//! with the right keywords and arguments.

#![allow(unused_variables)] // TODO hs
#![allow(unused_imports)] // TODO hs
#![allow(dead_code)] // TODO hs
#![allow(clippy::missing_docs_in_private_items)] // TODO hs
#![allow(clippy::needless_pass_by_value)] // TODO hs

use std::fmt::{self, Display, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::time::SystemTime;

use humantime::format_rfc3339;
use tor_error::{internal, into_internal, Bug};

use crate::parse::keyword::Keyword;

/// Network document text according to dir-spec.txt s1.2 and maybe s1.3
///
/// Contains just the text, but marked with the type of the builder
/// for clarity in function signatures etc.
pub struct NetdocText<Builder> {
    /// The actual document
    text: String,
    /// Marker.  Variance: this somehow came from a T (not that we expect this to matter)
    kind: PhantomData<Builder>,
}

impl<B> Deref for NetdocText<B> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

/// Encoder, representing a partially-built document
///
/// # Example
///
/// # TODO hs, actually fix and test this example
/// ```rust,ignore
/// use OnionServiceKeyword as K;
///
/// let mut document = NetDocEncoder::new();
/// let beginning = document.marker();
/// document.item(K::HsDescriptor).arg(3);
/// document.item(K::DescriptorLifetime).arg(&self.lifetime);
/// document.item(K::DescriptorSigningKeyCert).object("ED25519 CERT", &self.cert[..]);
/// document.item(K::RevisionCounter).arg(&self.counter);
/// document.item(K::Superencrypted).object("MESSAGE", inner_text);
/// let end = document.marker();
/// let signature = key.sign(document.slice(begining, end));
/// document.item(K::Signature).arg(B64(signature));
///
/// let text = document.finish()?;
/// ```
#[derive(Debug, Clone)]
pub(crate) struct NetdocEncoder {
    /// The being-built document, with everything accumulated so far
    ///
    /// If an [`ItemEncoder`] exists, it will add a newline when it's dropped.
    ///
    /// `Err` means bad values passed to some builder function
    built: Result<String, Bug>,
}

/// Encoder for an individual item within a being-built document
///
/// Returned by [`NetdocEncoder::item()`].
#[derive(Debug)]
pub(crate) struct ItemEncoder<'n> {
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
pub(crate) struct Cursor {
    /// The offset (in bytes, as for `&str`)
    ///
    /// Can be out of range if the corresponding `NetdocEncoder` is contains an `Err`.
    offset: usize,
}

/// Types that can be added as argument(s) to item keyword lines
///
/// Implemented for strings, and various other types.
///
/// This is a separate trait so we can control the formatting of (eg) [`SystemTime`],
/// without having a method on `ItemEncoder` for each argument type.
pub(crate) trait ItemArgument {
    /// Format as a string suitable for including as a netdoc keyword line argument
    ///
    /// The implementation is responsible for checking that the syntax is legal.
    /// For example, if `self` is a string, it must check that the string is
    /// in legal as a single argument.
    ///
    /// Some netdoc values (eg times) turn into several arguments; in that case,
    /// one `ItemArgument` may format into multiple arguments, and this method
    /// is responsible for writing them all, with the necessary spaces.
    fn write_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug>;
}

impl NetdocEncoder {
    /// Start encoding a document
    pub(crate) fn new() -> Self {
        NetdocEncoder {
            built: Ok(String::new()),
        }
    }

    /// Adds an item to the being-built document
    ///
    /// The item can be further extended with arguments or an object,
    /// using the returned `ItemEncoder`.
    pub(crate) fn item(&mut self, keyword: impl Keyword) -> ItemEncoder {
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
        // MSRV 1.65.0: change to let ... else
        let build = if let Ok(b) = &mut self.built {
            b
        } else {
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
    pub(crate) fn push_raw_string(&mut self, s: &dyn Display) {
        self.raw(s);
    }

    /// Return a cursor, pointing to just after the last item (if any)
    pub(crate) fn cursor(&self) -> Cursor {
        let offset = match &self.built {
            Ok(b) => b.len(),
            Err(_) => usize::MAX,
        };
        Cursor { offset }
    }

    /// Obtain the text of a section of the document
    ///
    /// Useful for making a signature.
    //
    // Q. Should this return `&str` or `NetdocText<'self>` ?
    // (`NetdocText would have to then contain `Cow`, which is fine.)
    pub(crate) fn slice(&self, begin: Cursor, end: Cursor) -> Result<&str, Bug> {
        self.built
            .as_ref()
            .map_err(Clone::clone)?
            .get(begin.offset..end.offset)
            .ok_or_else(|| internal!("NetdocEncoder::slice out of bounds, Cursor mismanaged"))
    }

    /// Build the document into textual form
    pub(crate) fn finish(self) -> Result<NetdocText<Self>, Bug> {
        let text = self.built?;
        Ok(NetdocText {
            text,
            kind: PhantomData,
        })
    }
}

impl ItemArgument for str {
    fn write_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        // Implements this
        // https://gitlab.torproject.org/tpo/core/torspec/-/merge_requests/106
        if self.is_empty() || self.chars().any(|c| !c.is_ascii_graphic()) {
            return Err(internal!("invalid keyword argument syntax {:?}", self));
        }
        out.args_raw_nonempty(&self);
        Ok(())
    }
}

impl<T: ItemArgument + ?Sized> ItemArgument for &'_ T {
    fn write_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        <T as ItemArgument>::write_onto(self, out)
    }
}

/// Implement [`ItemArgument`] for `$ty` in terms of `<$ty as Display>`
///
/// Checks that the syntax is acceptable.
macro_rules! impl_item_argument_as_display { { $( $ty:ty $(,)? )* } => { $(
    impl ItemArgument for $ty {
        fn write_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
            let arg = self.to_string();
            out.add_arg(&arg.as_str());
            Ok(())
        }
    }
)* } }

impl_item_argument_as_display! { usize, u8, u16, u32, u64, u128 }
impl_item_argument_as_display! { isize, i8, i16, i32, i64, i128 }

impl ItemArgument for SystemTime {
    fn write_onto(&self, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        out.args_raw_nonempty(
            // There are two needless allocations here.  A mutating-on-the-fly
            // struct impl fmt::Write could be used instead, but it's not clear it's worth it.
            &format_rfc3339(*self)
                .to_string()
                .replace('T', " ")
                .trim_end_matches('Z'),
        );
        Ok(())
    }
}

impl<'n> ItemEncoder<'n> {
    /// Add a single argument.
    ///
    /// If the argument is not in the correct syntax, a `Bug`
    /// error will be reported (later).
    //
    // This is not a hot path.  `dyn` for smaller code size.
    pub(crate) fn arg(mut self, arg: &dyn ItemArgument) -> Self {
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
            .write_onto(self)
            .unwrap_or_else(|err| self.doc.built = Err(err));
    }

    /// Add zero or more arguments, supplied as a single string.
    ///
    /// `args` should zero or more valid argument strings,
    /// separated by (single) spaces.
    /// This is not (properly) checked.
    /// Incorrect use might lead to malformed documents, or later errors.
    pub(crate) fn args_raw_string(mut self, args: &dyn Display) -> Self {
        let args = args.to_string();
        if !args.is_empty() {
            self.args_raw_nonempty(&args);
        }
        self
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
    pub(crate) fn object(
        self,
        keywords: &str,
        // Writeable isn't dyn-compatible
        data: impl tor_bytes::WriteableOnce,
    ) {
        todo!()
    }
}

impl Drop for ItemEncoder<'_> {
    fn drop(&mut self) {
        self.doc.raw(&'\n');
    }
}
