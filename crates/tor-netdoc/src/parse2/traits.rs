//! Core model for netdoc parsing

use super::*;

/// A document or section that can be parsed
///
/// Normally [derived](derive_deftly_template_NetdocParseable).
pub trait NetdocParseable: Sized {
    /// Document type for errors, normally its intro keyword
    fn doctype_for_error() -> &'static str;

    /// Is `Keyword` an intro Item Keyword for this kind of document?
    ///
    /// This is used with 1-keyword lookahead, to allow us to push or pop
    /// the parsing state into or out of a sub-document.
    ///
    /// For signatures sections, this should report *every* recognised keyword.
    fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool;

    /// Parse the document from a stream of Items
    ///
    /// Should stop before reading any keyword matching `stop_at`.
    /// (Except, right at the start.)
    ///
    /// Should also stop before reading a 2nd intro keyword,
    /// so that successive calls to this function can parse
    /// successive sub-documents of this kind.
    ///
    /// Otherwise, should continue until EOF.
    ///
    /// Must check whether the first item is this document's `is_intro_item_keyword`,
    /// and error if not.
    fn from_items(input: &mut ItemStream<'_>, stop_at: stop_at!()) -> Result<Self, ErrorProblem>;

    /// Is `Keyword` a structural keyword for this kind of document?
    ///
    /// Returns `Some(IsStructural)` for:
    ///   - this type's intro item keyword (`is_intro_item_keyword`)
    ///   - the intro items or structural items for any of its sub-documents and sections
    ///     `#[deftly(netdoc(subdoc))]`
    ///
    /// (This means it returns true for *any* item in a signatures subdocument
    /// ie any field in a struct decorated `#[deftly(netdoc(signatures))]`
    /// since those are considered intro items.)
    ///
    /// Used for avoiding parsing ambiguity when a netdoc from a semi-trusted source
    /// is embedded into another netdoc.
    /// See <https://spec.torproject.org/dir-spec/creating-key-certificates.html#nesting>.
    ///
    /// # Return type and relationship to `is_intro_item_keyword`
    ///
    /// Returns `Option<IsStructural>`
    /// so that it has a different type to [`NetdocParseable::is_intro_item_keyword`],
    /// preventing accidental confusion between the two kinds of keyword property enquiry.
    ///
    /// Our parsing algorithms actually only care about *intro keywords* for sub-documents.
    /// We don't need to worry about anything else;
    /// notably, we don't need to care about other structural items within those sub-documents.
    ///
    /// Except for authcerts in votes,, which are nested documents
    /// with partially trusted content.
    /// That is what this method is for.
    ///
    /// So, we privilege `is_intro_item_keyword` by having it return `bool`
    /// and by the affordances in [`StopAt`].
    fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural>;
}

/// A collection of fields that can be parsed within a section
///
/// None of the items can be structural.
///
/// Normally [derived](derive_deftly_template_NetdocParseableFields).
pub trait NetdocParseableFields: Sized {
    /// The partially-parsed set of items.
    type Accumulator: Sized + Debug + Send + Sync + 'static;

    /// Is this one of the keywords in this struct
    fn is_item_keyword(kw: KeywordRef<'_>) -> bool;

    /// Accumulate an item in this struct
    ///
    /// # Panics
    ///
    /// The caller must have first checked the `item`'s keyword with `is_item_keyword`.
    /// If this *isn't* an item for this structure, may panic.
    fn accumulate_item(acc: &mut Self::Accumulator, item: UnparsedItem<'_>) -> Result<(), EP>;

    /// Finish
    ///
    /// Resolves the `Accumulator` into the output type.
    /// Generally, this means throwing an error if expected fields were not present.
    fn finish(acc: Self::Accumulator) -> Result<Self, EP>;
}

/// A network document with (unverified) signatures
///
/// Typically implemented automatically, for `FooSigned` structs, as defined by
/// [`#[derive_deftly(NetdocSigned)]`](derive_deftly_template_NetdocSigned).
//
// TODO is this only useable for parsing?  It needs to be renamed, or maybe impooved and moved
pub trait NetdocSigned {
    /// The body, ie not including the signatures
    type Body: Sized;
    /// The signatures (the whole signature section)
    type Signatures: Sized;

    /// Inspect the document (and its signatures)
    ///
    /// # Security hazard
    ///
    /// The signature has not been verified, so the returned data must not be trusted.
    fn inspect_unverified(&self) -> (&Self::Body, &Self::Signatures);

    /// Obtain the actual document (and signatures), without verifying
    ///
    /// # Security hazard
    ///
    /// The signature has not been verified, so the returned data must not be trusted.
    fn unwrap_unverified(self) -> (Self::Body, Self::Signatures);

    /// Construct a new `NetdocSigned` from a body and signatures
    ///
    /// (Called by code generated by `#[derive_deftly(NetdocSigned)]`.)
    fn from_parts(body: Self::Body, signatures: Self::Signatures) -> Self;
}

/// An item (value) that can be parsed in a netdoc
///
/// This is the type `T` of a field `item: T` in a netdoc type.
///
/// An implementation is provided for tuples of `ItemArgumentParseable`,
/// which parses each argument in turn,
/// ignores additional arguments,
/// and rejects any Object.
///
/// Typically derived with
/// [`#[derive_deftly(ItemValueParseable)]`](derive_deftly_template_ItemValueParseable).
///
/// Signature items are special, and implement [`SignatureItemParseable`] instead.
pub trait ItemValueParseable: Sized {
    /// Parse the item's value
    fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, ErrorProblem>;
}

/// An (individual) argument that can be parsed from in a netdoc
///
/// An implementations is provided for **`T: FromStr`**,
/// which expects a single argument and passes it to `FromStr`.
///
/// For netdoc arguments whose specified syntax spans multiple space-separated words,
/// use a manual implementation or a wrapper type.
pub trait ItemArgumentParseable: Sized {
    /// Parse the argument
    fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, ArgumentError>;
}

/// An Object value that be parsed from a netdoc
pub trait ItemObjectParseable: Sized {
    /// Check that the Label is right
    fn check_label(label: &str) -> Result<(), ErrorProblem>;

    /// Convert the bytes of the Object (which was present) into the actual value
    ///
    /// `input` has been base64-decoded.
    fn from_bytes(input: &[u8]) -> Result<Self, ErrorProblem>;
}

/// Token indicating that a keyword is structural
///
/// Returned by [`NetdocParseable::is_structural_keyword`]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::exhaustive_structs)]
pub struct IsStructural;

//---------- provided blanket impls ----------

impl<T: NormalItemArgument> ItemArgumentParseable for T {
    fn from_args<'s>(args: &mut ArgumentStream<'s>) -> Result<Self, AE> {
        let v = args
            .next()
            .ok_or(AE::Missing)?
            .parse()
            .map_err(|_e| AE::Missing)?;
        Ok(v)
    }
}

impl<T: ItemValueParseable> ItemValueParseable for Arc<T> {
    fn from_unparsed(item: UnparsedItem<'_>) -> Result<Self, ErrorProblem> {
        T::from_unparsed(item).map(Arc::new)
    }
}

impl<T: NetdocParseable> NetdocParseable for Arc<T> {
    fn doctype_for_error() -> &'static str {
        T::doctype_for_error()
    }
    fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
        T::is_intro_item_keyword(kw)
    }
    fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
        T::is_structural_keyword(kw)
    }
    fn from_items(input: &mut ItemStream<'_>, stop_at: stop_at!()) -> Result<Self, EP> {
        T::from_items(input, stop_at).map(Arc::new)
    }
}
impl<T: NetdocParseableFields> NetdocParseableFields for Arc<T> {
    type Accumulator = T::Accumulator;
    fn is_item_keyword(kw: KeywordRef<'_>) -> bool {
        T::is_item_keyword(kw)
    }
    fn accumulate_item(acc: &mut Self::Accumulator, item: UnparsedItem<'_>) -> Result<(), EP> {
        T::accumulate_item(acc, item)
    }
    fn finish(acc: Self::Accumulator) -> Result<Self, EP> {
        T::finish(acc).map(Arc::new)
    }
}

/// implement [`ItemValueParseable`] for a particular tuple size
macro_rules! item_value_parseable_for_tuple {
    { $($i:literal)* } => { paste! {
        impl< $( [<T$i>]: ItemArgumentParseable, )* >
            ItemValueParseable for ( $( [<T$i>], )* )
        {
            fn from_unparsed(
                #[allow(unused_mut)]
                mut item: UnparsedItem<'_>,
            ) -> Result<Self, ErrorProblem> {
                let r = ( $(
                    <[<T$i>] as ItemArgumentParseable>::from_args(
                        item.args_mut(),
                    ).map_err(item.args().error_handler(stringify!($i)))?,
                )* );
                item.check_no_object()?;
                Ok(r)
            }
        }
    } }
}

item_value_parseable_for_tuple! {}
item_value_parseable_for_tuple! { 0 }
item_value_parseable_for_tuple! { 0 1 }
item_value_parseable_for_tuple! { 0 1 2 }
item_value_parseable_for_tuple! { 0 1 2 3 }
item_value_parseable_for_tuple! { 0 1 2 3 4 }
item_value_parseable_for_tuple! { 0 1 2 3 4 5 }
item_value_parseable_for_tuple! { 0 1 2 3 4 5 6 }
item_value_parseable_for_tuple! { 0 1 2 3 4 5 6 7 }
item_value_parseable_for_tuple! { 0 1 2 3 4 5 6 7 8 }
item_value_parseable_for_tuple! { 0 1 2 3 4 5 6 7 8 9 }
