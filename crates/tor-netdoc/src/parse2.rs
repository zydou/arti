//! New netdoc parsing arrangements, with `derive`
//!
//! # Parsing principles
//!
//! A parseable network document is a type implementing [`NetdocParseable`].
//! usually via the
//! [`NetdocParseable` derive=deftly macro`](crate::derive_deftly_template_NetdocParseable).
//!
//! A document type is responsible for recognising its own heading item.
//! Its parser will also be told other of structural items that it should not consume.
//! The structural lines can then be used to pass control to the appropriate parser.
//!
//! A "structural item" is a netdoc item that is defines the structure of the document.
//! This includes the intro items for whole documents,
//! the items that introduce document sections
//! (which we model by treating the section as a sub-document)
//! and signature items (which introduce the signatures at the end of the document,
//! and after which no non-signature items may appear).
//!
//! # Ordering
//!
//! We don't always parse things into a sorted order.
//! Sorting will be done when assembling documents, before outputting.
//!
//! # Types, and signature handling
//!
//! Most top-level network documents are signed somehow.
//! In this case there are three types:
//!
//!   * **`FooUnverified`**: a signed `Foo`, with its signatures, not yet verified.
//!     Implements [`NetdocParseableUnverified`],
//!     typically by invoking the
//!     [`NetdocUParseablenverified` derive macro](crate::derive_deftly_template_NetdocParseableUnverified)
//!     on `Foo`.
//!
//!     Type-specific methods are provided for verification,
//!     to obtain a `Foo`.
//!
//!   * **`Foo`**: the body data for the document.
//!     This doesn't contain any signatures.
//!     Having one of these to play with means signatures have already been validated.
//!     Can be parsed as part of the signed document,
//!     via the `NetdocParseable` implementation on `FooUnverified`,
//!     and then obtained via `.verify_...` method(s) on `FooUnverified`,
//!
//!   * **`FooSignatures`**: the signatures for a `Foo`.
//!     Implements `NetdocParseableSignatures`, via
//!     [derive](crate::derive_deftly_template_NetdocParseableSignatures),
//!     with `#[deftly(netdoc(signatures))]`.
//!
//! # Relationship to tor_netdoc::parse
//!
//! This is a completely new parsing approach, based on different principles.
//! The key principle is the recognition of "structural keywords",
//! recursively within a parsing stack, via the p`NetdocParseable`] trait.
//!
//! This allows the parser to be derived.  We have type-driven parsing
//! of whole Documents, Items, and their Arguments and Objects,
//! including of their multiplicity.
//!
//! The different keyword handling means we can't use most of the existing lexer,
//! and need new item parsing API:
//!
//!  * [`NetdocParseable`] trait.
//!  * [`KeywordRef`] type.
//!  * [`ItemStream`], [`UnparsedItem`], [`ArgumentStream`], [`UnparsedObject`].
//!
//! The different error handling means we have our own error types.
//! (The crate's existing parse errors have information that we don't track,
//! and is also a portmanteau error for parsing, writing, and other functions.)
//!
//! Document signing is handled in a more abstract way.
//!
//! Some old netdoc constructs are not supported.
//! For example, the obsolete `opt` prefix on safe-to-ignore Items.
//! The parser may make different decisions about netdocs with anomalous item ordering.

#[doc(hidden)]
#[macro_use]
pub mod internal_prelude;

#[macro_use]
mod structural;

#[macro_use]
mod derive;

mod error;
mod impls;
pub mod keyword;
mod lex;
mod lines;
pub mod multiplicity;
mod signatures;
mod traits;

use internal_prelude::*;

pub use error::{ArgumentError, ErrorProblem, ParseError, UnexpectedArgument, VerifyFailed};
pub use impls::times::NdaSystemTimeDeprecatedSyntax;
pub use keyword::KeywordRef;
pub use lex::{ArgumentStream, ItemStream, NoFurtherArguments, UnparsedItem, UnparsedObject};
pub use lines::{Lines, Peeked, StrExt};
pub use signatures::{
    HasUnverifiedParsedBody, NetdocParseableSignatures, NetdocParseableUnverified,
    SignatureHashInputs, SignatureHashesAccumulator, SignatureItemParseable, SignaturesData,
    sig_hashes,
};
#[allow(deprecated)]
#[deprecated]
pub use signatures::{check_validity_time, check_validity_time_tolerance};
pub use structural::{StopAt, StopPredicate};
pub use traits::{
    IsStructural, ItemArgumentParseable, ItemObjectParseable, ItemValueParseable, NetdocParseable,
    NetdocParseableFields,
};

#[doc(hidden)]
pub use derive::netdoc_parseable_derive_debug;

pub(crate) use internal_prelude::EP;

//---------- input ----------

/// Options for parsing
///
/// Specific document and type parsing methods may use these parameters
/// to control their parsing behaviour at run-time.
#[derive(educe::Educe, Debug, Clone)]
#[allow(clippy::manual_non_exhaustive)]
#[educe(Default)]
pub struct ParseOptions {
    /// Retain unknown values?
    ///
    /// Some field types, especially for flags fields, have the capability to retain
    /// unknown flags.  But, whereas known flags can be represented as single bits,
    /// representing unknown flags involves allocating and copying strings.
    /// Unless the document is to be reproduced, this is a waste of effort.
    ///
    /// Each document field type affected by this option should store the unknowns
    /// as `Unknown<HashSet<String>>` or similar.
    ///
    /// This feature should only be used where performance is important.
    /// For example, it is useful for types that appear in md consensus routerdescs,
    /// but less useful for types that appear only in a netstatus preamble.
    ///
    /// This is currently used for router flags.
    #[educe(Default(expression = "Unknown::new_discard()"))]
    pub retain_unknown_values: Unknown<()>,

    // Like `#[non_exhaustive]`, but doesn't prevent use of struct display syntax with `..`
    #[doc(hidden)]
    _private_non_exhaustive: (),
}

/// Input to a network document top-level parsing operation
#[derive(Debug, Clone, amplify::Getters)]
pub struct ParseInput<'s> {
    /// The actual document text
    #[getter(as_copy)]
    input: &'s str,

    /// Filename (for error reporting)
    #[getter(as_copy)]
    file: &'s str,

    /// Parsing options
    #[getter(as_ref, as_mut)]
    options: ParseOptions,
}

impl<'s> ParseInput<'s> {
    /// Prepare to parse an input string
    pub fn new(input: &'s str, file: &'s str) -> Self {
        ParseInput {
            input,
            file,
            options: ParseOptions::default(),
        }
    }

    /// Enable retention of unknown values during parsing
    ///
    /// Convenience method to set
    /// [`.options_mut().retain_unknown_values`](ParseOptions::retain_unknown_values)
    /// to [`Unknown::Retained`].
    #[cfg(feature = "retain-unknown")]
    pub fn retain_unknown_values(&mut self) {
        self.options_mut().retain_unknown_values = Unknown::Retained(());
    }
}

//---------- parser ----------

/// Common code for `parse_netdoc` and `parse_netdoc_multiple`
///
/// Creates the `ItemStream`, calls `parse_completely`, and handles errors.
fn parse_internal<T, D: NetdocParseable>(
    input: &ParseInput<'_>,
    parse_completely: impl FnOnce(&mut ItemStream) -> Result<T, ErrorProblem>,
) -> Result<T, ParseError> {
    let mut items = ItemStream::new(input);
    parse_completely(&mut items).map_err(error_handler::<D>(input, &items))
}

/// Return a function for converting `ErrorProblem` to `ParseError`
///
/// For use in `.map_err()`.
//
// Returning a closure means the usual kind of call site doesn't need to name `problem`.
fn error_handler<D: NetdocParseable>(
    input: &ParseInput<'_>,
    items: &ItemStream<'_>,
) -> impl Fn(ErrorProblem) -> ParseError {
    |problem| ParseError {
        problem,
        doctype: D::doctype_for_error(),
        file: input.file.to_owned(),
        lno: items.lno_for_error(),
        column: problem.column(),
    }
}

/// Parse a network document - **toplevel entrypoint**
pub fn parse_netdoc<D: NetdocParseable>(input: &ParseInput<'_>) -> Result<D, ParseError> {
    parse_internal::<_, D>(input, |items| {
        let doc = D::from_items(items, StopAt(false))?;
        if let Some(_kw) = items.peek_keyword()? {
            return Err(EP::MultipleDocuments);
        }
        Ok(doc)
    })
}

/// Parse multiple concatenated network documents - **toplevel entrypoint**
pub fn parse_netdoc_multiple<D: NetdocParseable>(
    input: &ParseInput<'_>,
) -> Result<Vec<D>, ParseError> {
    parse_internal::<_, D>(input, |items| {
        let mut docs = vec![];
        while items.peek_keyword()?.is_some() {
            let doc = D::from_items(items, StopAt(false))?;
            docs.push(doc);
        }
        Ok(docs)
    })
}

/// Error from `multi_push_doc`
#[derive(Debug, Error)]
#[error("out of bounds bug")]
struct OutOfBoundsBug;

/// Add `(doc, start_pos, end_pos)` to `docs`, checking bounds
///
/// Helper function for use by `parse_netdoc_ multiple_*` functions that return offsets.
fn multi_push_doc<T>(
    docs: &mut Vec<(T, usize, usize)>,
    input: &ParseInput<'_>,
    doc: T,
    start_pos: usize,
    end_pos: usize,
) -> Result<(), OutOfBoundsBug> {
    // Check start_pos and end_pos are in range.
    if input.input.get(start_pos..end_pos).is_none() {
        return Err(OutOfBoundsBug);
    }

    docs.push((doc, start_pos, end_pos));
    Ok(())
}

/// Parse multiple network documents, also returning their offsets  - **toplevel entrypoint**
///
/// Each returned document is accompanied by the byte offsets of its start and end.
///
/// (The netdoc metaformat does not allow anything in between subsequent documents in a file,
/// so the end of one document is the start of the next.)
///
/// This returns byte offsets rather than string slices,
/// because the caller can always convert the offsets into string slices,
/// but it is not straightforward to convert string slices borrowed from some input string
/// into offsets, in a way that is obviously correct without nightly `str::substr_range`.
///
/// Interfacing code can assume that slicing the input string with the returned
/// [`usize`] values will not cause an out-of-bounds error, meaning runtime
/// checks are not necessary there.
pub fn parse_netdoc_multiple_with_offsets<D: NetdocParseable>(
    input: &ParseInput<'_>,
) -> Result<Vec<(D, usize, usize)>, ParseError> {
    parse_internal::<_, D>(input, |items| {
        let mut docs = vec![];
        while items.peek_keyword()?.is_some() {
            let start_pos = items.byte_position();
            let doc = D::from_items(items, StopAt(false))?;
            let end_pos = items.byte_position();

            multi_push_doc(&mut docs, input, doc, start_pos, end_pos)
                .map_err(|OutOfBoundsBug| ErrorProblem::Internal("out-of-bounds bug?"))?;
        }
        Ok(docs)
    })
}

/// Parse multiple network documents, with error recovery  - **toplevel entrypoint**
///
/// Parses multiple documents.  If an error is encountered, it is returned,
/// and parsing continues with the next document (if possible).
///
/// Each document or error is accompanied by the applicable byte offsets in the input document,
/// as with [`parse_netdoc_multiple_with_offsets`].
#[allow(clippy::type_complexity)] // Yes, the return type is complicated
pub fn parse_netdoc_multiple_sophisticated<D: NetdocParseable>(
    input: &ParseInput<'_>,
) -> Result<Vec<(Result<D, ParseError>, usize, usize)>, Bug> {
    // Largely separate from parse_netdoc_multiple_with_offsets because the differences
    // are control flow; attempts at unifying these led to very confusing code.

    let mut items = ItemStream::new(input);
    let mut docs = vec![];
    let mut push_doc = |doc, start, end| {
        multi_push_doc(&mut docs, input, doc, start, end)
            .map_err(into_internal!("while parsing netdoc sequence"))
    };

    'docs: loop {
        let start_pos = items.byte_position();

        // Insisting on a KeywordRef prevents mistaken omission of code in match arms.
        let _intro_kw: KeywordRef = match items.peek_keyword() {
            Ok(Some(kw)) => kw,
            Ok(None) => break 'docs,
            Err(e) => {
                push_doc(
                    Err(error_handler::<D>(input, &items)(e)),
                    start_pos,
                    items.whole_input().len(),
                )?;
                // can't continue
                break 'docs;
            }
        };

        let doc = D::from_items(&mut items, StopAt(false)) //
            .map_err(error_handler::<D>(input, &items));

        let is_err = doc.is_err();
        let end_pos = items.byte_position();
        push_doc(doc, start_pos, end_pos)?;

        if is_err {
            // Skip the rest of the erroneous document until we find the next intro item.
            //
            // If we get lexical errors during error recovery, we don't *also* report them
            // and instead, just stop processing the input; hence the `.unwrap_or(None)`.
            // (And this is why we insist on `break 'docs`, rather than just break.)
            //
            // Insisting on KeywordRef and UnparsedItem helps prevent mistakes.
            let _next_intro_kw: KeywordRef = 'skip: loop {
                let _discard_item: UnparsedItem = match items.peek_keyword().unwrap_or(None) {
                    None => break 'docs,
                    Some(kw) if D::is_intro_item_keyword(kw) => break 'skip kw,
                    Some(_other_kw) => match items.next().transpose().unwrap_or(None) {
                        Some(item) => item,
                        None => break 'docs,
                    },
                };
            };
        }
    }
    Ok(docs)
}
