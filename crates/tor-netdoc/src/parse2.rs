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
//! We don't parse things into a sorted order.
//! Sorting will be done on output.
// TODO we don't implement deriving output yet.
//!
//! # Types, and signature handling
//!
//! Most top-level network documents are signed somehow.
//! In this case there are three types:
//!
//!   * **`FooSigned`**: a signed `Foo`, with its signatures, not yet verified.
//!     Implements [`NetdocSigned`],
//!     typically by invoking the
//!     [`NetdocSigned` derive macro](crate::derive_deftly_template_NetdocSigned)
//!     on `Foo`.
//!
//!     Type-specific methods are provided for verification,
//!     to obtain a `Foo`.
//!
//!   * **`Foo`**: the body data for the document.
//!     This doesn't contain any signatures.
//!     Having one of these to play with means signatures have already been validated.
//!     Implement `NetdocParseable`, via
//!     [derive](crate::derive_deftly_template_NetdocParseable).
//!
//!   * **`FooSignatures`**: the signatures for a `Foo`.
//!     Implement `NetdocParseable`, via
//!     [derive](crate::derive_deftly_template_NetdocParseable),
//!     with `#[deftly(netdoc(signatures))]`.
//!
//! # Naming conventions
//!
//!   * `DocumentName`: important types,
//!     including network documents or sub-documents,
//!     eg `NetworkStatsuMd` and `RouterVote`,
//!     and types that are generally useful.
//!   * `NddDoucmnetSection`: sections and sub-documents
//!     that the user won't normally need to name.
//!   * `NdiItemValue`: parsed value for a network document Item.
//!     eg `NdiVoteStatus` representing the whole of the RHS of a `vote-status` Item.
//!     Often not needed since `ItemValueParseable` is implemented for suitable tuples.
//!   * `NdaArgumentValue`: parsed value for a single argument;
//!     eg `NdaVoteStatus` representing the `vote` or `status` argument.
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

pub mod poc;

#[cfg(test)]
mod test;

use internal_prelude::*;

pub use error::{ErrorProblem, ParseError, VerifyFailed};
pub use impls::times::NdaSystemTimeDeprecatedSyntax;
pub use keyword::KeywordRef;
pub use lex::{ArgumentStream, ItemStream, NoFurtherArguments, UnparsedItem, UnparsedObject};
pub use lines::{Lines, Peeked, StrExt};
pub use signatures::{
    SignatureHashInputs, SignatureItemParseable, check_validity_time, sig_hash_methods,
};
pub use structural::{StopAt, StopPredicate};
pub use traits::{
    ItemArgumentParseable, ItemObjectParseable, ItemValueParseable, NetdocParseable,
    NetdocParseableFields,
};

#[doc(hidden)]
pub use derive::netdoc_parseable_derive_debug;

//---------- parser ----------

/// Common code for `parse_netdoc` and `parse_netdoc_multiple`
///
/// Creates the `ItemStream`, calls `parse_completely`, and handles errors.
fn parse_internal<T, D: NetdocParseable>(
    input: &str,
    file: &str,
    parse_completely: impl FnOnce(&mut ItemStream) -> Result<T, ErrorProblem>,
) -> Result<T, ParseError> {
    let mut items = ItemStream::new(input)?;
    parse_completely(&mut items).map_err(|problem| ParseError {
        problem,
        doctype: D::doctype_for_error(),
        file: file.to_owned(),
        lno: items.lno_for_error(),
    })
}

/// Parse a network document - **toplevel entrypoint**
pub fn parse_netdoc<D: NetdocParseable>(input: &str, file: &str) -> Result<D, ParseError> {
    parse_internal::<_, D>(input, file, |items| {
        let doc = D::from_items(items, StopAt(false))?;
        if let Some(_kw) = items.peek_keyword()? {
            return Err(EP::MultipleDocuments);
        }
        Ok(doc)
    })
}

/// Parse a network document - **toplevel entrypoint**
pub fn parse_netdoc_multiple<D: NetdocParseable>(
    input: &str,
    file: &str,
) -> Result<Vec<D>, ParseError> {
    parse_internal::<_, D>(input, file, |items| {
        let mut docs = vec![];
        while items.peek_keyword()?.is_some() {
            let doc = D::from_items(items, StopAt(false))?;
            docs.push(doc);
        }
        Ok(docs)
    })
}
