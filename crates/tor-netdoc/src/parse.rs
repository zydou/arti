//! Parsing support for the network document meta-format
//!
//! The meta-format used by Tor network documents evolved over time
//! from a legacy line-oriented format.  It's described more fully
//! in Tor's
//! [dir-spec.txt](https://spec.torproject.org/dir-spec).
//!
//! In brief, a network document is a sequence of [tokenize::Item]s.
//! Each Item starts with a [keyword::Keyword], takes a number of
//! _arguments_ on the same line, and is optionally followed by a
//! PEM-like base64-encoded _object_.
//!
//! Individual document types define further restrictions on the
//! Items.  They may require Items with a particular keyword to have a
//! certain number of arguments, to have (or not have) a particular
//! kind of object, to appear a certain number of times, and so on.
//!
//! More complex documents can be divided into [parser::Section]s.  A
//! Section might correspond to the header or footer of a longer
//! document, or to a single stanza in a longer document.
//!
//! To parse a document into a Section, the programmer defines a type
//! of keyword that the document will use, using the
//! `decl_keyword!` macro.  The programmer then defines a
//! [parser::SectionRules] object, containing a [rules::TokenFmt]
//! describing the rules for each allowed keyword in the
//! section. Finally, the programmer uses a [tokenize::NetDocReader]
//! to tokenize the document, passing the stream of tokens to the
//! SectionRules object to validate and parse it into a Section.
//!
//! For multiple-section documents, this crate uses
//! [`Itertools::peeking_take_while`](itertools::Itertools::peeking_take_while)
//! (via a `[.pause_at`](NetDocReader::pause_at) convenience method)
//! and a [batching_split_before](crate::util::batching_split_before)
//!  module which can split
//! a document item iterator into sections..

pub(crate) mod keyword;
pub(crate) mod parser;
pub(crate) mod rules;
pub(crate) mod tokenize;
#[macro_use]
pub(crate) mod macros;
