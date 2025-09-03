//! Parsing errors
//!
//! # Error philosophy
//!
//! We don't spend a huge amount of effort producing precise and informative errors.
//!
//! We report:
//!
//!  * A line number in the document where the error occurred.
//!    For a problem with an item keyword line, that line is reported.
//!    For an Object, a line somewhere in or just after the object is reported.
//!
//!  * The expected keyword of a missing item.
//!
//!  * The struct field name of a missing or invalid argument.
//!
//!  * The file name (might be a nominal file name)
//!
//!  * What kind of document we were trying to parse.
//!
//! We do not report:
//!
//!  * Column numbers or byte offsets.
//!
//!  * Any more details of the error for syntactically invalid arguments,
//!    bad base64 or bad binary data, etc. (eg we discard the `FromStr::Err`)
//!
//! This saves a good deal of work.

use super::*;

/// Error encountered when parsing a document, including its location
#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("failed to parse network document, type {doctype}: {file}:{lno}: {problem}")]
#[non_exhaustive]
pub struct ParseError {
    /// What the problem was
    #[source]
    pub problem: ErrorProblem,
    /// The document type, from `NetdocParseable::doctype_for_error`
    pub doctype: &'static str,
    /// Where the document came from, in human-readable form, filename or `<...>`
    pub file: String,
    /// Line number
    pub lno: usize,
}

/// Problem found when parsing a document
///
/// Just the nature of the problem, including possibly which field or argument
/// if that's necessary to disambiguate, but not including location in the document.
///
/// We are quite minimal:
/// we do not report the `Display` of argument parse errors, for example.
#[derive(Error, Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorProblem {
    /// Empty document
    #[error("empty document")]
    EmptyDocument,
    /// Wrong document type
    #[error("wrong document type")]
    WrongDocumentType,
    /// Multiple top-level documents
    #[error("multiple top-level documents")]
    MultipleDocuments,
    /// Item missing required base64-encoded Object
    #[error("item missing required base64-encoded Object")]
    MissingObject,
    /// Item repeated when not allowed
    #[error("item repeated when not allowed")]
    ItemRepeated,
    /// Item forbidden (in this kind of document or location)
    #[error("item forbidden (in this kind of document or location)")]
    ItemForbidden,
    /// Item repeated when not allowed
    #[error("item repeated when not allowed")]
    ItemMisplacedAfterSignature,
    /// Document contains nul byte
    #[error("document contains nul byte")]
    NulByte,
    /// Item keyword line starts with whitespace
    #[error("item keyword line starts with whitespace")]
    KeywordLineStartsWithWhitespace,
    /// No keyword when item keyword line expected
    #[error("no keyword when item keyword line expected")]
    MissingKeyword,
    /// No keyword when item keyword line expected
    #[error("no keyword when item keyword line expected: {0}")]
    InvalidKeyword(#[from] keyword::InvalidKeyword),
    /// Missing item {keyword}
    #[error("missing item {keyword}")]
    MissingItem {
        /// Keyword for item that was missing
        keyword: &'static str,
    },
    /// Missing argument {field}
    #[error("missing argument {field}")]
    MissingArgument {
        /// Field name for argument that was missing
        field: &'static str,
    },
    /// Invalid value for argument {field}
    #[error("invalid value for argument {field}")]
    InvalidArgument {
        /// Field name for argument that had invalid value
        field: &'static str,
    },
    /// Unexpected additional argument(s)
    #[error("too many arguments")]
    UnexpectedArgument,
    /// Base64-encoded Object footer not found
    #[error("base64-encoded Object footer not found")]
    ObjectMissingFooter,
    /// Base64-encoded Object END label does not match BEGIN
    #[error("base64-encoded Object END label does not match BEGIN")]
    ObjectMismatchedLabels,
    /// Base64-encoded Object END label does not match BEGIN
    #[error("base64-encoded Object label is not as expected")]
    ObjectIncorrectLabel,
    /// Base64-encoded Object has incorrectly formatted delimiter lines
    #[error("base64-encoded Object has incorrectly formatted delimiter lines")]
    InvalidObjectDelimiters,
    /// Base64-encoded Object found where none expected
    #[error("base64-encoded Object found where none expected")]
    ObjectUnexpected,
    /// Base64-encoded Object contains invalid base64
    #[error("base64-encoded Object contains invalid base64")]
    ObjectInvalidBase64,
    /// Base64-encoded Object contains valid base64 specifying invalid data
    #[error("base64-encoded Object contains invalid data")]
    ObjectInvalidData,
    /// Other parsing proble
    #[error("other problem: {0}")]
    Other(&'static str),
}

/// Error from signature verification (and timeliness check)
#[derive(Error, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum VerifyFailed {
    /// Signature verification failed
    #[error("netdoc signature verification failed")]
    VerifyFailed,
    /// Document is too new - clock skew?
    #[error("document is too new - clock skew?")]
    TooNew,
    /// Document is too old
    #[error("document is too old")]
    TooOld,
    /// Document not signed by the right testator (or too few known testators)
    #[error("document not signed by the right testator (or too few known testators)")]
    InsufficientTrustedSigners,
    /// document has inconsistent content
    #[error("document has inconsistent content")]
    Inconsistent,
    /// Something else is wrong
    #[error("document has uncategorised problem found during verification")]
    Other,
}

impl From<signature::Error> for VerifyFailed {
    fn from(_: signature::Error) -> VerifyFailed {
        VerifyFailed::VerifyFailed
    }
}
