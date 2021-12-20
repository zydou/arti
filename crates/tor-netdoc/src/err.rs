//! Error type from parsing a document, and the position where it occurred
use thiserror::Error;

use crate::types::policy::PolicyError;
use std::fmt;

/// A position within a directory object. Used to tell where an error
/// occurred.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Pos {
    /// The error did not occur at any particular position.
    ///
    /// This can happen when the error is something like a missing entry:
    /// the entry is supposed to go _somewhere_, but we can't say where.
    None,
    /// The error occurred at an unknown position.
    ///
    /// We should avoid using this case.
    Unknown,
    /// The error occurred at an invalid offset within the string, or
    /// outside the string entirely.
    ///
    /// This can only occur because of an internal error of some kind.
    Invalid(usize),
    /// The error occurred at a particular byte within the string.
    ///
    /// We try to convert these to a Pos before displaying them to the user.
    Byte {
        /// Byte offset within a string.
        off: usize,
    },
    /// The error occurred at a particular line (and possibly at a
    /// particular byte within the line.)
    PosInLine {
        /// Line offset within a string.
        line: usize,
        /// Byte offset within the line.
        byte: usize,
    },
    /// The error occurred at a position in memory.  This shouldn't be
    /// exposed to the user, but rather should be mapped to a position
    /// in the string.
    Raw {
        /// A raw pointer to the position where the error occurred.
        ptr: *const u8,
    },
}

// It's okay to send a Pos to another thread, even though its Raw
// variant contains a pointer. That's because we never dereference the
// pointer: we only compare it to another pointer representing a
// string.
//
// TODO: Find a better way to have Pos work.
unsafe impl Send for Pos {}
unsafe impl Sync for Pos {}

impl Pos {
    /// Construct a Pos from an offset within a &str slice.
    pub fn from_offset(s: &str, off: usize) -> Self {
        if off > s.len() || !s.is_char_boundary(off) {
            Pos::Invalid(off)
        } else {
            let s = &s[..off];
            let last_nl = s.rfind('\n');
            match last_nl {
                Some(pos) => {
                    let newlines = s.bytes().filter(|b| *b == b'\n').count();
                    Pos::PosInLine {
                        line: newlines + 1,
                        byte: off - pos,
                    }
                }
                None => Pos::PosInLine {
                    line: 1,
                    byte: off + 1,
                },
            }
        }
    }
    /// Construct a Pos from a slice of some other string.  This
    /// Pos won't be terribly helpful, but it may be converted
    /// into a useful Pos with `within`.
    pub fn at(s: &str) -> Self {
        let ptr = s.as_ptr();
        Pos::Raw { ptr }
    }
    /// Construct Pos from the end of some other string.
    pub fn at_end_of(s: &str) -> Self {
        let ending = &s[s.len()..];
        Pos::at(ending)
    }
    /// Construct a position from a byte offset.
    pub fn from_byte(off: usize) -> Self {
        Pos::Byte { off }
    }
    /// Construct a position from a line and a byte offset within that line.
    pub fn from_line(line: usize, byte: usize) -> Self {
        Pos::PosInLine { line, byte }
    }
    /// If this position appears within `s`, and has not yet been mapped to
    /// a line-and-byte position, return its offset.
    pub(crate) fn offset_within(&self, s: &str) -> Option<usize> {
        match self {
            Pos::Byte { off } => Some(*off),
            Pos::Raw { ptr } => offset_in(*ptr, s),
            _ => None,
        }
    }
    /// Given a position, if it was at a byte offset, convert it to a
    /// line-and-byte position within `s`.
    ///
    /// Requires that this position was actually generated from `s`.
    /// If it was not, the results here may be nonsensical.
    ///
    /// TODO: I wish I knew an efficient safe way to do this that
    /// guaranteed that we we always talking about the right string.
    #[must_use]
    pub fn within(self, s: &str) -> Self {
        match self {
            Pos::Byte { off } => Self::from_offset(s, off),
            Pos::Raw { ptr } => {
                if let Some(off) = offset_in(ptr, s) {
                    Self::from_offset(s, off)
                } else {
                    self
                }
            }
            _ => self,
        }
    }
}

/// If `ptr` is within `s`, return its byte offset.
fn offset_in(ptr: *const u8, s: &str) -> Option<usize> {
    // We need to confirm that 'ptr' falls within 's' in order
    // to subtract it meaningfully and find its offset.
    // Otherwise, we'll get a bogus result.
    //
    // Fortunately, we _only_ get a bogus result: we don't
    // hit unsafe behavior.
    let ptr_u = ptr as usize;
    let start_u = s.as_ptr() as usize;
    let end_u = (s.as_ptr() as usize) + s.len();
    if start_u <= ptr_u && ptr_u < end_u {
        Some(ptr_u - start_u)
    } else {
        None
    }
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Pos::*;
        match self {
            None => write!(f, ""),
            Unknown => write!(f, " at unknown position"),
            Invalid(off) => write!(f, " at invalid offset at index {}", off),
            Byte { off } => write!(f, " at byte {}", off),
            PosInLine { line, byte } => write!(f, " on line {}, byte {}", line, byte),
            Raw { ptr } => write!(f, " at {:?}", ptr),
        }
    }
}

/// An error that occurred while parsing a directory object of some kind.
#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// An internal error in the parser: these should never happen.
    #[error("internal error{0}")]
    Internal(Pos), // TODO string.
    /// An entry was found with no keyword.
    #[error("no keyword for entry{0}")]
    MissingKeyword(Pos),
    /// An entry was found with no newline at the end.
    #[error("line truncated before newline{0}")]
    TruncatedLine(Pos),
    /// A bad string was found in the keyword position.
    #[error("invalid keyword{0}")]
    BadKeyword(Pos),
    /// We found an ill-formed "BEGIN FOO" tag.
    #[error("invalid PEM BEGIN tag{0}")]
    BadObjectBeginTag(Pos),
    /// We found an ill-formed "END FOO" tag.
    #[error("invalid PEM END tag{0}")]
    BadObjectEndTag(Pos),
    /// We found a "BEGIN FOO" tag with an "END FOO" tag that didn't match.
    #[error("mismatched PEM tags{0}")]
    BadObjectMismatchedTag(Pos),
    /// We found a base64 object with an invalid base64 encoding.
    #[error("invalid base64 in object around byte {0}")]
    BadObjectBase64(Pos),
    /// The document is not supposed to contain more than one of some
    /// kind of entry, but we found one anyway.
    #[error("duplicate entry for {0}{1}")]
    DuplicateToken(&'static str, Pos),
    /// The document is not supposed to contain any of some particular kind
    /// of entry, but we found one anyway.
    #[error("entry {0} unexpected{1}")]
    UnexpectedToken(&'static str, Pos),
    /// The document is supposed to contain any of some particular kind
    /// of entry, but we didn't find one one anyway.
    #[error("didn't find required entry {0}")]
    MissingToken(&'static str),
    /// The document was supposed to have one of these, but not where we
    /// found it.
    #[error("found {0} out of place{1}")]
    MisplacedToken(&'static str, Pos),
    /// We found more arguments on an entry than it is allowed to have.
    #[error("too many arguments for {0}{1}")]
    TooManyArguments(&'static str, Pos),
    /// We didn't fine enough arguments for some entry.
    #[error("too few arguments for {0}{1}")]
    TooFewArguments(&'static str, Pos),
    /// We found an object attached to an entry that isn't supposed to
    /// have one.
    #[error("unexpected object for {0}{1}")]
    UnexpectedObject(&'static str, Pos),
    /// An entry was supposed to have an object, but it didn't.
    #[error("missing object for {0}{1}")]
    MissingObject(&'static str, Pos),
    /// We found an object on an entry, but the type was wrong.
    #[error("wrong object type for entry{0}")]
    WrongObject(Pos),
    /// We tried to find an argument that we were sure would be there,
    /// but it wasn't!
    ///
    /// This error should never occur in correct code; it should be
    /// caught earlier by TooFewArguments.
    #[error("missing argument for entry{0}")]
    MissingArgument(Pos),
    /// We found an argument that couldn't be parsed.
    #[error("bad argument for entry{0}: {1}")]
    BadArgument(Pos, String),
    /// We found an object that couldn't be parsed after it was decoded.
    #[error("bad object for entry{0}: {1}")]
    BadObjectVal(Pos, String),
    /// There was some signature that we couldn't validate.
    #[error("couldn't validate signature{0}")]
    BadSignature(Pos), // TODO(nickm): say which kind of signature.
    /// There was a tor version we couldn't parse.
    #[error("couldn't parse Tor version{0}")]
    BadTorVersion(Pos),
    /// There was an ipv4 or ipv6 policy entry that we couldn't parse.
    #[error("invalid policy entry{0}: {1}")]
    BadPolicy(Pos, #[source] PolicyError),
    /// An object was expired or not yet valid.
    #[error("untimely object{0}: {1}")]
    Untimely(Pos, #[source] tor_checkable::TimeValidityError),
    /// An underlying byte sequence couldn't be decoded.
    #[error("decoding error{0}: {1}")]
    Undecodable(Pos, #[source] tor_bytes::Error),
    /// Versioned document with an unrecognized version.
    #[error("unrecognized document version {0}")]
    BadDocumentVersion(u32),
    /// Unexpected document type
    #[error("unexpected document type")]
    BadDocumentType,
    /// Document or section started with wrong token
    #[error("Wrong starting token {0}{1}")]
    WrongStartingToken(String, Pos),
    /// Document or section ended with wrong token
    #[error("Wrong ending token {0}{1}")]
    WrongEndingToken(String, Pos),
    /// Items not sorted as expected
    #[error("Incorrect sort order{0}")]
    WrongSortOrder(Pos),
    /// A consensus lifetime was ill-formed.
    #[error("Invalid consensus lifetime")]
    InvalidLifetime,
    /// We're unable to finish building an object, for some reason.
    #[error("Unable to construct object: {0}")]
    CannotBuild(&'static str),
}

impl Error {
    /// Helper: return a mutable reference to this error's position (if any)
    fn pos_mut(&mut self) -> Option<&mut Pos> {
        use Error::*;
        match self {
            Internal(p) => Some(p),
            MissingKeyword(p) => Some(p),
            TruncatedLine(p) => Some(p),
            BadKeyword(p) => Some(p),
            BadObjectBeginTag(p) => Some(p),
            BadObjectEndTag(p) => Some(p),
            BadObjectMismatchedTag(p) => Some(p),
            BadObjectBase64(p) => Some(p),
            DuplicateToken(_, p) => Some(p),
            UnexpectedToken(_, p) => Some(p),
            MissingToken(_) => None,
            MisplacedToken(_, p) => Some(p),
            TooManyArguments(_, p) => Some(p),
            TooFewArguments(_, p) => Some(p),
            UnexpectedObject(_, p) => Some(p),
            MissingObject(_, p) => Some(p),
            WrongObject(p) => Some(p),
            MissingArgument(p) => Some(p),
            BadArgument(p, _) => Some(p),
            BadObjectVal(p, _) => Some(p),
            BadSignature(p) => Some(p),
            BadTorVersion(p) => Some(p),
            BadPolicy(p, _) => Some(p),
            Untimely(p, _) => Some(p),
            Undecodable(p, _) => Some(p),
            BadDocumentVersion(_) => None,
            BadDocumentType => None,
            WrongStartingToken(_, p) => Some(p),
            WrongEndingToken(_, p) => Some(p),
            WrongSortOrder(p) => Some(p),
            InvalidLifetime => None,
            CannotBuild(_) => None,
        }
    }

    /// Helper: return this error's position.
    pub(crate) fn pos(&self) -> Pos {
        // TODO(nickm): This duplicate code is yucky. We should
        // refactor this error type to use an ErrorKind pattern.
        use Error::*;
        let pos = match self {
            Internal(p) => Some(p),
            MissingKeyword(p) => Some(p),
            TruncatedLine(p) => Some(p),
            BadKeyword(p) => Some(p),
            BadObjectBeginTag(p) => Some(p),
            BadObjectEndTag(p) => Some(p),
            BadObjectMismatchedTag(p) => Some(p),
            BadObjectBase64(p) => Some(p),
            DuplicateToken(_, p) => Some(p),
            UnexpectedToken(_, p) => Some(p),
            MissingToken(_) => None,
            MisplacedToken(_, p) => Some(p),
            TooManyArguments(_, p) => Some(p),
            TooFewArguments(_, p) => Some(p),
            UnexpectedObject(_, p) => Some(p),
            MissingObject(_, p) => Some(p),
            WrongObject(p) => Some(p),
            MissingArgument(p) => Some(p),
            BadArgument(p, _) => Some(p),
            BadObjectVal(p, _) => Some(p),
            BadSignature(p) => Some(p),
            BadTorVersion(p) => Some(p),
            BadPolicy(p, _) => Some(p),
            Untimely(p, _) => Some(p),
            Undecodable(p, _) => Some(p),
            BadDocumentVersion(_) => None,
            BadDocumentType => None,
            WrongStartingToken(_, p) => Some(p),
            WrongEndingToken(_, p) => Some(p),
            WrongSortOrder(p) => Some(p),
            InvalidLifetime => None,
            CannotBuild(_) => None,
        };
        *pos.unwrap_or(&Pos::Unknown)
    }

    /// Return a new error based on this one, with any byte-based
    /// position mapped to some line within a string.
    #[must_use]
    pub fn within(mut self, s: &str) -> Error {
        if let Some(p) = self.pos_mut() {
            *p = p.within(s);
        }
        self
    }

    /// Return a new error based on this one, with the position (if
    /// any) replaced by 'p'.
    #[must_use]
    pub fn at_pos(mut self, p: Pos) -> Error {
        if let Some(mypos) = self.pos_mut() {
            *mypos = p;
        }
        self
    }

    /// Return a new error based on this one, with the position (if
    /// replaced by 'p' if it had no position before.
    #[must_use]
    pub fn or_at_pos(mut self, p: Pos) -> Error {
        if let Some(mypos) = self.pos_mut() {
            if *mypos == Pos::None {
                *mypos = p;
            }
        }
        self
    }
}

/// Create a From<> implementation to construct an Error::BadArgument
/// from another error type.
macro_rules! derive_from_err{
    { $etype:ty } => {
        impl From<$etype> for Error {
            fn from(e: $etype) -> Error {
                Error::BadArgument(Pos::None, e.to_string())
            }
        }
    }
}
derive_from_err! {std::num::ParseIntError}
derive_from_err! {std::net::AddrParseError}

impl From<crate::types::policy::PolicyError> for Error {
    fn from(e: crate::types::policy::PolicyError) -> Error {
        Error::BadPolicy(Pos::None, e)
    }
}

impl From<tor_bytes::Error> for Error {
    fn from(e: tor_bytes::Error) -> Error {
        Error::Undecodable(Pos::None, e)
    }
}

impl From<tor_checkable::TimeValidityError> for Error {
    fn from(e: tor_checkable::TimeValidityError) -> Error {
        Error::Untimely(Pos::None, e)
    }
}

impl From<signature::Error> for Error {
    fn from(_e: signature::Error) -> Error {
        Error::BadSignature(Pos::None)
    }
}
