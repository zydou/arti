//! Break a string into a set of directory-object Items.
//!
//! This module defines Item, which represents a basic entry in a
//! directory document, and NetDocReader, which is used to break a
//! string into Items.

use crate::parse::keyword::Keyword;
use crate::types::misc::FromBytes;
use crate::util::PeekableIterator;
use crate::{Error, NetdocErrorKind as EK, Pos, Result};
use base64ct::{Base64, Encoding};
use itertools::Itertools;
use std::cell::{Ref, RefCell};
use std::iter::Peekable;
use std::str::FromStr;
use tor_error::internal;

/// Useful constants for netdoc object syntax
pub(crate) mod object {
    /// indicates the start of an object
    pub(crate) const BEGIN_STR: &str = "-----BEGIN ";
    /// indicates the end of an object
    pub(crate) const END_STR: &str = "-----END ";
    /// indicates the end of a begin or end tag.
    pub(crate) const TAG_END: &str = "-----";
    /// Maximum PEM base64 line length (not enforced during parsing)
    #[cfg(feature = "hs-service")]
    pub(crate) const BASE64_PEM_MAX_LINE: usize = 64;
}

/// Return true iff a given character is "space" according to the rules
/// of dir-spec.txt
pub(crate) fn is_sp(c: char) -> bool {
    c == ' ' || c == '\t'
}
/// Check that all the characters in `s` are valid base64.
///
/// This is not a perfect check for base64ness -- it is mainly meant
/// to help us recover after unterminated base64.
fn b64check(s: &str) -> Result<()> {
    for b in s.bytes() {
        match b {
            b'=' => (),
            b'a'..=b'z' => (),
            b'A'..=b'Z' => (),
            b'0'..=b'9' => (),
            b'/' | b'+' => (),
            _ => {
                return Err(EK::BadObjectBase64.at_pos(Pos::at(s)));
            }
        };
    }
    Ok(())
}

/// A tagged object that is part of a directory Item.
///
/// This represents a single blob within a pair of "-----BEGIN
/// FOO-----" and "-----END FOO-----".  The data is not guaranteed to
/// be actual base64 when this object is created: doing so would
/// require either that we parse the base64 twice, or that we allocate
/// a buffer to hold the data before it's needed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Object<'a> {
    /// Reference to the "tag" string (the 'foo') in the BEGIN line.
    tag: &'a str,
    /// Reference to the allegedly base64-encoded data.  This may or
    /// may not actually be base64 at this point.
    data: &'a str,
    /// Reference to the END line for this object.  This doesn't
    /// need to be parsed, but it's used to find where this object
    /// ends.
    endline: &'a str,
}

/// A single part of a directory object.
///
/// Each Item -- called an "entry" in dir-spec.txt -- has a keyword, a
/// (possibly empty) set of arguments, and an optional object.
///
/// This is a zero-copy implementation that points to slices within a
/// containing string.
#[derive(Clone, Debug)]
pub(crate) struct Item<'a, K: Keyword> {
    /// The keyword that determines the type of this item.
    kwd: K,
    /// A reference to the actual string that defines the keyword for
    /// this item.
    kwd_str: &'a str,
    /// Reference to the arguments that appear in the same line after the
    /// keyword.  Does not include the terminating newline or the
    /// space that separates the keyword for its arguments.
    args: &'a str,
    /// The arguments, split by whitespace.  This vector is constructed
    /// as needed, using interior mutability.
    split_args: RefCell<Option<Vec<&'a str>>>,
    /// If present, a base-64-encoded object that appeared at the end
    /// of this item.
    object: Option<Object<'a>>,
}

/// A cursor into a string that returns Items one by one.
///
/// (This type isn't used directly, but is returned wrapped in a Peekable.)
#[derive(Debug)]
struct NetDocReaderBase<'a, K: Keyword> {
    /// The string we're parsing.
    s: &'a str,
    /// Our position within the string.
    off: usize,
    /// Tells Rust it's okay that we are parameterizing on K.
    _k: std::marker::PhantomData<K>,
}

impl<'a, K: Keyword> NetDocReaderBase<'a, K> {
    /// Create a new NetDocReader to split a string into tokens.
    fn new(s: &'a str) -> Self {
        NetDocReaderBase {
            s,
            off: 0,
            _k: std::marker::PhantomData,
        }
    }
    /// Return the current Pos within the string.
    fn pos(&self, pos: usize) -> Pos {
        Pos::from_offset(self.s, pos)
    }
    /// Skip forward by n bytes.
    ///
    /// (Note that standard caveats with byte-oriented processing of
    /// UTF-8 strings apply.)
    fn advance(&mut self, n: usize) -> Result<()> {
        if n > self.remaining() {
            return Err(
                Error::from(internal!("tried to advance past end of document"))
                    .at_pos(Pos::from_offset(self.s, self.off)),
            );
        }
        self.off += n;
        Ok(())
    }
    /// Return the remaining number of bytes in this reader.
    fn remaining(&self) -> usize {
        self.s.len() - self.off
    }

    /// Return true if the next characters in this reader are `s`
    fn starts_with(&self, s: &str) -> bool {
        self.s[self.off..].starts_with(s)
    }
    /// Try to extract a NL-terminated line from this reader.  Always
    /// remove data if the reader is nonempty.
    fn line(&mut self) -> Result<&'a str> {
        let remainder = &self.s[self.off..];
        if let Some(nl_pos) = remainder.find('\n') {
            self.advance(nl_pos + 1)?;
            let line = &remainder[..nl_pos];

            // TODO: we should probably detect \r and do something about it.
            // Just ignoring it isn't the right answer, though.
            Ok(line)
        } else {
            self.advance(remainder.len())?; // drain everything.
            Err(EK::TruncatedLine.at_pos(self.pos(self.s.len())))
        }
    }

    /// Try to extract a line that begins with a keyword from this reader.
    ///
    /// Returns a (kwd, args) tuple on success.
    fn kwdline(&mut self) -> Result<(&'a str, &'a str)> {
        let pos = self.off;
        let line = self.line()?;
        if line.is_empty() {
            return Err(EK::EmptyLine.at_pos(self.pos(pos)));
        }
        let (line, anno_ok) = if let Some(rem) = line.strip_prefix("opt ") {
            (rem, false)
        } else {
            (line, true)
        };
        let mut parts_iter = line.splitn(2, |c| c == ' ' || c == '\t');
        let kwd = match parts_iter.next() {
            Some(k) => k,
            // This case seems like it can't happen: split always returns
            // something, apparently.
            None => return Err(EK::MissingKeyword.at_pos(self.pos(pos))),
        };
        if !keyword_ok(kwd, anno_ok) {
            return Err(EK::BadKeyword.at_pos(self.pos(pos)));
        }
        // TODO(nickm): dir-spec does not yet allow unicode in the arguments, but we're
        // assuming that proposal 285 is accepted.
        let args = match parts_iter.next() {
            Some(a) => a,
            // take a zero-length slice, so it will be within the string.
            None => &kwd[kwd.len()..],
        };
        Ok((kwd, args))
    }

    /// Try to extract an Object beginning wrapped within BEGIN/END tags.
    ///
    /// Returns Ok(Some(Object(...))) on success if an object is
    /// found, Ok(None) if no object is found, and Err only if a
    /// corrupt object is found.
    fn object(&mut self) -> Result<Option<Object<'a>>> {
        use object::*;

        let pos = self.off;
        if !self.starts_with(BEGIN_STR) {
            return Ok(None);
        }
        let line = self.line()?;
        if !line.ends_with(TAG_END) {
            return Err(EK::BadObjectBeginTag.at_pos(self.pos(pos)));
        }
        let tag = &line[BEGIN_STR.len()..(line.len() - TAG_END.len())];
        if !tag_keywords_ok(tag) {
            return Err(EK::BadObjectBeginTag.at_pos(self.pos(pos)));
        }
        let datapos = self.off;
        let (endlinepos, endline) = loop {
            let p = self.off;
            let line = self.line()?;
            if line.starts_with(END_STR) {
                break (p, line);
            }
            // Exit if this line isn't plausible base64.  Otherwise,
            // an unterminated base64 block could potentially
            // "consume" all the rest of the string, which would stop
            // us from recovering.
            b64check(line).map_err(|e| e.within(self.s))?;
        };
        let data = &self.s[datapos..endlinepos];
        if !endline.ends_with(TAG_END) {
            return Err(EK::BadObjectEndTag.at_pos(self.pos(endlinepos)));
        }
        let endtag = &endline[END_STR.len()..(endline.len() - TAG_END.len())];
        if endtag != tag {
            return Err(EK::BadObjectMismatchedTag.at_pos(self.pos(endlinepos)));
        }
        Ok(Some(Object { tag, data, endline }))
    }

    /// Read the next Item from this NetDocReaderBase.
    ///
    /// If successful, returns Ok(Some(Item)), or Ok(None) if exhausted.
    /// Returns Err on failure.
    ///
    /// Always consumes at least one line if possible; always ends on a
    /// line boundary if one exists.
    fn item(&mut self) -> Result<Option<Item<'a, K>>> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let (kwd_str, args) = self.kwdline()?;
        let object = self.object()?;
        let split_args = RefCell::new(None);
        let kwd = K::from_str(kwd_str);
        Ok(Some(Item {
            kwd,
            kwd_str,
            args,
            split_args,
            object,
        }))
    }
}

/// Return true iff 's' is a valid keyword or annotation.
///
/// (Only allow annotations if `anno_ok` is true.`
fn keyword_ok(mut s: &str, anno_ok: bool) -> bool {
    /// Helper: return true if this character can appear in keywords.
    fn kwd_char_ok(c: char) -> bool {
        matches!(c,'A'..='Z' | 'a'..='z' |'0'..='9' | '-')
    }

    if s.is_empty() {
        return false;
    }
    if anno_ok && s.starts_with('@') {
        s = &s[1..];
    }
    if s.starts_with('-') {
        return false;
    }
    s.chars().all(kwd_char_ok)
}

/// Return true iff 's' is a valid keywords string for a BEGIN/END tag.
pub(crate) fn tag_keywords_ok(s: &str) -> bool {
    s.split(' ').all(|w| keyword_ok(w, false))
}

/// When used as an Iterator, returns a sequence of `Result<Item>`.
impl<'a, K: Keyword> Iterator for NetDocReaderBase<'a, K> {
    type Item = Result<Item<'a, K>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.item().transpose()
    }
}

/// Helper: as base64::decode(), but allows newlines in the middle of the
/// encoded object.
fn base64_decode_multiline(s: &str) -> std::result::Result<Vec<u8>, base64ct::Error> {
    // base64 module hates whitespace.
    let mut s = s.to_string();
    s.retain(|ch| ch != '\n');
    let v = Base64::decode_vec(&s)?;
    Ok(v)
}

impl<'a, K: Keyword> Item<'a, K> {
    /// Return the parsed keyword part of this item.
    pub(crate) fn kwd(&self) -> K {
        self.kwd
    }
    /// Return the keyword part of this item, as a string.
    pub(crate) fn kwd_str(&self) -> &'a str {
        self.kwd_str
    }
    /// Return true if the keyword for this item is in 'ks'.
    pub(crate) fn has_kwd_in(&self, ks: &[K]) -> bool {
        ks.contains(&self.kwd)
    }
    /// Return the arguments of this item, as a single string.
    pub(crate) fn args_as_str(&self) -> &'a str {
        self.args
    }
    /// Return the arguments of this item as a vector.
    fn args_as_vec(&self) -> Ref<'_, Vec<&'a str>> {
        // We're using an interior mutability pattern here to lazily
        // construct the vector.
        if self.split_args.borrow().is_none() {
            self.split_args.replace(Some(self.args().collect()));
        }
        Ref::map(self.split_args.borrow(), |opt| match opt {
            Some(v) => v,
            None => panic!(),
        })
    }
    /// Return an iterator over the arguments of this item.
    pub(crate) fn args(&self) -> impl Iterator<Item = &'a str> {
        self.args.split(is_sp).filter(|s| !s.is_empty())
    }
    /// Return the nth argument of this item, if there is one.
    pub(crate) fn arg(&self, idx: usize) -> Option<&'a str> {
        self.args_as_vec().get(idx).copied()
    }
    /// Return the nth argument of this item, or an error if it isn't there.
    pub(crate) fn required_arg(&self, idx: usize) -> Result<&'a str> {
        self.arg(idx)
            .ok_or_else(|| EK::MissingArgument.at_pos(Pos::at(self.args)))
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Returns Ok(None) if the argument doesn't exist.
    pub(crate) fn parse_optional_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.arg(idx) {
            None => Ok(None),
            Some(s) => match s.parse() {
                Ok(r) => Ok(Some(r)),
                Err(e) => {
                    let e: Error = e.into();
                    Err(e.or_at_pos(Pos::at(s)))
                }
            },
        }
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Return an error if the argument doesn't exist.
    pub(crate) fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<V>
    where
        Error: From<V::Err>,
    {
        match self.parse_optional_arg(idx) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(EK::MissingArgument.at_pos(self.arg_pos(idx))),
            Err(e) => Err(e),
        }
    }
    /// Return the number of arguments for this Item
    pub(crate) fn n_args(&self) -> usize {
        self.args().count()
    }
    /// Return true iff this Item has an associated object.
    pub(crate) fn has_obj(&self) -> bool {
        self.object.is_some()
    }
    /// Return the tag of this item's associated object, if it has one.
    pub(crate) fn obj_tag(&self) -> Option<&'a str> {
        self.object.map(|o| o.tag)
    }
    /// Try to decode the base64 contents of this Item's associated object.
    ///
    /// On success, return the object's tag and decoded contents.
    pub(crate) fn obj_raw(&self) -> Result<Option<(&'a str, Vec<u8>)>> {
        match self.object {
            None => Ok(None),
            Some(obj) => {
                let decoded = base64_decode_multiline(obj.data)
                    .map_err(|_| EK::BadObjectBase64.at_pos(Pos::at(obj.data)))?;
                Ok(Some((obj.tag, decoded)))
            }
        }
    }
    /// Try to decode the base64 contents of this Item's associated object,
    /// and make sure that its tag matches 'want_tag'.
    pub(crate) fn obj(&self, want_tag: &str) -> Result<Vec<u8>> {
        match self.obj_raw()? {
            None => Err(EK::MissingObject
                .with_msg(self.kwd.to_str())
                .at_pos(self.end_pos())),
            Some((tag, decoded)) => {
                if tag != want_tag {
                    Err(EK::WrongObject.at_pos(Pos::at(tag)))
                } else {
                    Ok(decoded)
                }
            }
        }
    }
    /// Try to decode the base64 contents of this item's associated object
    /// as a given type that implements FromBytes.
    pub(crate) fn parse_obj<V: FromBytes>(&self, want_tag: &str) -> Result<V> {
        let bytes = self.obj(want_tag)?;
        // Unwrap may be safe because above `.obj()` should return an Error if
        // wanted tag was not present
        #[allow(clippy::unwrap_used)]
        let p = Pos::at(self.object.unwrap().data);
        V::from_vec(bytes, p).map_err(|e| e.at_pos(p))
    }
    /// Return the position of this item.
    ///
    /// This position won't be useful unless it is later contextualized
    /// with the containing string.
    pub(crate) fn pos(&self) -> Pos {
        Pos::at(self.kwd_str)
    }
    /// Return the position of this Item in a string.
    ///
    /// Returns None if this item doesn't actually belong to the string.
    pub(crate) fn offset_in(&self, s: &str) -> Option<usize> {
        crate::util::str::str_offset(s, self.kwd_str)
    }
    /// Return the position of the n'th argument of this item.
    ///
    /// If this item does not have a n'th argument, return the
    /// position of the end of the final argument.
    pub(crate) fn arg_pos(&self, n: usize) -> Pos {
        let args = self.args_as_vec();
        if n < args.len() {
            Pos::at(args[n])
        } else {
            self.last_arg_end_pos()
        }
    }
    /// Return the position at the end of the last argument.  (This will
    /// point to a newline.)
    fn last_arg_end_pos(&self) -> Pos {
        let args = self.args_as_vec();
        if args.len() >= 1 {
            let last_arg = args[args.len() - 1];
            Pos::at_end_of(last_arg)
        } else {
            Pos::at_end_of(self.kwd_str)
        }
    }
    /// Return the position of the end of this object. (This will point to a
    /// newline.)
    pub(crate) fn end_pos(&self) -> Pos {
        match self.object {
            Some(o) => Pos::at_end_of(o.endline),
            None => self.last_arg_end_pos(),
        }
    }
    /// If this item occurs within s, return the byte offset
    /// immediately after the end of this item.
    pub(crate) fn offset_after(&self, s: &str) -> Option<usize> {
        self.end_pos().offset_within(s).map(|nl_pos| nl_pos + 1)
    }
}

/// Represents an Item that might not be present, whose arguments we
/// want to inspect.  If the Item is there, this acts like a proxy to the
/// item; otherwise, it treats the item as having no arguments.
pub(crate) struct MaybeItem<'a, 'b, K: Keyword>(Option<&'a Item<'b, K>>);

// All methods here are as for Item.
impl<'a, 'b, K: Keyword> MaybeItem<'a, 'b, K> {
    /// Return the position of this item, if it has one.
    fn pos(&self) -> Pos {
        match self.0 {
            Some(item) => item.pos(),
            None => Pos::None,
        }
    }
    /// Construct a MaybeItem from an Option reference to an item.
    pub(crate) fn from_option(opt: Option<&'a Item<'b, K>>) -> Self {
        MaybeItem(opt)
    }

    /// If this item is present, parse its argument at position `idx`.
    /// Treat the absence or malformedness of the argument as an error,
    /// but treat the absence of this item as acceptable.
    #[cfg(any(test, feature = "routerdesc"))]
    pub(crate) fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => match item.parse_arg(idx) {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(e.or_at_pos(self.pos())),
            },
            None => Ok(None),
        }
    }
    /// If this item is present, return its arguments as a single string.
    pub(crate) fn args_as_str(&self) -> Option<&str> {
        self.0.map(|item| item.args_as_str())
    }
    /// If this item is present, parse all of its arguments as a
    /// single string.
    pub(crate) fn parse_args_as_str<V: FromStr>(&self) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => match item.args_as_str().parse::<V>() {
                Ok(v) => Ok(Some(v)),
                Err(e) => {
                    let e: Error = e.into();
                    Err(e.or_at_pos(self.pos()))
                }
            },
            None => Ok(None),
        }
    }
}

/// Extension trait for `Result<Item>` -- makes it convenient to implement
/// PauseAt predicates
pub(crate) trait ItemResult<K: Keyword> {
    /// Return true if this is an ok result with an annotation.
    fn is_ok_with_annotation(&self) -> bool;
    /// Return true if this is an ok result with a non-annotation.
    fn is_ok_with_non_annotation(&self) -> bool;
    /// Return true if this is an ok result with the keyword 'k'
    fn is_ok_with_kwd(&self, k: K) -> bool {
        self.is_ok_with_kwd_in(&[k])
    }
    /// Return true if this is an ok result with a keyword in the slice 'ks'
    fn is_ok_with_kwd_in(&self, ks: &[K]) -> bool;
    /// Return true if this is an ok result with a keyword not in the slice 'ks'
    fn is_ok_with_kwd_not_in(&self, ks: &[K]) -> bool;
    /// Return true if this is an empty-line error.
    fn is_empty_line(&self) -> bool;
}

impl<'a, K: Keyword> ItemResult<K> for Result<Item<'a, K>> {
    fn is_ok_with_annotation(&self) -> bool {
        match self {
            Ok(item) => item.kwd().is_annotation(),
            Err(_) => false,
        }
    }
    fn is_ok_with_non_annotation(&self) -> bool {
        match self {
            Ok(item) => !item.kwd().is_annotation(),
            Err(_) => false,
        }
    }
    fn is_ok_with_kwd_in(&self, ks: &[K]) -> bool {
        match self {
            Ok(item) => item.has_kwd_in(ks),
            Err(_) => false,
        }
    }
    fn is_ok_with_kwd_not_in(&self, ks: &[K]) -> bool {
        match self {
            Ok(item) => !item.has_kwd_in(ks),
            Err(_) => false,
        }
    }
    fn is_empty_line(&self) -> bool {
        matches!(
            self,
            Err(e) if e.netdoc_error_kind() == crate::err::NetdocErrorKind::EmptyLine
        )
    }
}

/// A peekable cursor into a string that returns Items one by one.
///
/// This is an [`Iterator`], yielding [`Item`]s.
#[derive(Debug)]
pub(crate) struct NetDocReader<'a, K: Keyword> {
    // TODO: I wish there were some way around having this string
    // reference, since we already need one inside NetDocReaderBase.
    /// The underlying string being parsed.
    s: &'a str,
    /// A stream of tokens being parsed by this NetDocReader.
    tokens: Peekable<NetDocReaderBase<'a, K>>,
}

impl<'a, K: Keyword> NetDocReader<'a, K> {
    /// Construct a new NetDocReader to read tokens from `s`.
    pub(crate) fn new(s: &'a str) -> Self {
        NetDocReader {
            s,
            tokens: NetDocReaderBase::new(s).peekable(),
        }
    }
    /// Return a reference to the string used for this NetDocReader.
    pub(crate) fn str(&self) -> &'a str {
        self.s
    }
    /// Return a wrapper around the peekable iterator in this
    /// NetDocReader that reads tokens until it reaches an element where
    /// 'f' is true.
    pub(crate) fn pause_at<'f, 'r, F>(
        &mut self,
        mut f: F,
    ) -> itertools::PeekingTakeWhile<'_, Self, impl FnMut(&Result<Item<'a, K>>) -> bool + 'f>
    where
        'f: 'r,
        F: FnMut(&Result<Item<'a, K>>) -> bool + 'f,
        K: 'f,
    {
        self.peeking_take_while(move |i| !f(i))
    }

    /// Return true if there are no more items in this NetDocReader.
    // The implementation sadly needs to mutate the inner state, even if it's not *semantically*
    // mutated..  We don't want inner mutability just to placate clippy for an internal API.
    #[allow(clippy::wrong_self_convention)]
    #[allow(dead_code)] // TODO perhaps we should remove this ?
    pub(crate) fn is_exhausted(&mut self) -> bool {
        self.peek().is_none()
    }

    /// Give an error if there are remaining tokens in this NetDocReader.
    pub(crate) fn should_be_exhausted(&mut self) -> Result<()> {
        match self.peek() {
            None => Ok(()),
            Some(Ok(t)) => Err(EK::UnexpectedToken
                .with_msg(t.kwd().to_str())
                .at_pos(t.pos())),
            Some(Err(e)) => Err(e.clone()),
        }
    }

    /// Give an error if there are remaining tokens in this NetDocReader.
    ///
    /// Like [`should_be_exhausted`](Self::should_be_exhausted),
    /// but permit empty lines at the end of the document.
    #[cfg(feature = "routerdesc")]
    pub(crate) fn should_be_exhausted_but_for_empty_lines(&mut self) -> Result<()> {
        use crate::err::NetdocErrorKind as K;
        while let Some(Err(e)) = self.peek() {
            if e.netdoc_error_kind() == K::EmptyLine {
                let _ignore = self.next();
            } else {
                break;
            }
        }
        self.should_be_exhausted()
    }

    /// Return the position from which the underlying reader is about to take
    /// the next token.  Use to make sure that the reader is progressing.
    pub(crate) fn pos(&mut self) -> Pos {
        match self.tokens.peek() {
            Some(Ok(tok)) => tok.pos(),
            Some(Err(e)) => e.pos(),
            None => Pos::at_end_of(self.s),
        }
    }
}

impl<'a, K: Keyword> Iterator for NetDocReader<'a, K> {
    type Item = Result<Item<'a, K>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.tokens.next()
    }
}

impl<'a, K: Keyword> PeekableIterator for NetDocReader<'a, K> {
    fn peek(&mut self) -> Option<&Self::Item> {
        self.tokens.peek()
    }
}

impl<'a, K: Keyword> itertools::PeekingNext for NetDocReader<'a, K> {
    fn peeking_next<F>(&mut self, f: F) -> Option<Self::Item>
    where
        F: FnOnce(&Self::Item) -> bool,
    {
        if f(self.peek()?) {
            self.next()
        } else {
            None
        }
    }
}

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
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    #![allow(clippy::cognitive_complexity)]
    use super::*;
    use crate::parse::macros::test::Fruit;
    use crate::{NetdocErrorKind as EK, Pos, Result};

    #[test]
    fn read_simple() {
        use Fruit::*;

        let s = "\
@tasty very much so
opt apple 77
banana 60
cherry 6
-----BEGIN CHERRY SYNOPSIS-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END CHERRY SYNOPSIS-----
plum hello there
";
        let mut r: NetDocReader<'_, Fruit> = NetDocReader::new(s);

        assert_eq!(r.str(), s);
        assert!(r.should_be_exhausted().is_err()); // it's not exhausted.

        let toks: Result<Vec<_>> = r.by_ref().collect();
        assert!(r.should_be_exhausted().is_ok());

        let toks = toks.unwrap();
        assert_eq!(toks.len(), 5);
        assert_eq!(toks[0].kwd(), ANN_TASTY);
        assert_eq!(toks[0].n_args(), 3);
        assert_eq!(toks[0].args_as_str(), "very much so");
        assert_eq!(toks[0].arg(1), Some("much"));
        {
            let a: Vec<_> = toks[0].args().collect();
            assert_eq!(a, vec!["very", "much", "so"]);
        }
        assert!(toks[0].parse_arg::<usize>(0).is_err());
        assert!(toks[0].parse_arg::<usize>(10).is_err());
        assert!(!toks[0].has_obj());
        assert_eq!(toks[0].obj_tag(), None);

        assert_eq!(toks[2].pos().within(s), Pos::from_line(3, 1));
        assert_eq!(toks[2].arg_pos(0).within(s), Pos::from_line(3, 8));
        assert_eq!(toks[2].last_arg_end_pos().within(s), Pos::from_line(3, 10));
        assert_eq!(toks[2].end_pos().within(s), Pos::from_line(3, 10));

        assert_eq!(toks[3].kwd(), STONEFRUIT);
        assert_eq!(toks[3].kwd_str(), "cherry"); // not cherry/plum!
        assert_eq!(toks[3].n_args(), 1);
        assert_eq!(toks[3].required_arg(0), Ok("6"));
        assert_eq!(toks[3].parse_arg::<usize>(0), Ok(6));
        assert_eq!(toks[3].parse_optional_arg::<usize>(0), Ok(Some(6)));
        assert_eq!(toks[3].parse_optional_arg::<usize>(3), Ok(None));
        assert!(toks[3].has_obj());
        assert_eq!(toks[3].obj_tag(), Some("CHERRY SYNOPSIS"));
        assert_eq!(
            &toks[3].obj("CHERRY SYNOPSIS").unwrap()[..],
            "🍒🍒🍒🍒🍒🍒".as_bytes()
        );
        assert!(toks[3].obj("PLUOT SYNOPSIS").is_err());
        // this "end-pos" value is questionable!
        assert_eq!(toks[3].end_pos().within(s), Pos::from_line(7, 30));
    }

    #[test]
    fn test_badtoks() {
        use Fruit::*;

        let s = "\
-foobar 9090
apple 3.14159
$hello
unrecognized 127.0.0.1 foo
plum
-----BEGIN WHATEVER-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END SOMETHING ELSE-----
orange
orange
-----BEGIN WHATEVER-----
not! base64!
-----END WHATEVER-----
guava paste
opt @annotation
orange
-----BEGIN LOBSTER
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END SOMETHING ELSE-----
orange
-----BEGIN !!!!!!-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END !!!!!!-----
cherry
-----BEGIN CHERRY SYNOPSIS-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END CHERRY SYNOPSIS

truncated line";

        let r: NetDocReader<'_, Fruit> = NetDocReader::new(s);
        let toks: Vec<_> = r.collect();

        assert!(toks[0].is_err());
        assert_eq!(
            toks[0].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(1, 1))
        );

        assert!(toks[1].is_ok());
        assert!(toks[1].is_ok_with_non_annotation());
        assert!(!toks[1].is_ok_with_annotation());
        assert!(toks[1].is_ok_with_kwd_in(&[APPLE, ORANGE]));
        assert!(toks[1].is_ok_with_kwd_not_in(&[ORANGE, UNRECOGNIZED]));
        let t = toks[1].as_ref().unwrap();
        assert_eq!(t.kwd(), APPLE);
        assert_eq!(t.arg(0), Some("3.14159"));

        assert!(toks[2].is_err());
        assert!(!toks[2].is_ok_with_non_annotation());
        assert!(!toks[2].is_ok_with_annotation());
        assert!(!toks[2].is_ok_with_kwd_in(&[APPLE, ORANGE]));
        assert!(!toks[2].is_ok_with_kwd_not_in(&[ORANGE, UNRECOGNIZED]));
        assert_eq!(
            toks[2].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(3, 1))
        );

        assert!(toks[3].is_ok());
        let t = toks[3].as_ref().unwrap();
        assert_eq!(t.kwd(), UNRECOGNIZED);
        assert_eq!(t.arg(1), Some("foo"));

        assert!(toks[4].is_err());
        assert_eq!(
            toks[4].as_ref().err().unwrap(),
            &EK::BadObjectMismatchedTag.at_pos(Pos::from_line(8, 1))
        );

        assert!(toks[5].is_ok());
        let t = toks[5].as_ref().unwrap();
        assert_eq!(t.kwd(), ORANGE);
        assert_eq!(t.args_as_str(), "");

        // This blob counts as two errors: a bad base64 blob, and
        // then an end line.
        assert!(toks[6].is_err());
        assert_eq!(
            toks[6].as_ref().err().unwrap(),
            &EK::BadObjectBase64.at_pos(Pos::from_line(12, 1))
        );

        assert!(toks[7].is_err());
        assert_eq!(
            toks[7].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(13, 1))
        );

        assert!(toks[8].is_ok());
        let t = toks[8].as_ref().unwrap();
        assert_eq!(t.kwd(), GUAVA);

        // this is an error because you can't use opt with annotations.
        assert!(toks[9].is_err());
        assert_eq!(
            toks[9].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(15, 1))
        );

        // this looks like a few errors.
        assert!(toks[10].is_err());
        assert_eq!(
            toks[10].as_ref().err().unwrap(),
            &EK::BadObjectBeginTag.at_pos(Pos::from_line(17, 1))
        );
        assert!(toks[11].is_err());
        assert_eq!(
            toks[11].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(18, 1))
        );
        assert!(toks[12].is_err());
        assert_eq!(
            toks[12].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(19, 1))
        );

        // so does this.
        assert!(toks[13].is_err());
        assert_eq!(
            toks[13].as_ref().err().unwrap(),
            &EK::BadObjectBeginTag.at_pos(Pos::from_line(21, 1))
        );
        assert!(toks[14].is_err());
        assert_eq!(
            toks[14].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(22, 1))
        );
        assert!(toks[15].is_err());
        assert_eq!(
            toks[15].as_ref().err().unwrap(),
            &EK::BadKeyword.at_pos(Pos::from_line(23, 1))
        );

        // not this.
        assert!(toks[16].is_err());
        assert_eq!(
            toks[16].as_ref().err().unwrap(),
            &EK::BadObjectEndTag.at_pos(Pos::from_line(27, 1))
        );

        assert!(toks[17].is_err());
        assert_eq!(
            toks[17].as_ref().err().unwrap(),
            &EK::EmptyLine.at_pos(Pos::from_line(28, 1))
        );

        assert!(toks[18].is_err());
        assert_eq!(
            toks[18].as_ref().err().unwrap(),
            &EK::TruncatedLine.at_pos(Pos::from_line(29, 15))
        );
    }
}
