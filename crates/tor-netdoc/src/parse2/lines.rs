//! Version of `std::str::Lines` that tracks line numbers and has `remainder()`

/// Version of `std::str::Lines` that tracks line numbers and has `remainder()`
///
/// Implements `Iterator`, returning one `str` for each line, with the `'\n'` removed.
///
/// Missing final newline is silently tolerated.
#[derive(Debug, Clone)]
pub struct Lines<'s> {
    /// Line number at the start of `rest`
    lno: usize,
    /// The remaining part of the document
    rest: &'s str,
}

/// Extension trait adding a method to `str`
pub trait StrExt: AsRef<str> {
    /// Remove `count` bytes from the end of `self`
    ///
    /// # Panics
    ///
    /// Panics if `count > self.len()`.
    fn strip_end_counted(&self, count: usize) -> &str {
        let s = self.as_ref();
        &s[0..s.len().checked_sub(count).expect("stripping too much")]
    }
}
impl StrExt for str {}

/// Information about the next line we have peeked
///
/// To get the line as an actual string, pass this to `peeked_line`.
///
/// # Correctness
///
/// Each `Peeked` is only valid in conjunction with the `Lines` that returned it,
/// and becomes invalidated if the `Lines` is modified
/// (ie, it can be invalidated by calls that take `&mut Lines`).
///
/// Cloning a `Peeked` is hazrdous since using it twice would be wrong.
///
/// None of this is checked at compile- or run-time.
// We could perhaps use lifetimes somehow to enforce this,
// but `ItemStream` wants `Peeked` to be `'static` and `Clone`.
#[derive(Debug, Clone, amplify::Getters)]
pub struct Peeked {
    /// The length of the next line
    //
    // # Invariant
    //
    // `rest[line_len]` is a newline, or `line_len` is `rest.len()`.
    #[getter(as_copy)]
    line_len: usize,
}

impl<'s> Lines<'s> {
    /// Start reading lines from a document as a string
    pub fn new(s: &'s str) -> Self {
        Lines { lno: 1, rest: s }
    }

    /// Line number of the next line we'll read
    pub fn peek_lno(&self) -> usize {
        self.lno
    }

    /// Peek the next line
    pub fn peek(&self) -> Option<Peeked> {
        if self.rest.is_empty() {
            None
        } else if let Some(newline) = self.rest.find('\n') {
            Some(Peeked { line_len: newline })
        } else {
            Some(Peeked {
                line_len: self.rest.len(),
            })
        }
    }

    /// The rest of the file as a `str`
    pub fn remaining(&self) -> &'s str {
        self.rest
    }

    /// After `peek`, advance to the next line, consuming the one that was peeked
    ///
    /// # Correctness
    ///
    /// See [`Peeked`].
    #[allow(clippy::needless_pass_by_value)] // Yes, we want to consume Peeked
    pub fn consume_peeked(&mut self, peeked: Peeked) -> &'s str {
        let line = self.peeked_line(&peeked);
        self.rest = &self.rest[peeked.line_len..];
        if !self.rest.is_empty() {
            debug_assert!(self.rest.starts_with('\n'));
            self.rest = &self.rest[1..];
        }
        self.lno += 1;
        line
    }

    /// After `peek`, obtain the actual peeked line as a `str`
    ///
    /// As with [`<Lines as Iterator>::next`](Lines::next), does not include the newline.
    // Rustdoc doesn't support linking` fully qualified syntax.
    // https://github.com/rust-lang/rust/issues/74563
    ///
    /// # Correctness
    ///
    /// See [`Peeked`].
    pub fn peeked_line(&self, peeked: &Peeked) -> &'s str {
        &self.rest[0..peeked.line_len()]
    }
}

impl<'s> Iterator for Lines<'s> {
    type Item = &'s str;

    fn next(&mut self) -> Option<&'s str> {
        let peeked = self.peek()?;
        let line = self.consume_peeked(peeked);
        Some(line)
    }
}
