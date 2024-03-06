#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![warn(missing_docs)]
#![warn(noop_method_call)]
#![warn(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unchecked_duration_subtraction)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
#![allow(clippy::result_large_err)] // temporary workaround for arti#587
#![allow(clippy::needless_raw_string_hashes)] // complained-about code is fine, often best
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

use std::fmt::{Display, Formatter};
use std::num::NonZeroUsize;
use std::str::FromStr;

mod err;
pub use err::Error;

/// Result type used by this crate
type Result<T> = std::result::Result<T, Error>;

/// Return true if `s` looks more like a consensus diff than some other kind
/// of document.
pub fn looks_like_diff(s: &str) -> bool {
    s.starts_with("network-status-diff-version")
}

/// Apply a given diff to an input text, and return the result from applying
/// that diff.
///
/// This is a slow version, for testing and correctness checking.  It uses
/// an O(n) operation to apply diffs, and therefore runs in O(n^2) time.
#[cfg(any(test, fuzzing, feature = "slow-diff-apply"))]
pub fn apply_diff_trivial<'a>(input: &'a str, diff: &'a str) -> Result<DiffResult<'a>> {
    let mut diff_lines = diff.lines();
    let (_, d2) = parse_diff_header(&mut diff_lines)?;

    let mut diffable = DiffResult::from_str(input, d2);

    for command in DiffCommandIter::new(diff_lines) {
        command?.apply_to(&mut diffable)?;
    }

    Ok(diffable)
}

/// Apply a given diff to an input text, and return the result from applying
/// that diff.
///
/// If `check_digest_in` is provided, require the diff to say that it
/// applies to a document with the provided digest.
pub fn apply_diff<'a>(
    input: &'a str,
    diff: &'a str,
    check_digest_in: Option<[u8; 32]>,
) -> Result<DiffResult<'a>> {
    let mut input = DiffResult::from_str(input, [0; 32]);

    let mut diff_lines = diff.lines();
    let (d1, d2) = parse_diff_header(&mut diff_lines)?;
    if let Some(d_want) = check_digest_in {
        if d1 != d_want {
            return Err(Error::CantApply("listed digest does not match document"));
        }
    }

    let mut output = DiffResult::new(d2);

    for command in DiffCommandIter::new(diff_lines) {
        command?.apply_transformation(&mut input, &mut output)?;
    }

    output.push_reversed(&input.lines[..]);

    output.lines.reverse();
    Ok(output)
}

/// Given a line iterator, check to make sure the first two lines are
/// a valid diff header as specified in dir-spec.txt.
fn parse_diff_header<'a, I>(iter: &mut I) -> Result<([u8; 32], [u8; 32])>
where
    I: Iterator<Item = &'a str>,
{
    let line1 = iter.next();
    if line1 != Some("network-status-diff-version 1") {
        return Err(Error::BadDiff("unrecognized or missing header"));
    }
    let line2 = iter.next().ok_or(Error::BadDiff("header truncated"))?;
    if !line2.starts_with("hash ") {
        return Err(Error::BadDiff("missing 'hash' line"));
    }
    let elts: Vec<_> = line2.split_ascii_whitespace().collect();
    if elts.len() != 3 {
        return Err(Error::BadDiff("invalid 'hash' line"));
    }
    let d1 = hex::decode(elts[1])?;
    let d2 = hex::decode(elts[2])?;
    match (d1.try_into(), d2.try_into()) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        _ => Err(Error::BadDiff("wrong digest lengths on 'hash' line")),
    }
}

/// A command that can appear in a diff.  Each command tells us to
/// remove zero or more lines, and insert zero or more lines in their
/// place.
///
/// Commands refer to lines by 1-indexed line number.
#[derive(Clone, Debug)]
enum DiffCommand<'a> {
    /// Remove the lines from low through high, inclusive.
    Delete {
        /// The first line to remove
        low: usize,
        /// The last line to remove
        high: usize,
    },
    /// Remove the lines from low through the end of the file, inclusive.
    DeleteToEnd {
        /// The first line to remove
        low: usize,
    },
    /// Replace the lines from low through high, inclusive, with the
    /// lines in 'lines'.
    Replace {
        /// The first line to replace
        low: usize,
        /// The last line to replace
        high: usize,
        /// The text to insert instead
        lines: Vec<&'a str>,
    },
    /// Insert the provided 'lines' after the line with index 'pos'.
    Insert {
        /// The position after which to insert the text
        pos: usize,
        /// The text to insert
        lines: Vec<&'a str>,
    },
}

/// The result of applying one or more diff commands to an input string.
///
/// It refers to lines from the diff and the input by reference, to
/// avoid copying.
#[derive(Clone, Debug)]
pub struct DiffResult<'a> {
    /// An expected digest of the output, after it has been assembled.
    d_post: [u8; 32],
    /// The lines in the output.
    lines: Vec<&'a str>,
}

/// A possible value for the end of a range.  It can be either a line number,
/// or a dollar sign indicating "end of file".
#[derive(Clone, Copy, Debug)]
enum RangeEnd {
    /// A line number in the file.
    Num(NonZeroUsize),
    /// A dollar sign, indicating "end of file" in a delete command.
    DollarSign,
}

impl FromStr for RangeEnd {
    type Err = Error;
    fn from_str(s: &str) -> Result<RangeEnd> {
        if s == "$" {
            Ok(RangeEnd::DollarSign)
        } else {
            let v: NonZeroUsize = s.parse()?;
            if v.get() == std::usize::MAX {
                return Err(Error::BadDiff("range end cannot at usize::MAX"));
            }
            Ok(RangeEnd::Num(v))
        }
    }
}

impl<'a> DiffCommand<'a> {
    /// Transform 'target' according to the this command.
    ///
    /// Because DiffResult internally uses a vector of line, this
    /// implementation is potentially O(n) in the size of the input.
    #[cfg(any(test, fuzzing, feature = "slow-diff-apply"))]
    fn apply_to(&self, target: &mut DiffResult<'a>) -> Result<()> {
        match self {
            Self::Delete { low, high } => {
                target.remove_lines(*low, *high)?;
            }
            Self::DeleteToEnd { low } => {
                target.remove_lines(*low, target.lines.len())?;
            }
            Self::Replace { low, high, lines } => {
                target.remove_lines(*low, *high)?;
                target.insert_at(*low, lines)?;
            }
            Self::Insert { pos, lines } => {
                // This '+1' seems off, but it's what the spec says. I wonder
                // if the spec is wrong.
                target.insert_at(*pos + 1, lines)?;
            }
        };
        Ok(())
    }

    /// Apply this command to 'input', moving lines into 'output'.
    ///
    /// This is a more efficient algorithm, but it requires that the
    /// diff commands are sorted in reverse order by line
    /// number. (Fortunately, the Tor ed diff format guarantees this.)
    ///
    /// Before calling this method, input and output must contain the
    /// results of having applied the previous command in the diff.
    /// (When no commands have been applied, input starts out as the
    /// original text, and output starts out empty.)
    ///
    /// This method applies the command by copying unaffected lines
    /// from the _end_ of input into output, adding any lines inserted
    /// by this command, and finally deleting any affected lines from
    /// input.
    ///
    /// We build the `output` value in reverse order, and then put it
    /// back to normal before giving it to the user.
    fn apply_transformation(
        &self,
        input: &mut DiffResult<'a>,
        output: &mut DiffResult<'a>,
    ) -> Result<()> {
        if let Some(succ) = self.following_lines() {
            if let Some(subslice) = input.lines.get(succ - 1..) {
                // Lines from `succ` onwards are unaffected.  Copy them.
                output.push_reversed(subslice);
            } else {
                // Oops, dubious line number.
                return Err(Error::CantApply(
                    "ending line number didn't correspond to document",
                ));
            }
        }

        if let Some(lines) = self.lines() {
            // These are the lines we're inserting.
            output.push_reversed(lines);
        }

        let remove = self.first_removed_line();
        if remove == 0 || (!self.is_insert() && remove > input.lines.len()) {
            return Err(Error::CantApply(
                "starting line number didn't correspond to document",
            ));
        }
        input.lines.truncate(remove - 1);

        Ok(())
    }

    /// Return the lines that we should add to the output
    fn lines(&self) -> Option<&[&'a str]> {
        match self {
            Self::Replace { lines, .. } | Self::Insert { lines, .. } => Some(lines.as_slice()),
            _ => None,
        }
    }

    /// Return a mutable reference to the vector of lines we should
    /// add to the output.
    fn linebuf_mut(&mut self) -> Option<&mut Vec<&'a str>> {
        match self {
            Self::Replace { ref mut lines, .. } | Self::Insert { ref mut lines, .. } => Some(lines),
            _ => None,
        }
    }

    /// Return the (1-indexed) line number of the first line in the
    /// input that comes _after_ this command, and is not affected by it.
    ///
    /// We use this line number to know which lines we should copy.
    fn following_lines(&self) -> Option<usize> {
        match self {
            Self::Delete { high, .. } | Self::Replace { high, .. } => Some(high + 1),
            Self::DeleteToEnd { .. } => None,
            Self::Insert { pos, .. } => Some(pos + 1),
        }
    }

    /// Return the (1-indexed) line number of the first line that we
    /// should clear from the input when processing this command.
    ///
    /// This can be the same as following_lines(), if we shouldn't
    /// actually remove any lines.
    fn first_removed_line(&self) -> usize {
        match self {
            Self::Delete { low, .. } => *low,
            Self::DeleteToEnd { low } => *low,
            Self::Replace { low, .. } => *low,
            Self::Insert { pos, .. } => *pos + 1,
        }
    }

    /// Return true if this is an Insert command.
    fn is_insert(&self) -> bool {
        matches!(self, Self::Insert { .. })
    }

    /// Extract a single command from a line iterator that yields lines
    /// of the diffs.  Return None if we're at the end of the iterator.
    fn from_line_iterator<I>(iter: &mut I) -> Result<Option<Self>>
    where
        I: Iterator<Item = &'a str>,
    {
        let command = match iter.next() {
            Some(s) => s,
            None => return Ok(None),
        };

        // `command` can be of these forms: `Rc`, `Rd`, `N,$d`, and `Na`,
        // where R is a range of form `N,N`, and where N is a line number.

        if command.len() < 2 || !command.is_ascii() {
            return Err(Error::BadDiff("command too short"));
        }

        let (range, command) = command.split_at(command.len() - 1);
        let (low, high) = if let Some(comma_pos) = range.find(',') {
            (
                range[..comma_pos].parse::<usize>()?,
                Some(range[comma_pos + 1..].parse::<RangeEnd>()?),
            )
        } else {
            (range.parse::<usize>()?, None)
        };

        if low == std::usize::MAX {
            return Err(Error::BadDiff("range cannot begin at usize::MAX"));
        }

        match (low, high) {
            (lo, Some(RangeEnd::Num(hi))) if lo > hi.into() => {
                return Err(Error::BadDiff("mis-ordered lines in range"))
            }
            (_, _) => (),
        }

        let mut cmd = match (command, low, high) {
            ("d", low, None) => Self::Delete { low, high: low },
            ("d", low, Some(RangeEnd::Num(high))) => Self::Delete {
                low,
                high: high.into(),
            },
            ("d", low, Some(RangeEnd::DollarSign)) => Self::DeleteToEnd { low },
            ("c", low, None) => Self::Replace {
                low,
                high: low,
                lines: Vec::new(),
            },
            ("c", low, Some(RangeEnd::Num(high))) => Self::Replace {
                low,
                high: high.into(),
                lines: Vec::new(),
            },
            ("a", low, None) => Self::Insert {
                pos: low,
                lines: Vec::new(),
            },
            (_, _, _) => return Err(Error::BadDiff("can't parse command line")),
        };

        if let Some(ref mut linebuf) = cmd.linebuf_mut() {
            // The 'c' and 'a' commands take a series of lines followed by a
            // line containing a period.
            loop {
                match iter.next() {
                    None => return Err(Error::BadDiff("unterminated block to insert")),
                    Some(".") => break,
                    Some(line) => linebuf.push(line),
                }
            }
        }

        Ok(Some(cmd))
    }
}

/// Iterator that wraps a line iterator and returns a sequence of
/// `Result<DiffCommand>`.
///
/// This iterator forces the commands to affect the file in reverse order,
/// so that we can use the O(n) algorithm for applying these diffs.
struct DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    /// The underlying iterator.
    iter: I,

    /// The 'first removed line' of the last-parsed command; used to ensure
    /// that commands appear in reverse order.
    last_cmd_first_removed: Option<usize>,
}

impl<'a, I> DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    /// Construct a new DiffCommandIter wrapping `iter`.
    fn new(iter: I) -> Self {
        DiffCommandIter {
            iter,
            last_cmd_first_removed: None,
        }
    }
}

impl<'a, I> Iterator for DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    type Item = Result<DiffCommand<'a>>;
    fn next(&mut self) -> Option<Result<DiffCommand<'a>>> {
        match DiffCommand::from_line_iterator(&mut self.iter) {
            Err(e) => Some(Err(e)),
            Ok(None) => None,
            Ok(Some(c)) => match (self.last_cmd_first_removed, c.following_lines()) {
                (Some(_), None) => Some(Err(Error::BadDiff("misordered commands"))),
                (Some(a), Some(b)) if a < b => Some(Err(Error::BadDiff("misordered commands"))),
                (_, _) => {
                    self.last_cmd_first_removed = Some(c.first_removed_line());
                    Some(Ok(c))
                }
            },
        }
    }
}

impl<'a> DiffResult<'a> {
    /// Construct a new DiffResult containing the provided string
    /// split into lines, and an expected post-transformation digest.
    fn from_str(s: &'a str, d_post: [u8; 32]) -> Self {
        // I'd like to use str::split_inclusive here, but that isn't stable yet
        // as of rust 1.48.

        let lines: Vec<_> = s.lines().collect();

        DiffResult { d_post, lines }
    }

    /// Return a new empty DiffResult with an expected
    /// post-transformation digests
    fn new(d_post: [u8; 32]) -> Self {
        DiffResult {
            d_post,
            lines: Vec::new(),
        }
    }

    /// Put every member of `lines` at the end of this DiffResult, in
    /// reverse order.
    fn push_reversed(&mut self, lines: &[&'a str]) {
        self.lines.extend(lines.iter().rev());
    }

    /// Remove the 1-indexed lines from `first` through `last` inclusive.
    ///
    /// This has to move elements around within the vector, and so it
    /// is potentially O(n) in its length.
    #[cfg(any(test, fuzzing, feature = "slow-diff-apply"))]
    fn remove_lines(&mut self, first: usize, last: usize) -> Result<()> {
        if first > self.lines.len() || last > self.lines.len() || first == 0 || last == 0 {
            Err(Error::CantApply("line out of range"))
        } else {
            let n_to_remove = last - first + 1;
            if last != self.lines.len() {
                self.lines[..].copy_within((last).., first - 1);
            }
            self.lines.truncate(self.lines.len() - n_to_remove);
            Ok(())
        }
    }

    /// Insert the provided `lines` so that they appear at 1-indexed
    /// position `pos`.
    ///
    /// This has to move elements around within the vector, and so it
    /// is potentially O(n) in its length.
    #[cfg(any(test, fuzzing, feature = "slow-diff-apply"))]
    fn insert_at(&mut self, pos: usize, lines: &[&'a str]) -> Result<()> {
        if pos > self.lines.len() + 1 || pos == 0 {
            Err(Error::CantApply("position out of range"))
        } else {
            let orig_len = self.lines.len();
            self.lines.resize(self.lines.len() + lines.len(), "");
            self.lines
                .copy_within(pos - 1..orig_len, pos - 1 + lines.len());
            self.lines[(pos - 1)..(pos + lines.len() - 1)].copy_from_slice(lines);
            Ok(())
        }
    }

    /// See whether the output of this diff matches the target digest.
    ///
    /// If not, return an error.
    pub fn check_digest(&self) -> Result<()> {
        use digest::Digest;
        use tor_llcrypto::d::Sha3_256;
        let mut d = Sha3_256::new();
        for line in &self.lines {
            d.update(line.as_bytes());
            d.update(b"\n");
        }
        if d.finalize() == self.d_post.into() {
            Ok(())
        } else {
            Err(Error::CantApply("Wrong digest after applying diff"))
        }
    }
}

impl<'a> Display for DiffResult<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for elt in &self.lines {
            writeln!(f, "{}", elt)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn remove() -> Result<()> {
        let example = DiffResult::from_str("1\n2\n3\n4\n5\n6\n7\n8\n9\n", [0; 32]);

        let mut d = example.clone();
        d.remove_lines(5, 7)?;
        assert_eq!(d.to_string(), "1\n2\n3\n4\n8\n9\n");

        let mut d = example.clone();
        d.remove_lines(1, 9)?;
        assert_eq!(d.to_string(), "");

        let mut d = example.clone();
        d.remove_lines(1, 1)?;
        assert_eq!(d.to_string(), "2\n3\n4\n5\n6\n7\n8\n9\n");

        let mut d = example.clone();
        d.remove_lines(6, 9)?;
        assert_eq!(d.to_string(), "1\n2\n3\n4\n5\n");

        let mut d = example.clone();
        assert!(d.remove_lines(6, 10).is_err());
        assert!(d.remove_lines(0, 1).is_err());
        assert_eq!(d.to_string(), "1\n2\n3\n4\n5\n6\n7\n8\n9\n");

        Ok(())
    }

    #[test]
    fn insert() -> Result<()> {
        let example = DiffResult::from_str("1\n2\n3\n4\n5\n", [0; 32]);
        let mut d = example.clone();
        d.insert_at(3, &["hello", "world"])?;
        assert_eq!(d.to_string(), "1\n2\nhello\nworld\n3\n4\n5\n");

        let mut d = example.clone();
        d.insert_at(6, &["hello", "world"])?;
        assert_eq!(d.to_string(), "1\n2\n3\n4\n5\nhello\nworld\n");

        let mut d = example.clone();
        assert!(d.insert_at(0, &["hello", "world"]).is_err());
        assert!(d.insert_at(7, &["hello", "world"]).is_err());
        Ok(())
    }

    #[test]
    fn push_reversed() {
        let mut d = DiffResult::new([0; 32]);
        d.push_reversed(&["7", "8", "9"]);
        assert_eq!(d.to_string(), "9\n8\n7\n");
        d.push_reversed(&["world", "hello", ""]);
        assert_eq!(d.to_string(), "9\n8\n7\n\nhello\nworld\n");
    }

    #[test]
    fn apply_command_simple() {
        let example = DiffResult::from_str("a\nb\nc\nd\ne\nf\n", [0; 32]);

        let mut d = example.clone();
        assert_eq!(d.to_string(), "a\nb\nc\nd\ne\nf\n".to_string());
        assert!(DiffCommand::DeleteToEnd { low: 5 }.apply_to(&mut d).is_ok());
        assert_eq!(d.to_string(), "a\nb\nc\nd\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Delete { low: 3, high: 5 }
            .apply_to(&mut d)
            .is_ok());
        assert_eq!(d.to_string(), "a\nb\nf\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Replace {
            low: 3,
            high: 5,
            lines: vec!["hello", "world"]
        }
        .apply_to(&mut d)
        .is_ok());
        assert_eq!(d.to_string(), "a\nb\nhello\nworld\nf\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Insert {
            pos: 3,
            lines: vec!["hello", "world"]
        }
        .apply_to(&mut d)
        .is_ok());
        assert_eq!(
            d.to_string(),
            "a\nb\nc\nhello\nworld\nd\ne\nf\n".to_string()
        );
    }

    #[test]
    fn parse_command() -> Result<()> {
        fn parse(s: &str) -> Result<DiffCommand<'_>> {
            let mut iter = s.lines();
            let cmd = DiffCommand::from_line_iterator(&mut iter)?;
            let cmd2 = DiffCommand::from_line_iterator(&mut iter)?;
            if cmd2.is_some() {
                panic!("Unexpected second command");
            }
            Ok(cmd.unwrap())
        }

        fn parse_err(s: &str) {
            let mut iter = s.lines();
            let cmd = DiffCommand::from_line_iterator(&mut iter);
            assert!(matches!(cmd, Err(Error::BadDiff(_))));
        }

        let p = parse("3,8d\n")?;
        assert!(matches!(p, DiffCommand::Delete { low: 3, high: 8 }));
        let p = parse("3d\n")?;
        assert!(matches!(p, DiffCommand::Delete { low: 3, high: 3 }));
        let p = parse("100,$d\n")?;
        assert!(matches!(p, DiffCommand::DeleteToEnd { low: 100 }));

        let p = parse("30,40c\nHello\nWorld\n.\n")?;
        assert!(matches!(
            p,
            DiffCommand::Replace {
                low: 30,
                high: 40,
                ..
            }
        ));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));
        let p = parse("30c\nHello\nWorld\n.\n")?;
        assert!(matches!(
            p,
            DiffCommand::Replace {
                low: 30,
                high: 30,
                ..
            }
        ));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));

        let p = parse("999a\nHello\nWorld\n.\n")?;
        assert!(matches!(p, DiffCommand::Insert { pos: 999, .. }));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));
        let p = parse("0a\nHello\nWorld\n.\n")?;
        assert!(matches!(p, DiffCommand::Insert { pos: 0, .. }));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));

        parse_err("hello world");
        parse_err("\n\n");
        parse_err("$,5d");
        parse_err("5,6,8d");
        parse_err("8,5d");
        parse_err("6");
        parse_err("d");
        parse_err("-10d");
        parse_err("4,$c\na\n.");
        parse_err("foo");
        parse_err("5,10p");
        parse_err("18446744073709551615a");
        parse_err("1,18446744073709551615d");

        Ok(())
    }

    #[test]
    fn apply_transformation() -> Result<()> {
        let example = DiffResult::from_str("1\n2\n3\n4\n5\n6\n7\n8\n9\n", [0; 32]);
        let empty = DiffResult::new([1; 32]);

        let mut inp = example.clone();
        let mut out = empty.clone();
        DiffCommand::DeleteToEnd { low: 5 }.apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "1\n2\n3\n4\n");
        assert_eq!(out.to_string(), "");

        let mut inp = example.clone();
        let mut out = empty.clone();
        DiffCommand::DeleteToEnd { low: 9 }.apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "1\n2\n3\n4\n5\n6\n7\n8\n");
        assert_eq!(out.to_string(), "");

        let mut inp = example.clone();
        let mut out = empty.clone();
        DiffCommand::Delete { low: 3, high: 5 }.apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "1\n2\n");
        assert_eq!(out.to_string(), "9\n8\n7\n6\n");

        let mut inp = example.clone();
        let mut out = empty.clone();
        DiffCommand::Replace {
            low: 5,
            high: 6,
            lines: vec!["oh hey", "there"],
        }
        .apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "1\n2\n3\n4\n");
        assert_eq!(out.to_string(), "9\n8\n7\nthere\noh hey\n");

        let mut inp = example.clone();
        let mut out = empty.clone();
        DiffCommand::Insert {
            pos: 3,
            lines: vec!["oh hey", "there"],
        }
        .apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "1\n2\n3\n");
        assert_eq!(out.to_string(), "9\n8\n7\n6\n5\n4\nthere\noh hey\n");
        DiffCommand::Insert {
            pos: 0,
            lines: vec!["boom!"],
        }
        .apply_transformation(&mut inp, &mut out)?;
        assert_eq!(inp.to_string(), "");
        assert_eq!(
            out.to_string(),
            "9\n8\n7\n6\n5\n4\nthere\noh hey\n3\n2\n1\nboom!\n"
        );

        let mut inp = example.clone();
        let mut out = empty.clone();
        let r = DiffCommand::Delete {
            low: 100,
            high: 200,
        }
        .apply_transformation(&mut inp, &mut out);
        assert!(r.is_err());
        let r = DiffCommand::Delete { low: 5, high: 200 }.apply_transformation(&mut inp, &mut out);
        assert!(r.is_err());
        let r = DiffCommand::Delete { low: 0, high: 1 }.apply_transformation(&mut inp, &mut out);
        assert!(r.is_err());
        let r = DiffCommand::DeleteToEnd { low: 10 }.apply_transformation(&mut inp, &mut out);
        assert!(r.is_err());
        Ok(())
    }

    #[test]
    fn header() -> Result<()> {
        fn header_from(s: &str) -> Result<([u8; 32], [u8; 32])> {
            let mut iter = s.lines();
            parse_diff_header(&mut iter)
        }

        let (a,b) = header_from(
            "network-status-diff-version 1
hash B03DA3ACA1D3C1D083E3FF97873002416EBD81A058B406D5C5946EAB53A79663 F6789F35B6B3BA58BB23D29E53A8ED6CBB995543DBE075DD5671481C4BA677FB"
        )?;

        assert_eq!(
            &a[..],
            hex::decode("B03DA3ACA1D3C1D083E3FF97873002416EBD81A058B406D5C5946EAB53A79663")?
        );
        assert_eq!(
            &b[..],
            hex::decode("F6789F35B6B3BA58BB23D29E53A8ED6CBB995543DBE075DD5671481C4BA677FB")?
        );

        assert!(header_from("network-status-diff-version 2\n").is_err());
        assert!(header_from("").is_err());
        assert!(header_from("5,$d\n1,2d\n").is_err());
        assert!(header_from("network-status-diff-version 1\n").is_err());
        assert!(header_from(
            "network-status-diff-version 1
hash x y
5,5d"
        )
        .is_err());
        assert!(header_from(
            "network-status-diff-version 1
hash x y
5,5d"
        )
        .is_err());
        assert!(header_from(
            "network-status-diff-version 1
hash AA BB
5,5d"
        )
        .is_err());
        assert!(header_from(
            "network-status-diff-version 1
oh hello there
5,5d"
        )
        .is_err());
        assert!(header_from("network-status-diff-version 1
hash B03DA3ACA1D3C1D083E3FF97873002416EBD81A058B406D5C5946EAB53A79663 F6789F35B6B3BA58BB23D29E53A8ED6CBB995543DBE075DD5671481C4BA677FB extra").is_err());

        Ok(())
    }

    #[test]
    fn apply_simple() {
        let pre = include_str!("../testdata/consensus1.txt");
        let diff = include_str!("../testdata/diff1.txt");
        let post = include_str!("../testdata/consensus2.txt");

        let result = apply_diff_trivial(pre, diff).unwrap();
        assert!(result.check_digest().is_ok());
        assert_eq!(result.to_string(), post);
    }

    #[test]
    fn sort_order() -> Result<()> {
        fn cmds(s: &str) -> Result<Vec<DiffCommand<'_>>> {
            let mut out = Vec::new();
            for cmd in DiffCommandIter::new(s.lines()) {
                out.push(cmd?);
            }
            Ok(out)
        }

        let _ = cmds("6,9d\n5,5d\n")?;
        assert!(cmds("5,5d\n6,9d\n").is_err());
        assert!(cmds("5,5d\n6,6d\n").is_err());
        assert!(cmds("5,5d\n5,6d\n").is_err());

        Ok(())
    }
}
