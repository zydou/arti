//! Lexing of netdoc elements

use super::*;

/// Linear whitespace as defined by torspec
// Only pub via internal_prelude, for benefit of macros
pub const WS: &[char] = &[' ', '\t'];

define_derive_deftly! {
    /// Define `parse_options` accessor
    ///
    /// The driver must have a lifetime named `'s`, which is suitable for the returned
    /// `&'s ParseOptions`.
    ///
    /// # Top-level attributes:
    ///
    ///  * **`#[deftly(parse_options(field = ".field.field"))]`**, default `.options`
    ParseOptions beta_deftly, expect items:

    impl<$tgens> $ttype {
        /// Examine the parsing options
        pub fn parse_options(&self) -> &'s ParseOptions {
            &self
                ${tmeta(parse_options(field))
                  as token_stream,
                  default { .options }}
        }
    }
}

/// Top-level reader: Netdoc text interpreted as a stream of items
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(ParseOptions)]
pub struct ItemStream<'s> {
    /// The whole input document.
    whole_input: &'s str,
    /// Remaining document, as a stream of lines
    lines: Lines<'s>,
    /// If we have peeked ahead, what we discovered
    peeked: PeekState<'s>,
    /// Parsing options.
    options: &'s ParseOptions,
}

/// Whether an `ItemStream` has peeked ahead, and if so what it discovered
#[derive(Debug, Clone)]
enum PeekState<'s> {
    /// We've peeked a line
    Some(ItemStreamPeeked<'s>),
    /// We've not peeked, or peeking gave `None`
    None {
        /// Line number of the last item we yielded.
        ///
        /// `0` at the start.
        yielded_item_lno: usize,
    },
}

/// If an `ItemStream` has peeked ahead, what it discovered
#[derive(Debug, Clone)]
struct ItemStreamPeeked<'s> {
    /// The next keyword
    keyword: KeywordRef<'s>,
    /// Token proving that we
    line: lines::Peeked,
    /// Length of the suffix of the line that is the arguments rather than the keyword
    ///
    /// Does not include the first whitespace, that terminated the keyword.
    args_len: usize,
}

/// An Item that has been lexed but not parsed
#[derive(Debug, Clone, amplify::Getters, Deftly)]
#[derive_deftly(ParseOptions)]
#[deftly(parse_options(field = ".args.options"))]
pub struct UnparsedItem<'s> {
    /// The item's Keyword
    #[getter(as_copy)]
    keyword: KeywordRef<'s>,
    /// The Item's Arguments
    #[getter(skip)]
    args: ArgumentStream<'s>,
    /// The Item's Object, if there was one
    #[getter(as_clone)]
    object: Option<UnparsedObject<'s>>,
}

/// Reader for arguments on an Item
///
/// Represents the (remaining) arguments.
#[derive(Debug, Clone, Deftly)]
#[derive_deftly(ParseOptions)]
pub struct ArgumentStream<'s> {
    /// The remaining unparsed arguments
    ///
    /// Can start with WS, which is usually trimmed
    rest: &'s str,

    /// Original line length
    ///
    /// Used for reporting column of argument errors.
    whole_line_len: usize,

    /// Remaining length *before* we last yielded.
    previous_rest_len: usize,

    /// Parsing options.
    options: &'s ParseOptions,
}

/// An Object that has been lexed but not parsed
#[derive(Debug, Clone, amplify::Getters, Deftly)]
#[derive_deftly(ParseOptions)]
pub struct UnparsedObject<'s> {
    /// The Label
    #[getter(as_copy)]
    label: &'s str,

    /// The portion of the input document which is base64 data (and newlines)
    #[getter(skip)]
    data_b64: &'s str,

    /// Parsing options.
    options: &'s ParseOptions,
}

impl<'s> ItemStream<'s> {
    /// Start reading a network document as a series of Items
    pub fn new(input: &'s ParseInput<'s>) -> Result<Self, ParseError> {
        Ok(ItemStream {
            whole_input: input.input,
            lines: Lines::new(input.input),
            peeked: PeekState::None {
                yielded_item_lno: 0,
            },
            options: &input.options,
        })
    }

    /// Line number for reporting an error we have just discovered
    ///
    /// If we have recent peeked, we report the line number of the peeked keyword line.
    ///
    /// Otherwise, we report the line number of the most-recently yielded item.
    pub fn lno_for_error(&self) -> usize {
        match self.peeked {
            PeekState::Some { .. } => {
                // The error was presumably caused by whatever was seen in the peek.
                // That's the current line number.
                self.lines.peek_lno()
            }
            PeekState::None { yielded_item_lno } => {
                // The error was presumably caused by the results of next_item().
                yielded_item_lno
            }
        }
    }

    /// Core of peeking.  Tries to make `.peeked` be `Some`.
    fn peek_internal<'i>(&'i mut self) -> Result<(), EP> {
        if matches!(self.peeked, PeekState::None { .. }) {
            let Some(peeked) = self.lines.peek() else {
                return Ok(());
            };

            let peeked_line = self.lines.peeked_line(&peeked);

            let (keyword, args) = peeked_line.split_once(WS).unwrap_or((peeked_line, ""));
            let keyword = KeywordRef::new(keyword)?;

            self.peeked = PeekState::Some(ItemStreamPeeked {
                keyword,
                line: peeked,
                args_len: args.len(),
            });
        }

        Ok(())
    }

    /// Peek the next keyword
    pub fn peek_keyword(&mut self) -> Result<Option<KeywordRef<'s>>, EP> {
        self.peek_internal()?;
        let PeekState::Some(peeked) = &self.peeked else {
            return Ok(None);
        };
        Ok(Some(peeked.keyword))
    }

    /// Obtain the body so far, suitable for hashing for a Regular signature
    pub fn body_sofar_for_signature(&self) -> SignedDocumentBody<'s> {
        let body = &self.whole_input[0..self.byte_position()];
        SignedDocumentBody { body }
    }

    /// Byte position, pointing to the start of the next item to yield
    ///
    /// Offset in bytes from the start of the original input string
    /// to the "current" position,
    /// ie to just after the item we yielded and just before the next item (or EOF).
    pub fn byte_position(&self) -> usize {
        self.whole_input.len() - self.lines.remaining().len()
    }

    /// Access for the entire input string
    ///
    /// The original `input: &str` argument to [`ParseInput::new`].
    ///
    /// Includes both yielded and unyielded items.
    pub fn whole_input(&self) -> &'s str {
        self.whole_input
    }

    /// Parse a (sub-)document with its own signatures
    pub fn parse_signed<
        B: NetdocParseable,
        S: NetdocParseable,
        O: NetdocSigned<Body = B, Signatures = S>,
    >(
        &mut self,
        outer_stop: stop_at!(),
    ) -> Result<O, EP> {
        let mut input = ItemStream {
            whole_input: &self.whole_input[self.whole_input.len() - self.lines.remaining().len()..],
            ..self.clone()
        };
        let r = (|| {
            let inner_always_stop = outer_stop | StopAt::doc_intro::<B>();
            let body = B::from_items(&mut input, inner_always_stop | StopAt::doc_intro::<S>())?;
            let signatures = S::from_items(&mut input, inner_always_stop)?;
            let signed = O::from_parts(body, signatures);
            Ok(signed)
        })(); // don't exit here

        *self = ItemStream {
            whole_input: self.whole_input,
            ..input
        };

        r
    }

    /// Obtain the inputs that would be needed to hash any (even Irregular) signature
    ///
    /// These are the hash inputs which would be needed for the next item,
    /// assuming it's a signature keyword.
    pub fn peek_signature_hash_inputs(
        &mut self,
        body: SignedDocumentBody<'s>,
    ) -> Result<Option<SignatureHashInputs<'s>>, EP> {
        self.peek_internal()?;
        let PeekState::Some(peeked) = &self.peeked else {
            return Ok(None);
        };
        let signature_item_line = self.lines.peeked_line(&peeked.line);
        let signature_item_kw_spc = signature_item_line.strip_end_counted(peeked.args_len);
        Ok(Some(SignatureHashInputs {
            body,
            signature_item_kw_spc,
            signature_item_line,
        }))
    }

    /// Yield the next item.
    pub fn next_item(&mut self) -> Result<Option<UnparsedItem<'s>>, EP> {
        self.peek_internal()?;
        let peeked = match self.peeked {
            PeekState::None { .. } => return Ok(None),
            PeekState::Some { .. } => match mem::replace(
                &mut self.peeked,
                PeekState::None {
                    yielded_item_lno: self.lines.peek_lno(),
                },
            ) {
                PeekState::Some(peeked) => peeked,
                PeekState::None { .. } => panic!("it was Some just now"),
            },
        };

        let keyword = peeked.keyword;
        let line = self.lines.consume_peeked(peeked.line);
        let args = &line[keyword.len()..];
        let options = self.options;
        let args = ArgumentStream::new(args, line.len(), options);

        let object = if self.lines.remaining().starts_with('-') {
            fn pem_delimiter<'s>(lines: &mut Lines<'s>, start: &str) -> Result<&'s str, EP> {
                let line = lines.next().ok_or(
                    // If this is the *header*, we already know there's a line,
                    // so this error path is only for footers.
                    EP::ObjectMissingFooter,
                )?;
                let label = line
                    .strip_prefix(start)
                    .ok_or(EP::InvalidObjectDelimiters)?
                    .strip_suffix(PEM_AFTER_LABEL)
                    .ok_or(EP::InvalidObjectDelimiters)?;
                Ok(label)
            }

            let label1 = pem_delimiter(&mut self.lines, PEM_HEADER_START)?;
            let base64_start_remaining = self.lines.remaining();
            while !self.lines.remaining().starts_with('-') {
                let _: &str = self.lines.next().ok_or(EP::ObjectMissingFooter)?;
            }
            let data_b64 = base64_start_remaining.strip_end_counted(self.lines.remaining().len());
            let label2 = pem_delimiter(&mut self.lines, PEM_FOOTER_START)?;
            let label = [label1, label2]
                .into_iter()
                .all_equal_value()
                .map_err(|_| EP::ObjectMismatchedLabels)?;
            Some(UnparsedObject {
                label,
                data_b64,
                options,
            })
        } else {
            None
        };

        Ok(Some(UnparsedItem {
            keyword,
            args,
            object,
        }))
    }
}

impl<'s> UnparsedItem<'s> {
    /// Access the arguments, mutably (for consuming and parsing them)
    pub fn args_mut(&mut self) -> &mut ArgumentStream<'s> {
        &mut self.args
    }
    /// Access a copy of the arguments
    ///
    /// When using this, be careful not to process any arguments twice.
    pub fn args_copy(&self) -> ArgumentStream<'s> {
        self.args.clone()
    }

    /// Access the arguments (readonly)
    ///
    /// When using this, be careful not to process any arguments twice.
    pub fn args(&self) -> &ArgumentStream<'s> {
        &self.args
    }

    /// Check that this item has no Object.
    pub fn check_no_object(&self) -> Result<(), EP> {
        if self.object.is_some() {
            return Err(EP::ObjectUnexpected);
        }
        Ok(())
    }
    /// Convenience method for handling an error parsing an arguemnt
    ///
    /// Returns a closure that converts every error into [`ArgumentError::Invalid`]
    /// and then to an [`ErrorProblem`] using
    /// [`.args().handle_error()`](ArgumentStream::handle_error).
    ///
    /// Useful in manual `ItemValueParseable` impls, when parsing arguments ad-hoc.
    pub fn invalid_argument_handler<E>(
        &self,
        field: &'static str,
    ) -> impl FnOnce(E) -> ErrorProblem {
        let error = self.args().handle_error(field, AE::Invalid);
        move |_any_error| error
    }
}

/// End of an argument list that does not accept any further (unknown) arguments
///
/// Implements `ItemArgumentParseable`.  Parses successfully iff the argument list is empty.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[allow(clippy::exhaustive_structs)]
pub struct NoFurtherArguments;

impl ItemArgumentParseable for NoFurtherArguments {
    fn from_args(args: &mut ArgumentStream) -> Result<Self, AE> {
        Ok(args.reject_extra_args()?)
    }
}

impl<'s> Iterator for ItemStream<'s> {
    type Item = Result<UnparsedItem<'s>, EP>;
    fn next(&mut self) -> Option<Result<UnparsedItem<'s>, EP>> {
        self.next_item().transpose()
    }
}

impl<'s> ArgumentStream<'s> {
    /// Make a new `ArgumentStream` from a string
    ///
    /// The string may start with whitespace (which will be ignored).
    pub fn new(rest: &'s str, whole_line_len: usize, options: &'s ParseOptions) -> Self {
        let previous_rest_len = whole_line_len;
        ArgumentStream {
            rest,
            whole_line_len,
            previous_rest_len,
            options,
        }
    }

    /// Consume this whole `ArgumnetStream`, giving the remaining arguments as a string
    ///
    /// The returned string won't start with whitespace.
    //
    /// `self` will be empty on return.
    // (We don't take `self` by value because that makes use with `UnparsedItem` annoying.)
    pub fn into_remaining(&mut self) -> &'s str {
        self.prep_yield();
        mem::take(&mut self.rest)
    }

    /// Return the component parts of this `ArgumnetStream`
    ///
    /// The returned string might start with whitespace.
    pub fn whole_line_len(&self) -> usize {
        self.whole_line_len
    }

    /// Prepares to yield an argument (or the rest)
    ///
    ///  * Trims leading WS from `rest`.
    ///  * Records the `previous_rest_len`
    fn prep_yield(&mut self) {
        self.rest = self.rest.trim_start_matches(WS);
        self.previous_rest_len = self.rest.len();
    }

    /// Prepares to yield, and then determines if there *is* anything to yield.
    ///
    ///  * Trim leading whitespace
    ///  * Records the `previous_rest_len`
    ///  * See if we're now empty
    pub fn something_to_yield(&mut self) -> bool {
        self.prep_yield();
        !self.rest.is_empty()
    }

    /// Throw and error if there are further arguments
    //
    // (We don't take `self` by value because that makes use with `UnparsedItem` annoying.)
    pub fn reject_extra_args(&mut self) -> Result<NoFurtherArguments, UnexpectedArgument> {
        if self.something_to_yield() {
            let column = self.next_arg_column();
            Err(UnexpectedArgument { column })
        } else {
            Ok(NoFurtherArguments)
        }
    }

    /// Convert a "length of `rest`" into the corresponding column number.
    fn arg_column_from_rest_len(&self, rest_len: usize) -> usize {
        // Can't underflow since rest is always part of the whole.
        // Can't overflow since that would mean the document was as big as the address space.
        self.whole_line_len - rest_len + 1
    }

    /// Obtain the column number of the previously yielded argument.
    ///
    /// (After `into_remaining`, gives the column number
    /// of the start of the returned remaining argument string.)
    pub fn prev_arg_column(&self) -> usize {
        self.arg_column_from_rest_len(self.previous_rest_len)
    }

    /// Obtains the column number of the *next* argument.
    ///
    /// Should be called after `something_to_yield`; otherwise the returned value
    /// may point to whitespace which is going to be skipped.
    // ^ this possible misuse doesn't seem worth defending against with type-fu,
    //   for a private function with few call sites.
    fn next_arg_column(&self) -> usize {
        self.arg_column_from_rest_len(self.rest.len())
    }

    /// Convert an `ArgumentError` to an `ErrorProblem`.
    ///
    /// The caller must supply the field name.
    pub fn handle_error(&self, field: &'static str, ae: ArgumentError) -> ErrorProblem {
        self.error_handler(field)(ae)
    }

    /// Return a converter from `ArgumentError` to `ErrorProblem`.
    ///
    /// Useful in `.map_err`.
    pub fn error_handler(
        &self,
        field: &'static str,
    ) -> impl Fn(ArgumentError) -> ErrorProblem + 'static {
        let column = self.prev_arg_column();
        move |ae| match ae {
            AE::Missing => EP::MissingArgument { field },
            AE::Invalid => EP::InvalidArgument { field, column },
            AE::Unexpected => EP::UnexpectedArgument { column },
        }
    }
}

impl<'s> Iterator for ArgumentStream<'s> {
    type Item = &'s str;
    fn next(&mut self) -> Option<&'s str> {
        if !self.something_to_yield() {
            return None;
        }
        let arg;
        (arg, self.rest) = self.rest.split_once(WS).unwrap_or((self.rest, ""));
        Some(arg)
    }
}

impl<'s> UnparsedObject<'s> {
    /// Obtain the Object data, as decoded bytes
    pub fn decode_data(&self) -> Result<Vec<u8>, EP> {
        crate::parse::tokenize::base64_decode_multiline(self.data_b64)
            .map_err(|_e| EP::ObjectInvalidBase64)
    }
}
