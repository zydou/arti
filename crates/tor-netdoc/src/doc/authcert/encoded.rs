//! `EncodedAuthCert`

use std::str::FromStr;

use crate::parse2::{
    ErrorProblem, IsStructural, ItemStream, KeywordRef, NetdocParseable, ParseInput,
};

use ErrorProblem as EP;

use crate::parse2::poc::netstatus::NetworkStatusVote; // TODO DIRAUTH abolish poc

/// Entire authority key certificate, encoded and signed
///
/// This is a newtype around `String`.
///
/// # Invariants
///
///  * Is a complete document in netdoc metasyntax including trailing newline.
///  * Starts with one `dir-key-certificate-version`
///  * Ends with one `dir-key-certification`
///  * No other items are structural in a vote
///  * Every item keyword starts `dir-` or is `fingerprint`
///
/// See
/// <https://spec.torproject.org/dir-spec/creating-key-certificates.html#nesting>
///
/// ## Non-invariant
///
///  * **Signature and timeliness have not been checked**.
///
/// # Functionality
///
/// Implements `TryFrom<String>` and `FromStr`.
///
/// Implements `NetdocParseable`:
/// parser matches `dir-key-certificate-version` and `dir-key-certification`,
/// but also calls `Bug` if the caller's `stop_at`
/// reports that this keyword is structural for its container.
/// (This could happen if an `EncodedAuthCert` existedd in some other
/// document but a vote.  We do not check this property during encoding.)
///
/// # Rationale
///
/// Unlike most sub-documents found within netdocs, an authcert is a
/// signed document.  We expect to be able to copy an authcert into a
/// vote, encode, convey and parse the vote, and extract the
/// authcert, and verify the authcert's signature.
///
/// Additionally, the fact that authcerts have their own signatures means
/// that they need to be constructed separately from the surrounding
/// document, and then embedded in it later.
///
/// When parsing a vote, we need to be able to see *which parts* are
/// the authcert, and we need to be able to extract the specific document
/// text, but we maybe don't want to parse the authcert.
///
/// Conversely, signature verification of authcerts during decoding of a
/// vote is fairly complex.  We don't want to do signature
/// verification during parsing, because signature verification involves
/// the time, and we don't want parsing to need to know the time.
///
// ## Generics (possible future expansion)
//
// If we discover other similar document nestings we could genericise things:
//
// ```
// /// Invariant:
// ///
// ///  * Can be lexed as a netdoc
// ///  * First item is `Y:is_intro_item_keyword`
// ///  * Last item is (one) `YS:is_intro_item_keyword`
// ///  * No other item is any `N::is_structual_item_keyword`
// ///
// pub struct EncodedNetdoc<Y, YS, (N0, N1 ..)>(String);
//
// pub type EncodedAuthCert = EncodedNetdoc<
//     AuthCert, AuthCertSignatures,
//     (NetworkStatusVote, NetworkStatusSignaturesVote)
// >;
// ```
//
// Details TBD.
//
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, derive_more::AsRef)]
pub struct EncodedAuthCert(#[as_ref(str)] String);

/// State (machine) for checking item sequence
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ItemSequenceChecker {
    /// Expecting intro item
    Intro,
    /// Expecting body item
    Body,
    /// Expecting no more items
    End,
}

/// Token indicating keyword is structural for us
struct IsOurStructural;

/// auth cert's intro item
const INTRO_KEYWORD: &str = "dir-key-certificate-version";
/// auth cert's final item, used for bracketing
const FINAL_KEYWORD: &str = "dir-key-certification";

impl EncodedAuthCert {
    /// Obtain the document text as a `str`
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ItemSequenceChecker {
    /// Start the state machine
    fn start() -> Self {
        use ItemSequenceChecker::*;
        Intro
    }

    /// Process and check an item (given the keyword)
    fn keyword(&mut self, kw: KeywordRef<'_>) -> Result<Option<IsOurStructural>, EP> {
        use ItemSequenceChecker::*;

        let mut change_state = |from, to| {
            if *self == from {
                *self = to;
                Ok(Some(IsOurStructural))
            } else {
                Err(EP::OtherBadDocument("authcert bad structure"))
            }
        };

        if kw == INTRO_KEYWORD {
            change_state(Intro, Body)
        } else if kw == FINAL_KEYWORD {
            change_state(Body, End)
        } else if *self != Body {
            Err(EP::OtherBadDocument(
                "authcert loose body item or missing intro keyword",
            ))
        } else if let Some(IsStructural) = NetworkStatusVote::is_structural_keyword(kw) {
            Err(EP::OtherBadDocument(
                "authcert with vote structural keyword",
            ))
        } else if kw == "fingerprint" || kw.as_str().starts_with("dir-") {
            Ok(None)
        } else {
            Err(EP::OtherBadDocument(
                "authcert body keyword not dir- or fingerprint",
            ))
        }
    }

    /// Finish up, on EOF
    fn finish(self) -> Result<(), EP> {
        use ItemSequenceChecker::*;
        match self {
            End => Ok(()),
            _other => Err(EP::OtherBadDocument(
                "authcert missing end (signature) item",
            )),
        }
    }
}

/// Additional lexical checks
///
/// These might or might not be done by `parse2::lex`.
/// We do them here to be sure.
fn extra_lexical_checks(s: &str) -> Result<(), EP> {
    // Lexical checks (beyond those done by the lexer)

    let _without_trailing_nl = s
        // In case our lexer tolerates this
        .strip_suffix("\n")
        .ok_or(EP::OtherBadDocument("missing final newline"))?;

    Ok(())
}

/// Check that `s` meets the constraints
fn check(s: &str) -> Result<(), EP> {
    extra_lexical_checks(s)?;

    // Structural checks
    let input = ParseInput::new(s, "<authcert string>");
    let mut lex = ItemStream::new(&input).map_err(|e| e.problem)?;
    let mut seq = ItemSequenceChecker::start();
    while let Some(item) = lex.next_item()? {
        seq.keyword(item.keyword())?;
    }
    seq.finish()
}

impl TryFrom<String> for EncodedAuthCert {
    type Error = ErrorProblem;
    fn try_from(s: String) -> Result<Self, EP> {
        check(&s)?;
        Ok(EncodedAuthCert(s))
    }
}

impl FromStr for EncodedAuthCert {
    type Err = ErrorProblem;
    fn from_str(s: &str) -> Result<Self, EP> {
        s.to_owned().try_into()
    }
}

impl NetdocParseable for EncodedAuthCert {
    fn doctype_for_error() -> &'static str {
        "encoded authority key certificate"
    }

    fn is_intro_item_keyword(kw: KeywordRef<'_>) -> bool {
        kw == INTRO_KEYWORD
    }
    fn is_structural_keyword(kw: KeywordRef<'_>) -> Option<IsStructural> {
        (Self::is_intro_item_keyword(kw) || kw == FINAL_KEYWORD).then_some(IsStructural)
    }

    fn from_items(input: &mut ItemStream<'_>, stop_at: stop_at!()) -> Result<Self, EP> {
        let start_pos = input.byte_position();
        let mut seq = ItemSequenceChecker::start();
        while seq != ItemSequenceChecker::End {
            let item = input.next_item()?.ok_or(EP::MissingItem {
                keyword: FINAL_KEYWORD,
            })?;

            let kw = item.keyword();

            match seq.keyword(kw)? {
                Some(IsOurStructural) => {} // already checked
                None => {
                    if stop_at.stop_at(kw) {
                        return Err(EP::Internal(
                            "bug! parent document structural keyword found while trying to process an embedded authcert, but was accepted by ItemSequenceChecker; authcert embedded in something other than a vote?",
                        ));
                    }
                }
            }
        }
        seq.finish()?;

        let text = input
            .whole_input()
            .get(start_pos..)
            .expect("start_pos wasn't included in the body so far?!");

        extra_lexical_checks(text)?;

        if let Some(next_item) = input.peek_keyword()? {
            if !stop_at.stop_at(next_item) {
                return Err(EP::OtherBadDocument(
                    "unexpected loose items after embedded authcert",
                ));
            }
        }

        Ok(EncodedAuthCert(text.to_string()))
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use crate::parse2::parse_netdoc;
    use derive_deftly::Deftly;
    use std::fmt::{Debug, Display};

    #[derive(Debug, Deftly)]
    #[derive_deftly(NetdocParseable)]
    #[allow(unused)]
    struct Embeds {
        e_intro: (),
        #[deftly(netdoc(subdoc))]
        cert: EncodedAuthCert,
        #[deftly(netdoc(subdoc))]
        subdocs: Vec<Subdoc>,
    }
    #[derive(Debug, Deftly)]
    #[derive_deftly(NetdocParseable)]
    #[allow(unused)]
    struct Subdoc {
        dir_e_subdoc: (),
    }

    fn chk(exp_sole: Result<(), &str>, exp_embed: Result<(), &str>, doc: &str) {
        fn chk1<T: Debug, E: Debug + tor_error::ErrorReport + Display>(
            exp: Result<(), &str>,
            doc: &str,
            what: &str,
            got: Result<T, E>,
        ) {
            eprintln!("==========\n---- {what} 8<- ----\n{doc}---- ->8 {what} ----\n");
            match got {
                Err(got_e) => {
                    let got_m = got_e.report().to_string();
                    eprintln!("{what}, got error: {got_e:?}");
                    eprintln!("{what}, got error: {got_m:?}");
                    let exp_m = exp.expect_err("expected success!");
                    assert!(
                        got_m.contains(exp_m),
                        "{what}, expected different error: {exp_m:?}"
                    );
                }
                y @ Ok(_) => {
                    eprintln!("got {y:?}");
                    assert!(exp.is_ok(), "{what}, unexpected success; expected: {exp:?}");
                }
            }
        }
        chk1(exp_sole, doc, "from_str", EncodedAuthCert::from_str(doc));
        chk1(
            exp_sole,
            doc,
            "From<String>",
            EncodedAuthCert::try_from(doc.to_owned()),
        );
        let embeds = format!(
            r"e-intro
ignored
{doc}dir-e-subdoc
dir-ignored-2
"
        );
        let parse_input = ParseInput::new(&embeds, "<embeds>");
        chk1(
            exp_embed,
            &embeds,
            "embedded",
            parse_netdoc::<Embeds>(&parse_input),
        );
    }

    #[test]
    fn bad_authcerts() {
        NetworkStatusVote::is_structural_keyword(KeywordRef::new("dir-source").unwrap())
            .expect("structural dir-source");

        // These documents are all very skeleton: none of the items have arguments, or objects.
        // It works anyway because we don't actually parse as an authcert, when reading an
        // EncodedAuthCert.  We just check the item keyword sequence.

        chk(
            Err("missing final newline"),
            Err("missing item encoded authority key certificate"),
            r"",
        );
        chk(
            Err("authcert loose body item or missing intro keyword"),
            Err("missing item encoded authority key certificate"),
            r"wrong-intro
",
        );
        chk(
            Err("missing final newline"),
            Err("missing item dir-key-certification"),
            r"dir-key-certificate-version
dir-missing-nl",
        );
        chk(
            Err("authcert bad structure"),
            Err("authcert bad structure"),
            r"dir-key-certificate-version
dir-key-certificate-version
",
        );
        chk(
            Err("authcert body keyword not dir- or fingerprint"),
            Err("authcert body keyword not dir- or fingerprint"),
            r"dir-key-certificate-version
wrong-item
dir-key-certification
",
        );
        chk(
            Err("authcert with vote structural keyword"),
            Err("authcert with vote structural keyword"),
            r"dir-key-certificate-version
r
dir-key-certification
",
        );
        chk(
            Err("authcert with vote structural keyword"),
            Err("authcert with vote structural keyword"),
            r"dir-key-certificate-version
dir-source
dir-key-certification
",
        );
        chk(
            Ok(()), // Simulate bug where EncodedAuthCert doesn't know about our dir-e-subdoc
            Err("bug! parent document structural keyword found"),
            r"dir-key-certificate-version
dir-e-subdoc
dir-key-certification
",
        );
        chk(
            Err("authcert with vote structural keyword"),
            Err("authcert with vote structural keyword"),
            r"dir-key-certificate-version
dir-example-item
r
",
        );
        chk(
            Err("authcert loose body item or missing intro keyword"),
            Err("unexpected loose items after embedded authcert"),
            r"dir-key-certificate-version
dir-example-item
dir-key-certification
dir-extra-item
r
",
        );
        chk(
            Err("authcert bad structure"),
            Err("authcert bad structure"),
            r"dir-key-certificate-version
dir-key-certificate-version
dir-example-item
dir-key-certification
dir-key-certification
r
",
        );
        chk(
            Err("authcert bad structure"),
            Err("unexpected loose items after embedded authcert"),
            r"dir-key-certificate-version
dir-example-item
dir-key-certification
dir-key-certification
r
",
        );
    }
}
