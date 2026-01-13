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
///  * **Signature and timeliness has not been checked**.
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
                Err(EP::Other("authcert bad structure"))
            }
        };

        if kw == INTRO_KEYWORD {
            change_state(Intro, Body)
        } else if kw == FINAL_KEYWORD {
            change_state(Body, End)
        } else if *self != Body {
            Err(EP::Other(
                "authcert loose body item or missing intro keyword",
            ))
        } else if let Some(IsStructural) = NetworkStatusVote::is_structural_keyword(kw) {
            Err(EP::Other("authcert with vote structural keyword"))
        } else if kw == "fingerprint" || kw.as_str().starts_with("dir-") {
            Ok(None)
        } else {
            eprintln!("{kw:?}");
            Err(EP::Other("authcert body keyword not dir- or fingerprint"))
        }
    }

    /// Finish up, on EOF
    fn finish(self) -> Result<(), EP> {
        use ItemSequenceChecker::*;
        match self {
            End => Ok(()),
            _other => Err(EP::Other("authcert missing end (signature) item")),
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
        .ok_or(EP::Other("missing final newline"))?;

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
                        return Err(EP::Other(
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

        Ok(EncodedAuthCert(text.to_string()))
    }
}
