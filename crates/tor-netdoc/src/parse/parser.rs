//! Based on a set of rules, validate a token stream and collect the
//! tokens by type.
//!
//! See the "rules" module for definitions of keywords types and
//! per-keyword rules.
//!
//! The key types in this module are SectionRules, which explains how to
//! validate and partition a stream of Item, and Section, which contains
//! a validated set of Item, ready to be interpreted.
//!
//! # Example
//!
//! (This is an internal API, so see the routerdesc.rs source for an
//! example of use.)

use crate::parse::keyword::Keyword;
use crate::parse::rules::*;
use crate::parse::tokenize::*;
use crate::{NetdocErrorKind as EK, Result};

use educe::Educe;

/// Describe the rules for one section of a document.
///
/// The rules are represented as a mapping from token index to
/// rules::TokenFmt.
#[derive(Clone)]
pub(crate) struct SectionRules<T: Keyword> {
    /// A set of rules for decoding a series of tokens into a Section
    /// object.  Each element of this array corresponds to the
    /// token with the corresponding index values.
    ///
    /// When an array element is None, the corresponding keyword is
    /// not allowed in this kind section.  Otherwise, the array
    /// element is a TokenFmt describing how many of the corresponding
    /// token may appear, and what they need to look like.
    rules: Vec<Option<TokenFmt<T>>>,
}

/// The entry or entries for a particular keyword within a document.
#[derive(Clone, Educe)]
#[educe(Default)]
struct TokVal<'a, K: Keyword>(Vec<Item<'a, K>>);

impl<'a, K: Keyword> TokVal<'a, K> {
    /// Return the number of Items for this value.
    fn none() -> Self {
        Default::default()
    }
    /// Return the number of Items for this value.
    fn count(&self) -> usize {
        self.0.len()
    }
    /// Return the first Item for this value, or None if there wasn't one.
    fn first(&self) -> Option<&Item<'a, K>> {
        self.0.first()
    }
    /// Return the Item for this value, if there is exactly one.
    fn singleton(&self) -> Option<&Item<'a, K>> {
        match &*self.0 {
            [x] => Some(x),
            _ => None,
        }
    }
    /// Return all the Items for this value, as a slice.
    fn as_slice(&self) -> &[Item<'a, K>] {
        &self.0
    }
    /// Return the last Item for this value, if any.
    fn last(&self) -> Option<&Item<'a, K>> {
        self.0.last()
    }
}

/// A Section is the result of sorting a document's entries by keyword.
///
/// TODO: I'd rather have this be pub(crate), but I haven't figured out
/// how to make that work.
pub struct Section<'a, T: Keyword> {
    /// Map from Keyword index to TokVal
    v: Vec<TokVal<'a, T>>,
    /// The keyword that appeared first in this section.  This will
    /// be set if `v` is nonempty.
    first: Option<T>,
    /// The keyword that appeared last in this section.  This will
    /// be set if `v` is nonempty.
    last: Option<T>,
}

impl<'a, T: Keyword> Section<'a, T> {
    /// Make a new empty Section.
    fn new() -> Self {
        let n = T::n_vals();
        let mut v = Vec::with_capacity(n);
        v.resize(n, TokVal::none());
        Section {
            v,
            first: None,
            last: None,
        }
    }
    /// Helper: return the tokval for some Keyword.
    fn tokval(&self, t: T) -> &TokVal<'a, T> {
        let idx = t.idx();
        &self.v[idx]
    }
    /// Return all the Items for some Keyword, as a slice.
    pub(crate) fn slice(&self, t: T) -> &[Item<'a, T>] {
        self.tokval(t).as_slice()
    }
    /// Return a single Item for some Keyword, if there is exactly one.
    pub(crate) fn get(&self, t: T) -> Option<&Item<'a, T>> {
        self.tokval(t).singleton()
    }
    /// Return a single Item for some Keyword, giving an error if there
    /// is not exactly one.
    ///
    /// It is usually a mistake to use this function on a Keyword that is
    /// not required.
    pub(crate) fn required(&self, t: T) -> Result<&Item<'a, T>> {
        self.get(t)
            .ok_or_else(|| EK::MissingToken.with_msg(t.to_str()))
    }
    /// Return a proxy MaybeItem object for some keyword.
    //
    /// A MaybeItem is used to represent an object that might or might
    /// not be there.
    pub(crate) fn maybe<'b>(&'b self, t: T) -> MaybeItem<'b, 'a, T> {
        MaybeItem::from_option(self.get(t))
    }
    /// Return the first item that was accepted for this section, or None
    /// if no items were accepted for this section.
    pub(crate) fn first_item(&self) -> Option<&Item<'a, T>> {
        match self.first {
            None => None,
            Some(t) => self.tokval(t).first(),
        }
    }
    /// Return the last item that was accepted for this section, or None
    /// if no items were accepted for this section.
    pub(crate) fn last_item(&self) -> Option<&Item<'a, T>> {
        match self.last {
            None => None,
            Some(t) => self.tokval(t).last(),
        }
    }
    /// Insert an `item`.
    ///
    /// The `item` must have parsed Keyword `t`.
    fn add_tok(&mut self, t: T, item: Item<'a, T>) {
        let idx = Keyword::idx(t);
        if idx >= self.v.len() {
            self.v.resize(idx + 1, TokVal::none());
        }
        self.v[idx].0.push(item);
        if self.first.is_none() {
            self.first = Some(t);
        }
        self.last = Some(t);
    }
}

/// A builder for a set of section rules.
#[derive(Clone)]
pub(crate) struct SectionRulesBuilder<T: Keyword> {
    /// Have we been told, explicitly, to reject unrecognized tokens?
    strict: bool,
    /// The rules we're building.
    rules: SectionRules<T>,
}

impl<T: Keyword> SectionRulesBuilder<T> {
    /// Add a rule to this SectionRulesBuilder, based on a TokenFmtBuilder.
    ///
    /// Requires that no rule yet exists for the provided keyword.
    pub(crate) fn add(&mut self, t: TokenFmtBuilder<T>) {
        let rule: TokenFmt<_> = t.into();
        let idx = rule.kwd().idx();
        assert!(self.rules.rules[idx].is_none());
        self.rules.rules[idx] = Some(rule);
    }

    /// Explicitly reject any unrecognized tokens.
    ///
    /// To avoid errors, you must either explicitly reject unrecognized tokens,
    /// or you must define how they are handled.
    pub(crate) fn reject_unrecognized(&mut self) {
        self.strict = true;
    }

    /// Construct the SectionRules from this builder.
    ///
    /// # Panics
    ///
    /// Panics if you did not specify the behavior for unrecognized tokens,
    /// using either `reject_unrecognized` or `add(UNRECOGNIZED.rule()...)`
    pub(crate) fn build(self) -> SectionRules<T> {
        let unrecognized_idx = T::unrecognized().idx();
        assert!(
            self.strict || self.rules.rules[unrecognized_idx].is_some(),
            "BUG: Section has to handle UNRECOGNIZED tokens explicitly."
        );
        self.rules
    }
}

impl<T: Keyword> SectionRules<T> {
    /// Create a new builder for a SectionRules with no rules.
    ///
    /// By default, no Keyword is allowed by this SectionRules.
    pub(crate) fn builder() -> SectionRulesBuilder<T> {
        let n = T::n_vals();
        let mut rules = Vec::with_capacity(n);
        rules.resize(n, None);
        SectionRulesBuilder {
            strict: false,
            rules: SectionRules { rules },
        }
    }

    /// Parse a stream of tokens into a Section object without (fully)
    /// verifying them.
    ///
    /// Some errors are detected early, but others only show up later
    /// when we validate more carefully.
    fn parse_unverified<'a, I>(&self, tokens: I, section: &mut Section<'a, T>) -> Result<()>
    where
        I: Iterator<Item = Result<Item<'a, T>>>,
    {
        for item in tokens {
            let item = item?;

            let tok = item.kwd();
            let tok_idx = tok.idx();
            if let Some(rule) = &self.rules[tok_idx] {
                // we want this token.
                assert!(rule.kwd() == tok);
                section.add_tok(tok, item);
                rule.check_multiplicity(section.v[tok_idx].as_slice())?;
            } else {
                // We don't have a rule for this token.
                return Err(EK::UnexpectedToken
                    .with_msg(tok.to_str())
                    .at_pos(item.pos()));
            }
        }
        Ok(())
    }

    /// Check whether the tokens in a section we've parsed conform to
    /// these rules.
    fn validate(&self, s: &Section<'_, T>) -> Result<()> {
        // These vectors are both generated from T::n_vals().
        assert_eq!(s.v.len(), self.rules.len());

        // Iterate over every item, and make sure it matches the
        // corresponding rule.
        for (rule, t) in self.rules.iter().zip(s.v.iter()) {
            match rule {
                None => {
                    // We aren't supposed to have any of these.
                    if t.count() > 0 {
                        unreachable!(
                            "This item should have been rejected earlier, in parse_unverified()"
                        );
                    }
                }
                Some(rule) => {
                    // We're allowed to have this. Is the number right?
                    rule.check_multiplicity(t.as_slice())?;
                    // The number is right. Check each individual item.
                    for item in t.as_slice() {
                        rule.check_item(item)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check all the base64-encoded objects on a given keyword.
    ///
    /// We use this to validate objects on unrecognized items, since
    /// otherwise nothing would check that they are well-formed.
    fn validate_objects(&self, s: &Section<'_, T>, kwd: T) -> Result<()> {
        for item in s.slice(kwd).iter() {
            let _ = item.obj_raw()?;
        }
        Ok(())
    }

    /// Parse a stream of tokens into a validated section.
    pub(crate) fn parse<'a, I>(&self, tokens: I) -> Result<Section<'a, T>>
    where
        I: Iterator<Item = Result<Item<'a, T>>>,
    {
        let mut section = Section::new();
        self.parse_unverified(tokens, &mut section)?;
        self.validate(&section)?;
        self.validate_objects(&section, T::unrecognized())?;
        self.validate_objects(&section, T::ann_unrecognized())?;
        Ok(section)
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
    use super::SectionRules;
    use crate::parse::keyword::Keyword;
    use crate::parse::macros::test::Fruit;
    use crate::parse::tokenize::{Item, NetDocReader};
    use crate::{Error, NetdocErrorKind as EK, Result};
    use once_cell::sync::Lazy;

    /// Rules for parsing a set of router annotations.
    static FRUIT_SALAD: Lazy<SectionRules<Fruit>> = Lazy::new(|| {
        use Fruit::*;
        let mut rules = SectionRules::builder();
        rules.add(ANN_TASTY.rule().required().args(1..=1));
        rules.add(ORANGE.rule().args(1..));
        rules.add(STONEFRUIT.rule().may_repeat());
        rules.add(GUAVA.rule().obj_optional());
        rules.add(LEMON.rule().no_args().obj_required());
        rules.reject_unrecognized();
        rules.build()
    });

    #[test]
    fn parse_section() -> Result<()> {
        use Fruit::*;
        let s = "\
@tasty yes
orange soda
cherry cobbler
cherry pie
plum compote
guava fresh from 7 trees
-----BEGIN GUAVA MANIFESTO-----
VGhlIGd1YXZhIGVtb2ppIGlzIG5vdCBjdXJyZW50bHkgc3VwcG9ydGVkIGluI
HVuaWNvZGUgMTMuMC4gTGV0J3MgZmlnaHQgYWdhaW5zdCBhbnRpLWd1YXZhIG
JpYXMu
-----END GUAVA MANIFESTO-----
lemon
-----BEGIN LEMON-----
8J+Niw==
-----END LEMON-----
";
        let r: NetDocReader<'_, Fruit> = NetDocReader::new(s);
        let sec = FRUIT_SALAD.parse(r).unwrap();

        assert_eq!(sec.required(ANN_TASTY)?.arg(0), Some("yes"));

        assert!(sec.get(ORANGE).is_some());
        assert_eq!(sec.get(ORANGE).unwrap().args_as_str(), "soda");

        let stonefruit_slice = sec.slice(STONEFRUIT);
        assert_eq!(stonefruit_slice.len(), 3);
        let kwds: Vec<&str> = stonefruit_slice.iter().map(Item::kwd_str).collect();
        assert_eq!(kwds, &["cherry", "cherry", "plum"]);

        assert_eq!(sec.maybe(GUAVA).args_as_str(), Some("fresh from 7 trees"));
        assert_eq!(sec.maybe(GUAVA).parse_arg::<u32>(2).unwrap(), Some(7));
        assert!(sec.maybe(GUAVA).parse_arg::<u32>(1).is_err());

        // Try the `obj` accessor.
        assert_eq!(sec.get(GUAVA).unwrap().obj("GUAVA MANIFESTO").unwrap(),
                   &b"The guava emoji is not currently supported in unicode 13.0. Let's fight against anti-guava bias."[..]);
        assert!(matches!(
            sec.get(ORANGE)
                .unwrap()
                .obj("ORANGE MANIFESTO")
                .unwrap_err()
                .netdoc_error_kind(),
            EK::MissingObject // orange you glad there isn't a manifesto?
        ));

        // Try `maybe_item` a bit.
        let maybe_banana = sec.maybe(BANANA);
        assert!(maybe_banana.parse_arg::<u32>(3).unwrap().is_none()); // yes! we have none.
        let maybe_guava = sec.maybe(GUAVA);
        assert_eq!(maybe_guava.parse_arg::<u32>(2).unwrap(), Some(7));

        assert_eq!(
            sec.get(ANN_TASTY).unwrap() as *const Item<'_, _>,
            sec.first_item().unwrap() as *const Item<'_, _>
        );

        assert_eq!(
            sec.get(LEMON).unwrap() as *const Item<'_, _>,
            sec.last_item().unwrap() as *const Item<'_, _>
        );

        Ok(())
    }

    #[test]
    fn rejected() {
        use crate::Pos;
        fn check(s: &str, e: &Error) {
            let r: NetDocReader<'_, Fruit> = NetDocReader::new(s);
            let res = FRUIT_SALAD.parse(r);
            assert!(res.is_err());
            assert_eq!(&res.err().unwrap().within(s), e);
        }

        // unrecognized tokens aren't allowed here
        check(
            "orange foo\nfoobar x\n@tasty yes\n",
            &EK::UnexpectedToken
                .with_msg("<unrecognized>")
                .at_pos(Pos::from_line(2, 1)),
        );

        // Only one orange per customer.
        check(
            "@tasty yes\norange foo\norange bar\n",
            &EK::DuplicateToken
                .with_msg("orange")
                .at_pos(Pos::from_line(3, 1)),
        );

        // There needs to be a declaration of tastiness.
        check("orange foo\n", &EK::MissingToken.with_msg("@tasty"));

        // You can't have an orange without an argument.
        check(
            "@tasty nope\norange\n",
            &EK::TooFewArguments
                .with_msg("orange")
                .at_pos(Pos::from_line(2, 1)),
        );
        // You can't have an more than one argument on "tasty".
        check(
            "@tasty yup indeed\norange normal\n",
            &EK::TooManyArguments
                .with_msg("@tasty")
                .at_pos(Pos::from_line(1, 1)),
        );

        // Every lemon needs an object
        check(
            "@tasty yes\nlemon\norange no\n",
            &EK::MissingObject
                .with_msg("lemon")
                .at_pos(Pos::from_line(2, 1)),
        );

        // oranges don't take an object.
        check(
            "@tasty yes\norange no\n-----BEGIN ORANGE-----\naaa\n-----END ORANGE-----\n",
            &EK::UnexpectedObject
                .with_msg("orange")
                .at_pos(Pos::from_line(2, 1)),
        );
    }
}
