//! Keywords for interpreting items and rules for validating them.

use crate::parse::keyword::Keyword;
use crate::parse::tokenize::Item;
use crate::{NetdocErrorKind as EK, Result};

/// May an Item take an object?
#[derive(Copy, Clone)]
enum ObjKind {
    /// No object is allowed.
    NoObj,
    /// An object is required.
    RequireObj,
    /// An object is optional.
    ObjOk,
}

/// A set of restrictions to place on Items for a single keyword.
///
/// These are built by the TokenFmtBuilder API.
#[derive(Clone)]
pub(crate) struct TokenFmt<T: Keyword> {
    /// Which keyword is being restricted?
    kwd: T,
    /// If present, a lower bound on how many arguments may be present.
    min_args: Option<usize>,
    /// If present, an upper bound on how many arguments may be present.
    max_args: Option<usize>,
    /// If true, then at least one of this Item must appear.
    required: bool,
    /// If false, then no more than one this Item may appear.
    may_repeat: bool,
    /// May this Item have an object? Must it?
    obj: ObjKind,
}

impl<T: Keyword> TokenFmt<T> {
    /// Return the keyword that this rule restricts.
    pub(crate) fn kwd(&self) -> T {
        self.kwd
    }
    /// Check whether a single Item matches this TokenFmt rule, with respect
    /// to its number of arguments.
    fn item_matches_args(&self, item: &Item<'_, T>) -> Result<()> {
        let n_args = item.n_args();
        if let Some(max) = self.max_args {
            if n_args > max {
                return Err(EK::TooManyArguments
                    .with_msg(self.kwd.to_str())
                    .at_pos(item.pos()));
            }
        }
        if let Some(min) = self.min_args {
            if n_args < min {
                return Err(EK::TooFewArguments
                    .with_msg(self.kwd.to_str())
                    .at_pos(item.pos()));
            }
        }
        Ok(())
    }

    /// Check whether a single Item matches a TokenFmt rule, with respect
    /// to its object's presence and type.
    fn item_matches_obj(&self, item: &Item<'_, T>) -> Result<()> {
        match (&self.obj, item.has_obj()) {
            (ObjKind::NoObj, true) => Err(EK::UnexpectedObject
                .with_msg(self.kwd.to_str())
                .at_pos(item.pos())),
            (ObjKind::RequireObj, false) => Err(EK::MissingObject
                .with_msg(self.kwd.to_str())
                .at_pos(item.pos())),
            (_, _) => Ok(()),
        }
    }

    /// Check whether a single item has the right number of arguments
    /// and object.
    pub(crate) fn check_item(&self, item: &Item<'_, T>) -> Result<()> {
        self.item_matches_args(item)?;
        self.item_matches_obj(item)
    }

    /// Check whether this kind of item may appear this many times.
    pub(crate) fn check_multiplicity(&self, items: &[Item<'_, T>]) -> Result<()> {
        match items.len() {
            0 => {
                if self.required {
                    return Err(EK::MissingToken.with_msg(self.kwd.to_str()));
                }
            }
            1 => (),
            _ => {
                if !self.may_repeat {
                    return Err(EK::DuplicateToken
                        .with_msg(self.kwd.to_str())
                        .at_pos(items[1].pos()));
                }
            }
        }
        Ok(())
    }
}

/// Represents a TokenFmt under construction.
///
/// To construct a rule, create this type with Keyword::rule(), then
/// call method on it to set its fields, and then pass it to
/// SectionRules::add().
///
/// # Example
///
/// ```ignore
/// // There must be exactly one "ROUTER" entry, with 5 or more arguments.
/// section_rules.add(D.rule().required().args(5..));
/// ```
///
/// TODO: I'd rather have this be pub(crate), but I haven't figured out
/// how to make that work.  There are complicated cascading side-effects.
pub struct TokenFmtBuilder<T: Keyword>(TokenFmt<T>);

impl<T: Keyword> From<TokenFmtBuilder<T>> for TokenFmt<T> {
    fn from(builder: TokenFmtBuilder<T>) -> Self {
        builder.0
    }
}

impl<T: Keyword> TokenFmtBuilder<T> {
    /// Make a new TokenFmtBuilder with default behavior.
    ///
    /// (By default, all arguments are allowed, the Item may appear 0
    /// or 1 times, and it may not take an object.)
    pub(crate) fn new(t: T) -> Self {
        Self(TokenFmt {
            kwd: t,
            min_args: None,
            max_args: None,
            required: false,
            may_repeat: false,
            obj: ObjKind::NoObj,
        })
    }

    /// Indicate that this Item is required.
    ///
    /// By default, no item is required.
    pub(crate) fn required(self) -> Self {
        Self(TokenFmt {
            required: true,
            ..self.0
        })
    }

    /// Indicate that this Item may appear more than once.
    ///
    /// By default, items may not repeat.
    pub(crate) fn may_repeat(self) -> Self {
        Self(TokenFmt {
            may_repeat: true,
            ..self.0
        })
    }

    /// Indicate that this Item takes no arguments.
    ///
    /// By default, items may take any number of arguments.
    pub(crate) fn no_args(self) -> Self {
        Self(TokenFmt {
            max_args: Some(0),
            ..self.0
        })
    }
    /// Indicate that this item takes a certain number of arguments.
    ///
    /// The number of arguments is provided as a range, like `5..`.
    pub(crate) fn args<R>(self, r: R) -> Self
    where
        R: std::ops::RangeBounds<usize>,
    {
        use std::ops::Bound::*;
        let min_args = match r.start_bound() {
            Included(x) => Some(*x),
            Excluded(x) => Some(*x + 1),
            Unbounded => None,
        };
        let max_args = match r.end_bound() {
            Included(x) => Some(*x),
            Excluded(x) => Some(*x - 1),
            Unbounded => None,
        };
        Self(TokenFmt {
            min_args,
            max_args,
            ..self.0
        })
    }
    /// Indicate that this token takes an optional object.
    ///
    /// By default, objects are not allowed.
    pub(crate) fn obj_optional(self) -> Self {
        Self(TokenFmt {
            obj: ObjKind::ObjOk,
            ..self.0
        })
    }
    /// Indicate that this token takes an required object.
    ///
    /// By default, objects are not allowed.
    pub(crate) fn obj_required(self) -> Self {
        Self(TokenFmt {
            obj: ObjKind::RequireObj,
            ..self.0
        })
    }
}
