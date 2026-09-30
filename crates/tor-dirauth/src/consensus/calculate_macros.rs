//! Macros to help implement consensus calculations
//!
//! See `calc!` (and `construct!` for usage documentation.
//!
//! ### Objective and rationale
//!
//! The primary objective is to avoid repetition of field names when computing
//! aggregates, to prevent bugs like this:
//!
//! ```rust,ignore
//! let output_lifetime = Lifetime {
//!     valid_after: low_median(votes.iter().map(|v| v.valid_after)),
//!     fresh_until: low_median(votes.iter().map(|v| v.fresh_until)),
//!     valid_until: low_median(votes.iter().map(|v| v.valid_after)), // <- BUG
//! };
//! ```
//!
//! Instead, we want the calculation of each field to mention that field name only once.
//!
//! A complication is that we want to be able to calculate both plain and md consensuses;
//! functions that calculate multiple flavours need to have *two* outputs,
//! but usually we want to state the method for calculating a field only once,
//! if it is the same for both flavours.
//!
//! Ideally we would support natural code flow, so that calculations can be gated by
//! `if` etc., and other caller code interspersed.  That will allow a user to
//! mix-and-match use of this macro with ad-hoc code.
//!
//! This means we can't directly output a struct display, all in one go.
//! (If we did, things would sometimes be in a weird order, also because with `Constructor`
//! the mandatory fields have to come last, unless we use a temporary for the base value.)
//!
//! #### Desired programmer API
//!
//! Instead, we want a macro-like syntax for *one* field calculation
//! that can appear as a statement within the implementing function body.
//!
//! Additionally, we don't want this standalone macro call to require
//! explicit restatement of the input expression (the set of votes),
//! nor of the context that needs to be threaded through the whole calculation.
//!
//! Therefore the field calculation macro is unhygienic,
//! Likewise there are output struct `construct!` macros that use the same conventions.
//!
//! #### Consequences - local variable scheme
//!
//! To achieve this without writing a code-walker (which would would be a horrific
//! recursive tt-muncher, or a bespoke proc-macro) we define a real standalone macro
//! that performs one field calculation.
//!
//! That macro needs to store the calculated output field value in a local variable.
//! These local variables can't just be the field names because with flavours
//! there are multiple sets of outputs, and also field names are sometimes quite generic
//! which could cause identifier clashes.
//!
//! So we use a prefixing scheme: the macro accepts field names,
//! but expands to bindings like `out_field`, `plain_field`, or `md_field`.
//!
//! ### Hygiene defeat via (ab)use of derive-deftly
//!
//! So, we want to explicitly control the hygiene spans of some of our output identifiers.
//!
//! This cannot be done by pure macro_rules.  `paste` can't do it.
//! (TODO <https://github.com/AS1100K/pastey/issues/42> pastey might allow respanning in future).
//! There is a `set-span` crate but that would be another dependency and
//! its invocation syntax is complex (as a consequence of Rust macro limitations).
//!
//! However: `derive-deftly`'s `${paste_spanned ...}` can do it.
//! There are then two wrinkles:
//!
//!  * derive-deftly wants to derive from something.  That's [`DummyForMacrology`]:
//!    we `derive_deftly_adhoc!` from it.  We don't actually *use* it.
//!
//!  * Dollar signs.  OMG dollar signs.  macro_rules macros have trouble generating output
//!    containing dollar signs; the expansion part has weird restrictions
//!    about where literal dollar signs can appear, and there is no escaping syntax.
//!
//!    We work around this in a fairly usual way - by passing an explicit dollar sign
//!    as a loose token and capture the dollar in a `$D` argument.  This allows those
//!    macro_rules arms to expand to derive-deftly invocations, using `$D` to invoke
//!    derive-deftly expansion features.
//!
//! So, in those macro_rules arms:
//!
//!  * `$foo` means a macro_rules template parameter.
//!
//!  * `$D foo`, `$D{foo ...}` mean the derive-deftly expansion `foo`,
//!    `$D< >` means derive-deftly's paste function, and so on.
//!
//!  * `$D$D` denotes a literal dollar sign in d-d output.
//!    (This is needed when a derive-deftly template needs to expand to a macro_rules invocation
//!    that will in turn use derive-deftly again.)
//!
//! This is sufficient to replace the `paste` crate completely, so we use this technique
//! throughout, rather than mixing use of deftly and the paste crate.

use super::*;

/// Dummy struct to allow use of derive-deftly to defeat hygiene - see the module-level docs
#[derive(Deftly)]
#[derive_deftly_adhoc]
#[allow(dead_code)]
pub(super) struct DummyForMacrology;

/// Calculates one consensus output field (possibly in multiple flavours), from votes
///
/// Calculates the value of one output field in a consensus or consensus component,
/// and makes bindings useful for `construct!` or `construct_pair!`.
///
/// Usually, calculates the value from the corresponding field in the input votes,
/// using [`Aggregate::aggregate`],
/// or two values (one per flavour) using [`ConsensusesFromVotes::consensuses`].
///
/// Uses the values **`votes`** and `**context**` from the surrounding scope,
/// **unhygienically**.
///
/// Intended for use in implementations of `Aggregate` and `ConsensusesFromVotes`.
///
/// ### Input syntaxes and semantics summary
///
/// ```rust,ignore
/// calc!{ OUT.FIELD <+ FUNC }       // calls FUNC on `ConsensusContext` and `ComponentInVotes`
/// calc!{ OUT.FIELD }               // uses Aggregate (or ConsensusesFromVotes)
/// calc!{ OUT.FIELD = EXPR }
/// calc!{ both.FIELD      .. .. }   // special, sets (plain_FIELD, md_FIELD)
/// calc!{ OUT1,OUT2.FIELD .. .. }   // calculates each OUT_FIELD the same way
/// ```
///
/// ### Environment, and (lack of) hygiene
///
/// The surrounding scope must contain:
///
/// ```rust,ignore
/// context: &CalculationContext,
/// inputs: impl ComponentInVotes<_>,
/// ```
///
/// These values are used unhygienically, to avoid the need to repeat their names
/// in every `calc!` call.
///
/// Errors from `FUNC` will be thrown with `?`.
///
/// ### Expansion
///
/// ```
/// // once for each OUT
/// let OUT_FIELD = .. .. ..;
/// // value expression uses `inputs` and `context`
/// ```
///
/// ### Arguments
///
///  * Each **`OUT`** is the prefix for the bindings.
///    Usually, `md`, `plain` when implementing [`ConsensusesFromVotes`].
///    or `out` when implementing [`Aggregate`].
///
///  * **`FUNC`** must have the signature of `Aggregate::aggregate`,
///    (or `ConsensusesFromVotes::consensuses` with `both`).
///
///  * **`both`**  for `OUT` (on its own) means to bind the tuple
///    `(plain_FIELD, md_FIELD)`; and the default `FUNC` is `ConsensusesFromVotes`.
///
///    With `both ... = `, `EXPR` is evaluated twice,
///    and `plain_FIELD` and `md_FIELD` are bound separately.
macro_rules! calc { { $($input:tt)* } => { calc_internal! { { $($input)* } {let} } } }

/// Like `calc` but assigns rather than binding
///
/// See [`calc!`].
///
/// ### Expansion
///
/// ```
/// # let OUT_FIELD;
/// // once for each OUT
/// OUT_FIELD = .. .. ..;
/// ```
#[allow(unused_macros)] // Let's keep this; otherwise it might be v. annoying when we need it
macro_rules! calc_assign { { $($input:tt)* } => { calc_internal! { { $($input)* } {} } } }

/// Implementation of `calc!` and `calc_assign!`.  Do not call directly.
macro_rules! calc_internal {
    // ----- Initial input syntax -----
    //
    //     { ORIGINAL INPUT.. } { LET }
    //
    // LET is `let` or nothing, depending whether this is `calc!` or `calc_assign!`
    //
    // Putting the original input first like this makes error messages a bit less
    // confusing - the compiler tends to point to relevant bits of our matching arms.
    // We do input syntax verification on this input syntax.
    //
    // We sequentially transform more-defaulted to more-explicit forms,
    // until we have the fully-specified form.

    // Function not specified - special case for `both`; refine to more-fully-specified input
    { { both. $f:ident $(;)?
    } $let:tt } => {
        calc_internal! { {
            both. $f <+ $crate::consensus::framework::ConsensusesFromVotes::consensuses
        } $let }
    };

    // function not specified - not `both`; refine to more-fully-specified input
    { { $($out:ident),+ $(,)? . $f:ident $(;)?
    } $let:tt } => {
        calc_internal! { {
            $($out),+ . $f <+ $crate::consensus::framework::Aggregate::aggregate
        } $let }
    };

    // function specified, RHS uses `<+`; convert into internal syntax
    { { $($out:ident),+ $(,)? . $f:ident <+ $func:expr $(;)?
    } $let:tt } => {
        calc_internal! {
            @ 1 {$} $let
            $($out),+ . $f { <+ $func }
        }
    };

    // RHS uses `= EXPR`; convert into internal syntax
    { { $($out:ident),+ $(,)? . $f:ident = $expr:expr $(;)?
    } $let:tt } => {
        calc_internal! {
            @ 1 {$} $let
            $($out),+ . $f { = $expr }
        }
    };

    // ----- Internal syntax 1 -----
    //
    //     @ 1 {$} {let} OUTPUT,.. . FIELD { RHS }
    //
    // Expands to actual implementation of binding or assignment

    // Special case for `both .. = ..`, since we don't want to expect a tuple then
    { @ 1 {$D:tt} { $($let:tt)? } both $(,)? . $f:ident { = $expr:expr } } => {
        derive_deftly::derive_deftly_adhoc! {
            DummyForMacrology beta_deftly:
            $($let)? $D{paste_spanned $f { plain_ $f }} = $expr;
            $($let)? $D{paste_spanned $f { md_    $f }} = $expr;
        }
    };

    // Special case for `both .. <+ ..`.
    // (We accept any RHS here, because we want it as a single tt for repeat reasons;
    // if the RHS isn't `<+` it must be `=`, because we checked the user's input syntax,
    // and `=` is handled above.)
    { @ 1 {$D:tt} { $($let:tt)? } both $(,)? . $f:ident $rhs:tt } => {
        derive_deftly::derive_deftly_adhoc! {
            DummyForMacrology beta_deftly:
            $($let)?
                ( $D{paste_spanned $f { plain_ $f }},
                  $D{paste_spanned $f { md_    $f }} )
                = calc_internal!( @ 2 {$D$D} $f $rhs );
        }
    };

    // One OUPTUT, not being `both`.
    { @ 1 {$D:tt} { $($let:tt)? } $out:ident $(,)? . $f:ident $rhs:tt } => {
        derive_deftly::derive_deftly_adhoc! {
            DummyForMacrology beta_deftly:
            $($let)?
                $D{paste_spanned $f { $out _ $f }}
                = calc_internal!( @ 2 {$D$D} $f $rhs );
        }
    };

    // Several OUTPUT.  Resolve into multiple invocations with one each.
    // We must do this separately because otherwise macro_rules gets confused about repetition.
    { @ 1 {$D:tt} $let:tt $($out:ident),+ . $f:ident $rhs:tt } => {
        $(
            // TODO it would be better to .clone() the result, rather than recalculating it.
            calc_internal! {
                @ 1 {$} $let $out . $f $rhs
            }
        )*
    };

    // ----- Internal syntax 2, resolve the RHS (`<+` or `=`) -----
    //
    //     @ 2 {D} FIELD { RHS }
    //
    // Expands to an expression.

    // RHS is `<+ FUNC`
    { @ 2 {$D:tt} $f:ident { <+ $func:expr } } => {
        derive_deftly::derive_deftly_adhoc! {
            DummyForMacrology beta_deftly:
            ($func) (
                $D{paste_spanned $f context},
                $D{paste_spanned $f inputs}.clone().map(|(vnum, i)| (vnum, &i.$f)),
            )?
        }
    };

    // RHS is `= EXPR`
    { @ 2 {$D:tt} $f:ident { = $expr:expr } } => {
        $expr
    };

    // ----- If this macro is buggy, don't blame the user -----
    { @ $dummy:literal $($error:tt)* } => {
        compile_error!(concat!(
            "MACRO INTERNAL ERROR calc!: ",
            stringify!($dummy:literal $($error)*)
        ))
    };
}

/// Constructs a struct using `Constructor`, from local variables
///
/// Expands to a struct literal, constructing a `STRUCT`
/// from local variables `PREFIX_FIELD`, using `TYPEConstructor`.
///
/// ### Input syntax
///
/// ```rust,ignore
/// construct! {
///     STRUCT {
///       // mandatory fields (in Constructor)
///        PREFIXM0 . FIELDM00, FIELDM01, FIELDM02 .. ..;
///        PREFIXM1 . FIELDM10 .. ..;
///        .. ..
///     } {
///        // optional fields
///        PREFIXO0 . FIELDO00, FIELDO01, FIELDO02 .. ..;
///        PREFIXO1 . FIELDO10 .. ..;
///        .. ..
///     }
/// }
/// ```
///
/// ### Semantics
///
/// Each `FIELD` must be a field in `Struct`.
/// There must be a corresponding local variable `PREFIX_FIELD`
/// of the right type, which will be moved into the constructed struct.
///
/// The first `{ }` contains mandatory fields, which must correspond 1:1 with
/// fields in the `Constructor`.
///
/// ### Generated code
///
/// ```rust,ignore
/// STRUCT {
///     FIELDO00: PREFIXO0_FIELDO00,
///     FIELDO01: PREFIXO0_FIELDO01,
///     // etc
///     ..STRUCTConstructor {
///         FIELDM00: PREFIXM0_FIELDM00,
///         FIELDM01: PREFIXM0_FIELDM01,
///         // etc
///     }.construct()
/// }
/// ```
//
// This macro also handles the implementation of `construct_both!`
macro_rules! construct {
    // ----- input syntax -----
    //
    // Parse the input syntax, and distribute the multiple fields for each output,
    // so that from now on we handle only one field at a time.
    //
    // We must decompose the type path, because $ty:path would make an AST pseudo-token
    // which can't be disassembled.  derive-deftly might be able to disassemble it,
    // but then we couldn't use $< ... > on it because deftly only allows "complex" elements
    // in paste if they come from the driver, not the template.  We could work around
    // this by having a local dummy struct with a deftly meta attr with the type in,
    // but then we'd be defining multiple dummy structs with the same name in different
    // scopes, which causes macro definition ambiguity errors.
    //
    // This means we don't support type paths with generics.  That's OK for our purposes.
    { $ty_i0:ident $(:: $ty_is:ident)*
      { $( $p_m:ident . $($f_m:ident),* $(,)? ; )* }
      { $( $p_o:ident . $($f_o:ident),* $(,)? ; )* }
      $(;)?
    } => {
        construct! {
            @ 1 {$} [] [ $ty_i0 $(:: $ty_is)* ]
            { $( $( $p_m . $f_m ; )* )* }
            { $( $( $p_o . $f_o ; )* )* }
        }
    };

    // ----- internal syntax 1 -----
    //
    // (a)   @ 1 {$} [TYPE PATH PREFIX] [UNPROCESSED TYPE PATH] {FIELDS_M..} {FIELDS_O..}
    // (b)   @ 1 {$} [TYPE PATH PREFIX] [TYPE_LEAF_NAME]        {FIELDS_M..} {FIELDS_O..}
    //
    // {FIELDS_*..} are { OUT . IDENT; OUT . IDENT; OUT . IDENT; .. }

    // tt-munch until UNPROCESSED TYPE PATH is just a single ident, the leaf,
    // turning (a) into (b).
    { @ 1 {$D:tt} [$($ty_pfx:tt)*] [$ty_i1:ident :: $($ty_rhs:tt)+] $($rhs:tt)*
    } => {
        construct! {
            @ 1 {$} [$($ty_pfx)* $ty_i1 ::] [$($ty_rhs)*] $($rhs)*
        }
    };

    // Handle the resolved syntax ((b), above)
    //  - construct the recipe for the Constructor type name
    //  - reinvoke ourselves twice, once for the optional fields and once for the mandatory ones
    { @ 1 {$D:tt} [$($ty_pfx:tt)*] [$ty_leaf:ident]
      { $( $p_m:ident . $f_m:ident ; )* }
      { $( $p_o:ident . $f_o:ident ; )* }
    } => {
        construct! {
            @ 2 {$}
            [$($ty_pfx)* $ty_leaf]
            { $( $p_o . $f_o ; )* }
            .. construct!{
                @ 2 {$D$D}
                // Set span explicitly so that errors go to the right place.
                // (Default span of $< > is the template's $< > invocation,
                // not the span of any of the literal template elements.
                // That distinction doesn't usually matter for derive-deftly, but here
                // our templates are a mixture of our own macro text, and input identifiers.)
                [$($ty_pfx)* $D{paste_spanned $ty_leaf { $ty_leaf Constructor }}]
                { $( $p_m . $f_m ; )* }
            }
            .construct()
        }
    };

    // ----- internal syntax 2 -----
    //
    //     @ 2 {D} [TYPE NAME RECIPE] {
    //         OUT . FIELD;
    //         OUT . FIELD;
    //         etc.
    //     }
    //
    // TYPE NAME RECIPE  is the path of the struct name literal;
    //                   it will be re-expanded using derive-deftly.
    //
    // Expands to the actual struct literal.
    { @ 2 {$D:tt} [$($ty:tt)*]
      { $( $p:ident . $f:ident ; )* }
      $( .. $base:expr )?
    } => {
        derive_deftly::derive_deftly_adhoc! {
            DummyForMacrology beta_deftly:

            $($ty)* {
              $(
                $f: $D{paste_spanned $f { $p _ $f }},
              )*
              $(
                .. $base
              )?
            }
        }
    };

    // ----- error handling -----
    { @ $($error:tt)* } => {
        compile_error!(concat!("MACRO INTERNAL ERROR construct!: ", stringify!($($error)*)))
    };
}

/// Constructs a flavoured pair of consensus components, from local variables
///
/// Like `construct!` but
///
///  * The constructed value is a tuple.
///  * Two types names (plain and md) must be provided:
///    `construct_pair! PLAIN_STRUCT, MD_STRUCT { .. } { .. }`.
///  * `PREFIX` must always be `both`; the actual variable names are `plain_` and `md_`.
macro_rules! construct_both {
    { $plain_i0:ident $(:: $plain_is:ident)* ,
      $md_i0   :ident $(:: $md_is   :ident)*
      { $( both . $($f_m:ident),* $(,)? ; )* }
      { $( both . $($f_o:ident),* $(,)? ; )* }
      $(;)?
    } => {
        (
            construct!(
                @ 1 {$} [] [$plain_i0 $(:: $plain_is)*]
                { $( $( plain . $f_m ; )* )* }
                { $( $( plain . $f_o ; )* )* }
            ),
            construct!(
                @ 1 {$} [] [$md_i0 $(:: $md_is)*]
                { $( $( md    . $f_m ; )* )* }
                { $( $( md    . $f_o ; )* )* }
            ),
        )
    };
}
