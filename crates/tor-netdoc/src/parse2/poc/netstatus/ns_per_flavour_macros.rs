//! Machinery for defining multiple flavours of network status document
//!
//! This module has one sub-module for each flavour.
//! That sub-module is named after the flavour, and its source file is `flavoured.rs`.
//! (We treat votes as a "flavour".)
//!
//! The following macros are defined for use by `flavoured.rs`
//! for flavour-dependent elements:
//!
//! * **`ns_type!( TypeForVote, TypeForConsensus, [TypeForConsensusMd] )`**:
//!
//!   Expands to the appropriate one of the two or three specified types.
//!   If `TypeForConsensusMd` is not specified, `TypeForConsensus` is used.
//!
//! * **`ns_expr!( value_for_vote, value_for_consensus, [value_for_consensus_md] )`**:
//!
//!   Expands to the appropriate one of the two or three specified expressions.
//!   If `value_for_consensus_md` is not specified, `TypeForConsensus` is used.
//!
//! * **`ns_choose!( ( FOR VOTE.. )( FOR CONSENSUS.. )( FOR CONSENSUS MD.. ) )`**:
//!
//!   Expands to the appropriate one of the two or three specified token streams.
//!   (The `( )` surrounding each argument are discarded.)
//
// Other ways we could have done this:
//
//  * Generics: `NsdNetworkStatus<Flavour>`.
//
//    The generics get everywhere, and they seriously mess up the
//    ad-hoc specialisation used for type-based multiplicity dispatch.
//
//  * tt-munching macro_rules macro that filters its input body,
//    replacing pseudo-macro invocations with their expansions.
//
//    This does work, but it involves radically increasing
//    the compiler recursion limit to many thousands.
//
//  * custom proc macro(s).
//
//    These would probably have to be bespoke to the application.
//
//  * build.rs, ad-hoc templating.  But this wouldn't be Rust syntax.

/// Does the work for one flavour.
///
///  * `$abbrev` is one of `vote`, `cons`, or `md` as applicable.
///
///  * `$suffix` is the `Flavoursuffix`, `Vote`, absent, or `Md`.
///
///  * `$vote $cons $md $d` is always `vote cons md $`.
///    `$d` is needed because it's not possible to write a literal `$`
///    in the expansion part of a proc macro.  `$$` is not stable.
///    `$vote` etc. are needed because to match the identifier hygiene of `$abbrev`.
macro_rules! ns_do_one_flavour { {
    $vote:ident $cons:ident $md:ident $d:tt :
    $abbrev:ident
    $($suffix:ident)?
} => {
    macro_rules! ns_choose {
        {
            ( $d( $d $vote:tt )* )
            ( $d( $d $cons:tt )* )
            ( $d( $d $md  :tt )* )
        } => {
            $d( $d $abbrev )*
        };
        {
            ( $d( $d vote:tt )* )
            ( $d( $d cons:tt )* )
        } => { ns_choose! {
            ( $d( $d vote    )* )
            ( $d( $d cons    )* )
            ( $d( $d cons    )* )
        } }
    }
    macro_rules! ns_type {
        { $d( $d option:ty ),* $d(,)? } => { ns_choose!( $d( ( $d option ) )* ) }
    }
    macro_rules! ns_expr {
        { $d( $d option:expr ),* $d(,)? } => { ns_choose!( $d( ( $d option ) )* ) }
    }
    #[allow(clippy::duplicate_mod)]
    #[path = "flavoured.rs"]
    pub mod $abbrev;
} }
ns_do_one_flavour! {
    vote cons md $ : vote Vote
}
ns_do_one_flavour! {
    vote cons md $ : cons Ns
}
ns_do_one_flavour! {
    vote cons md $ : md Md
}

/// Export each `flavour::Ty` as `TyFlavour`
macro_rules! ns_export_flavoured_types { { $( $ty:ident ),* $(,)? } => { paste!{
    pub use { $( vote::$ty as [<$ty Vote>], )* };
    pub use { $( cons::$ty as [<$ty Ns>],   )* };
    pub use { $( md::$ty   as [<$ty Md>],   )* };
} } }
pub(crate) use ns_export_flavoured_types;
