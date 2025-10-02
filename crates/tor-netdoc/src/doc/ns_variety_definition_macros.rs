//! Machinery for defining multiple varieties of network status document.
//!
//! This module handles re-using the same source code to define
//!  * Votes, and parts thereof
//!  * Consensuses, and parts thereof
//!  * Microdescriptor consensuses, and parts thereof
//!
//! We call these three kinds of document "variety".
//! So a variety is either "vote", or a consensus flavour.
//!
//! # Overwview
//!
//! Network status documents, including consensuses (of various flavours) and votes,
//! have a lot of similarity.
//! But they also have a lot of fiddly ad-hoc differences.
//!
//! To deal with this similarity, and to avoid repeating too much code,
//! while still handling the variation, we do as follows:
//!
//!  * Types which are simply the same for all varieties,
//!    are defined in shared modules like
//!    `tor_netdoc::doc::netstatus` (whole network status documents) and
//!    `tor_netdoc::doc::netstatus::rs` (router status entries).
// We would like to linkify ^ these but that involves decorating many things pub(crate)
// only in #[cfg(doc)] which is quite annoying.  These are just examples, anyway.
//!
//!  * Types which are completely different between varieties
//!    are defined in ordinary variety-specific modules like
//!    `tor_netdoc::doc::netstatus::rs::md`
//!    (router status entries in microdescriptor consensus).
//!
//!  * Types which are *similar* across varieties, but not identical,
//!    are handled via a per-variety macro-and-multiple-inclusion scheme.
//!    That scheme is implemented in this module.
//!
//!  * Types which are *similar* across consensus *flavours*, but not defined for *votes*,
//!    are handled via a per-*flavour* macro-and-multiple-inclusion scheme.
//!
//! # Each-variety/flavour macro and multiple inclusion scheme
//!
//! This module contains macros that will be used to define
//! similar-but-not-identical  types
//! for each document variety ("vote", "md", and "plain").
//!
//! The definition of such type is in an `each_variety.rs` file,
//! which will be included once for each variety.
//!
//! Types which are only implemented for votes are defined in `each_flavor.rs`.
//! which will be included once for each *flavour* (so not for votes).
//!
//! Within `each_variety.rs` and `each_flavor.rs` macros are available
//! (provided by the machinery here in `ns_variety_definition_macros`)
//! which can be used to define individual fields, or code fragments,
//! which vary between varieties.
//!
//! Inclusion of the `each_variety.rs` and `each_flavor.rs` files,
//! as adapted for the particular variety,
//! is done by calling `ns_do_variety_VARIETY`
//! in the (handwritten) specifies-specific module.
//!
//! For example, the call to `ns_do_variety_md!()`
//! in `tor-netdoc/src/doc/netstatus/rs/md.rs`
//! imports all of the contents of
//! `tor-netdoc/src/doc/netstatus/rs/each_variety.rs`
//! into the module `doc::netstatus::rs::md`.
//! And, for example, within `rs/each_variety.rs`,
//! `ns_const_name!(FOO)` expands to `MD_FOO`.
//!
//! # Usage
//!
//! Create and include (with `mod`) normal module files:
//!  * `vote.rs`
//!  * `md.rs`
//!  * `plain
//!
//! These contain variety-specific definitions.
//!
//! Alongside these files, create:
//!  * `each_flavor.rs`
//!  * `each_variety.rs`
//!
//! Do not write a `mod` line for it.
//! Instead, in each of `vote.rs`, `plain.rs` and `md.rs`,
//! call [`ns_do_variety_vote`], [`ns_do_variety_plain`], or [`ns_do_variety_md`].
//!
//! The `each_variety.rs` file will be included three times, once each as a submodule
//! of the variety-specific file.
//! So there will be `...:vote::each_variety::`, etc.,
//! all of which will automatically be re-imported into the parent `vote`.
//! Likewise `each_flavor.rs` file will be included two times.
//!
//! Within `each_variety.rs` (`each_flavor.rs`),
//! all items you define will be triplicated (duplicated).
//! Give them unqualified names.
//! Re-export them in the overall parent module,
//! using `ns_export_each_variety`.
//!
//! # Module scope for `..::VARIETY` and `..::VARIETY::each_variety`/`::each_flavor`
//!
//! Whether to put a particular item in `each_variety.rs`/`each_flavor.rs`, or `VARIETY.rs`,
//! depends just on how similar the source code is for the different varieties.
//!
//! Accordingly there is no real principled distinction between
//! the namespace of each of the (per-variety) `each_variety`/`each_flavor` modules,
//! and their (also per-variety) parents.
//!
//! So `each_variety.rs` and `each_flavor.rs` should `use super::*`.
//! Whenever convenient, fields or private items can be `pub(super)`.
//! `VARIETY.rs` can contain impl blocks for types in `each_variety.rs` and vice versa.
//!
//! `VARIETY.rs` can and should use variety-agnostic names for internal types.
//!
//! Whether an item appears in `each_variety.rs` or `each_flavor.rs`
//! depends (only) on whether it is to be defined for votes, or just for flavours.
//!
//! # Macros for across-variety-variation
//!
//! Within `each_variety.rs`,
//! the following macros are defined for use in `each_variety.rs`/`each_flavor.rs`
//! for variety-dependent elements:
//!
//! * **`ns_ty_name!( BaseTypeName )`**:
//!
//!   Expands to `PlainBaseTypeName`, `MdBaseTypeName`, or `VoteBaseTypeName`.
//!
//!   Cannot be used to *define* a type.
//!   (Define the type with an unqualified name, and
//!   re-export it with the qualified name, using `ns_export_each_variety`.)
//!
//! * **`ns_const_name!( BASE_CONST_NAME )`**:
//!
//!   Expands to `PLAIN_BASE_CONST_NAME`, `MD_BASE_CONST_NAME`, or `VOTE_BASE_CONST_NAME`.
//!
//! * **`ns_type!( TypeForPlainConsensus, TypeForMdConsensus, [TypeForVote] )`**:
//!
//!   Expands to the appropriate one of the two or three specified types.
//!   `TypeForVote` may be omitted in `each_flavor.rs`; it is an error in `each_variety.rs`.
//!
//! * **`ns_expr!( value_for_plain_consensus, value_for_md_consensus, [value_for_vote] )`**:
//!
//!   Expands to the appropriate one of the two or three specified expressions.
//!
//! * **`ns_choose!( ( FOR PLAIN CONSENSUS.. )( FOR MD CONSENSUS.. )[( FOR VOTE.. )] )`**:
//!
//!   Expands to the appropriate one of the two or three specified token streams.
//!   (The `( )` surrounding each argument are discarded.)
//!
//!   When defining whole items, prefer to put the variety-specific items directly
//!   in each of the variety-specific modules.
//!
//! * **`ns_use_this_variety! { use [LHS]::?::{RHS}; }`**:
//!
//!   For importing names from variety-specific sibling modules.
//!
//!   In the `use` statement, literal `[ ]` are needed around LHS, and are removed.
//!   `?` is replaced with the variety abbreviation (`plain`, `md` or `vote).
//!
//!   Multiple `use` within the same `ns_use_this_variety!` are allowed.
//!   Visibility (`pub use` etc.) is supported.
//!
//!   Attributes are not currently supported.
//!   Unfortunately, only the form with RHS inside `{ }` is permitted.
//!
//! * **`ns_if_vote!{ ( FOR VOTES.. )( FOR CONSENSUSES.. ) }`**:
//!
//!   Expands to `FOR VOTES` or `FOR CONSENSUSES` as applicable,
//!   similarly to `ns_choose!`, writing the `FOR CONSENSUSES` part only once.
//!   (The `( )` surrounding each argument are discarded.)
//
// Other ways we could have done this:
//
//  * Generics: `NetworkStatus<Variety>`.
//
//    The generics get everywhere, and they seriously mess up the
//    ad-hoc specialisation used for type-based multiplicity dispatch
//    (see tor-netdoc/src/parse2/multiplicity.rs).
//    We used this scheme for consensuses vs microdescriptor consensuses,
//    but it's not workable for votes, so we are switching.
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

/// Includes items from `each_variety.rs` for a particular variety.
///
/// **Internal to `ns_variety_definition_macros.rs`, do not use directly!**
///
///  * `$abbrev` is one of `vote`, `plain`, or `md` as applicable.
///
///  * `: $plain $md $vote $d` is always `: plain md vote $`.
///    `$d` is needed because it's not possible to write a literal `$`
///    in the expansion part of a proc macro, except at the end of a group (!)
///    (`$$` can do that but is is not stable.)
///    `$vote` etc. are needed to match the identifier hygiene of `$abbrev`.
macro_rules! ns_do_one_variety { {
    $abbrev:ident : $plain:ident $md:ident $vote:ident $d:tt
} => {
    // ----- Define the selector macros (see the module top-level comment -----

    #[allow(unused)]
    macro_rules! ns_choose {
        {
            ( $d( $d $plain:tt )* )
            ( $d( $d $md  :tt )* )
            ( $d( $d $vote:tt )* )
        } => {
            $d( $d $abbrev )*
        };
        {
            ( $d( $d $plain:tt )* )
            ( $d( $d $md  :tt )* )
        } => { ns_choose! {
            ( $d( $d vote    )* )
            ( $d( $d plain   )* )
            ( compile_error!("missing definition of what to do for the vote variety") )
        } }
    }
    #[allow(unused)] // Each of these macros is redefined per-call site, so may be unused
    macro_rules! ns_ty_name {
        { $d base:ident } => { paste::paste!( [< $prefix:camel_case   $d base >] ) }
    }
    #[allow(unused)]
    macro_rules! ns_const_name {
        { $d base:ident } => { paste::paste!( [< $prefix:upper_case _ $d base >] ) }
    }
    #[allow(unused)]
    macro_rules! ns_type {
        { $d( $d option:ty ),* $d(,)? } => { ns_choose!( $d( ( $d option ) )* ) }
    }
    #[allow(unused)]
    macro_rules! ns_expr {
        { $d( $d option:expr ),* $d(,)? } => { ns_choose!( $d( ( $d option ) )* ) }
    }
    #[allow(unused)]
    macro_rules! ns_use_this_variety {
        { $d( $d v:vis use [ $d( $d lhs:tt )* ] :: ?       :: { $d( $d rhs:tt )* }; )* } =>
        { $d( $d v     use   $d( $d lhs    )*   :: $abbrev :: { $d( $d rhs    )* }; )* }
    }

    // ----- Now read each_variety.rs in the context with *these* macro definitions -----

    #[allow(clippy::duplicate_mod)]
    #[path = "each_variety.rs"]
    mod each_variety;

    // ----- And finally re-export everything into the caller's scope -----

    #[allow(unused, unreachable_pub)] // There might not be any pub items.
    pub use each_variety::*;

  ns_if_vote! {() (

    #[allow(clippy::duplicate_mod)]
    #[path = "each_flavor.rs"]
    mod each_flavor;

    // ----- And finally re-export everything into the caller's scope -----

    #[allow(unused, unreachable_pub)] // There might not be any pub items.
    pub use each_flavor::*;

  )}
} }

/// Select token streams for votes vs conensuses
///
/// See the module-level documentation.
macro_rules! ns_if_vote { {
        ( $( $vote :tt )* )
        ( $( $other:tt )* )
    } => { ns_choose! {
        ( $( $other    )* )
        ( $( $other    )* )
        ( $( $vote     )* )
    } }
}

/// Include variety-agnostic items, for a full consensus, from `each_variety.rs`.
///
/// Use within `plain.rs`.
macro_rules! ns_do_variety_plain { {} => { ns_do_one_variety! { plain : plain md vote $ } } }
#[cfg(doc)]
use ns_do_variety_plain;

/// Include variety-agnostic items, for an md consensus, from `each_variety.rs`.
///
/// Use within `md.rs`.
macro_rules! ns_do_variety_md   { {} => { ns_do_one_variety! { md   : plain md vote $ } } }
#[cfg(doc)]
use ns_do_variety_md;

/// Include variety-agnostic items, for a vote, from `each_variety.rs`.
///
/// Use within `vote.rs`.
#[allow(unused)] // TODO feature = "ns-vote"
macro_rules! ns_do_variety_vote { {} => { ns_do_one_variety! { vote : plain md vote $ } } }
#[cfg(doc)]
use ns_do_variety_vote;

/// Export variety-specific names from each module.
///
/// Usage:
///
/// ```rust,ignore
/// ns_export_each_variety! {
///     ty: Typename1, Typename2;
///     const: CONSTNAME_1, CONSTNAME_2;
/// }
/// ```
///
/// Exports each `Tyename` as `VarietyTypename`,
/// and each `CONSTNAME` as `VARIETY_CONSTNAME`.
///
/// All three modules `vote`, `plain`, and `md` must exist,
/// and must contain the same items.
//
// TODO consider instead making the variety-specific module names public.
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/3139#note_3239852
#[allow(unused)]
macro_rules! ns_export_each_variety {
    {
        $kind:ident: $( $ty:ident ),* $(,)?
        $(; $($rest:tt)* )?
    } => {
        ns_export_each_variety! { @ $kind $($ty)* }
        $( ns_export_each_variety! { $($rest)* } )?
    };
    { } => {};
    { @ ty    $($id:ident)* } => { $( ns_export_each_variety! { @ [:camel] [ ] $id } )* };
    { @ const $($id:ident)* } => { $( ns_export_each_variety! { @ [:upper] [_] $id } )* };
    {
        @ [ $($case:tt)* ] [$($infix:tt)*] $id:ident
    } => { paste::paste!{
        #[cfg(feature = "plain-consensus")]
        #[cfg_attr(docsrs, doc(cfg(feature = "plain-consensus")))]
        pub use { plain ::$id as [<plain   $($case)* $($infix)* $id>] };
        // unconditional
        pub use { md  ::$id as [<md   $($case)* $($infix)* $id>] };
        #[cfg(feature = "ns-vote")] // TODO ns-vote this feature doesn't exist yet
        #[cfg_attr(docsrs, doc(cfg(feature = "ns-vote")))]
        pub use { vote::$id as [<vote $($case)* $($infix)* $id>] };
    } };
}

/// Export flavor-specific names from each (consensus) module.
///
/// Like [`ns_export_each_variety!`] but only exports for consensuses, not votes.
///
/// The two modules `plain`, and `md` must exist,
/// and must contain the same items.
//
// TODO maybe deduplicate with ns_export_each_variety
macro_rules! ns_export_each_flavor {
    {
        $kind:ident: $( $ty:ident ),* $(,)?
        $(; $($rest:tt)* )?
    } => {
        ns_export_each_flavor! { @ $kind $($ty)* }
        $( ns_export_each_flavor! { $($rest)* } )?
    };
    { } => {};
    { @ ty    $($id:ident)* } => { $( ns_export_each_flavor! { @ [:camel] [ ] $id } )* };
    { @ const $($id:ident)* } => { $( ns_export_each_flavor! { @ [:upper] [_] $id } )* };
    {
        @ [ $($case:tt)* ] [$($infix:tt)*] $id:ident
    } => { paste::paste!{
        #[cfg(feature = "plain-consensus")]
        #[cfg_attr(docsrs, doc(cfg(feature = "plain-consensus")))]
        pub use { plain ::$id as [<plain   $($case)* $($infix)* $id>] };
        // unconditional
        pub use { md  ::$id as [<md   $($case)* $($infix)* $id>] };
    } };
}
