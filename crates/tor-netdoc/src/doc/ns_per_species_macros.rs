//! Machinery for defining multiple species of network status document.
//!
//! This module handles re-using the same source code to define
//!  * Votes, and parts thereof
//!  * Consensuses, and parts thereof
//!  * Microdescriptor consensuses, and parts thereof
//!
//! We call these three kinds of document "species".
// Change "species" to "variety" everywhere.
//! So a species is either "vote", or a consensus flavour.
//!
//! # Usage
//!
//! Create and include (with `mod`) normal module files:
//!  * `vote.rs`
//!  * `md.rs`
//!  * `plain
//!
//! These contain species-specific definitions.
//!
//! Alongside these files, create:
//!  * `per_species.rs`
//!
//! Do not write a `mod` line for it.
//! Instead, in each of `vote.rs`, `plain.rs` and `md.rs`,
//! call [`ns_do_species_vote`], [`ns_do_species_plain`], or [`ns_do_species_md`].
//!
//! This module will be included three times, once each as a submodule
//! of the species-specific file.
//! So there will be `...:vote::per_species::`, etc.,
//! all of which will automatically be re-imported into the parent `vote`.
//!
//! Within `per_species.rs`, all items you define will be triplicated.
//! Give them unqualified names.
//! Re-export them in the overall parent module,
//! using `ns_export_per_species`.
//!
//! # Macros for across-species-variation
//!
//! Within `per_species.rs`,
//! the following macros are defined for use in `per_species.rs`
//! for species-dependent elements:
//!
//! * **`ns_ty_name!( BaseTtypeName )`**:
//!
//!   Expands to `NsBaseTypeName`, `MdBaseTypeName`, or `VoteBaseTypeName`.
// XXXX should be PlainBaseTypeName not Ns_
//!
//!   Cannot be used to *define* a type.
//!   (Define the type with an unqualified name, and
//!   re-export it with the qualified name, using `ns_export_per_species`.)
//!
//! * **`ns_const_name!( BASE_CONST_NAME )`**:
//!
//!   Expands to `NS_BASE_CONST_NAME`, `VOTE_BASE_CONST_NAME`, or `MD_BASE_CONST_NAME`.
// XXXX should be PLAIN_BASE_CONST_NAME not NS_
//!
//! * **`ns_type!( TypeForPlainConsensus, TypeForMdConsensus, [TypeForVote] )`**:
//!
//!   Expands to the appropriate one of the two or three specified types.
//!   If `TypeForVote` is not specified, it is a compile error
//!   for this `per_species` file to be used for votes.
//!
//! * **`ns_expr!( value_for_plain_consensus, value_for_md_consensus, [value_for_vote] )`**:
//!
//!   Expands to the appropriate one of the two or three specified expressions.
//!   If `value_for_vote` is not specified, it is a compile error
//!   for this `per_species` file to be used for votes.
//!
//! * **`ns_choose!( ( FOR PLAIN CONSENSUS.. )( FOR MD CONSENSUS.. )[( FOR VOTE.. )] )`**:
//!
//!   Expands to the appropriate one of the two or three specified token streams.
//!   (The `( )` surrounding each argument are discarded.)
//!
//!   If `FOR VOTE` is not specified, it is a compile error
//!   for this `per_species` file to be used for votes.
//!
//!   When defining whole items, prefer to put the species-specific items directly
//!   in each of the species-specific modules.
//
// Other ways we could have done this:
//
//  * Generics: `NetworkStatus<Species>`.
//
//    The generics get everywhere, and they seriously mess up the
//    ad-hoc specialisation used for type-based multiplicity dispatch.
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

/// Includes items from `per_species.rs` for a particular species.
///
/// **Internal to `ns_per_species_macros.rs`, do not use directly!**
///
///  * `$abbrev` is one of `vote`, `plain`, or `md` as applicable.
///
///  * `: $plain $md $vote $d` is always `: plain md vote $`.
///    `$d` is needed because it's not possible to write a literal `$`
///    in the expansion part of a proc macro, except at the end of a group (!)
///    (`$$` can do that but is is not stable.)
///    `$vote` etc. are needed to match the identifier hygiene of `$abbrev`.
macro_rules! ns_do_one_species { {
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
            ( $d( $d plain:tt )* )
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

    // ----- Now read per_species.rs in the context with *these* macro definitions -----

    #[allow(clippy::duplicate_mod)]
    #[path = "per_species.rs"]
    mod per_species;

    // ----- And finally re-export everything into the caller's scope -----

    #[allow(unused, unreachable_pub)] // There might not be any pub items.
    pub use per_species::*;
} }

/// Include species-agnostic items, for a full consensus, from `per_species.rs`.
///
/// Use within `plain.rs`.
macro_rules! ns_do_species_plain { {} => { ns_do_one_species! { plain : plain md vote $ } } }
use ns_do_species_plain;

/// Include species-agnostic items, for an md consensus, from `per_species.rs`.
///
/// Use within `md.rs`.
macro_rules! ns_do_species_md   { {} => { ns_do_one_species! { md   : plain md vote $ } } }
use ns_do_species_md;

/// Include species-agnostic items, for a vote, from `per_species.rs`.
///
/// Use within `vote.rs`.
#[allow(unused)] // TODO feature = "ns-vote"
macro_rules! ns_do_species_vote { {} => { ns_do_one_species! { vote : plain md vote $ } } }
use ns_do_species_vote;

/// Export species-specific names from each module.
///
/// Usage:
///
/// ```rust,ignore
/// ns_export_per_species! {
///     ty: Typename1, Typename2;
///     const: CONSTNAME_1, CONSTNAME_2;
/// }
/// ```
///
/// Exports each `Tyename` as `SpeciesTypename`,
/// and each `CONSTNAME` as `SPECIES_CONSTNAME`.
///
/// All three modules `vote`, `plain`, and `md` must exist,
/// and must contain the same items.
//
// Should prefix items with Plain/PLAIN_, rather than Ns/NS_
macro_rules! ns_export_per_species {
    {
        $kind:ident: $( $ty:ident ),* $(,)?
        $(; $($rest:tt)* )?
    } => {
        ns_export_per_species! { @ $kind $($ty)* }
        $( ns_export_per_species! { $($rest)* } )?
    };
    { } => {};
    { @ ty    $($id:ident)* } => { $( ns_export_per_species! { @ [:camel] [ ] $id } )* };
    { @ const $($id:ident)* } => { $( ns_export_per_species! { @ [:upper] [_] $id } )* };
    {
        @ [ $($case:tt)* ] [$($infix:tt)*] $id:ident
    } => { paste::paste!{
        #[cfg(feature = "ns-consensus")]
        #[cfg_attr(docsrs, doc(cfg(feature = "ns-consensus")))]
        pub use { plain ::$id as [<ns   $($case)* $($infix)* $id>] };
        // unconditional
        pub use { md  ::$id as [<md   $($case)* $($infix)* $id>] };
        #[cfg(feature = "ns-vote")] // TODO ns-vote this feature doesn't exist yet
        #[cfg_attr(docsrs, doc(cfg(feature = "ns-vote")))]
        pub use { vote::$id as [<vote $($case)* $($infix)* $id>] };
    } };
}
