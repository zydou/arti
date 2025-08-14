//! Machinery for defining multiple species of network status document.
//!
//! This module handles re-using the same source code to define
//!  * Votes, and parts thereof
//!  * Consensuses, and parts thereof
//!  * Microdescriptor consensuses, and parts thereof
//!
//! We call these three kinds of document "species".
//! So a species is either "vote", or a consensus flavour.
//!
//! # Usage
//!
//! Create and include (with `mod`) normal module files:
//!  * `vote.rs`
//!  * `md.rs`
//!  * `ns.rs`
//!
//! These contain species-specific definitions.
//!
//! Alongside these files, create:
//!  * `per_species.rs`
//!
//! Do not write a `mod` line for it.
//! Instead, in each of `vote.rs`, `ns.rs` and `md.rs`,
//! call [`ns_do_species_vote`], [`ns_do_species_ns`], or [`ns_do_species_md`].
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
//!   Expands to `VoteBaseTypeName`, `NsBaseTypeName`, or `MdBaseTypeName`.
//!
//!   Cannot be used to *define* a type.
//!   (Define the type with an unqualified name, and
//!   re-export it with the qualified name, using `ns_export_per_species`.)
//!
//! * **`ns_const_name!( BASE_CONST_NAME )`**:
//!
//!   Expands to `VOTE_BASE_TYPE_NAME`, `NS_BASE_TYPE_NAME`, or `MD_BASE_TYPE_NAME`.
//!
//! * **`ns_type!( TypeForVote, TypeForNsConsensus, [TypeForMdConsensus] )`**:
//!
//!   Expands to the appropriate one of the two or three specified types.
//!   If `TypeForMdConsensus` is not specified, `TypeForNsConsensus` is used.
//!
//! * **`ns_expr!( value_for_vote, value_for_ns_consensus, [value_for_md_consensus] )`**:
//!
//!   Expands to the appropriate one of the two or three specified expressions.
//!   If `value_for_consensus_md` is not specified, `TypeForConsensus` is used.
//!
//! * **`ns_choose!( ( FOR VOTE.. )( FOR NS CONSENSUS.. )( FOR MD CONSENSUS.. ) )`**:
//!
//!   Expands to the appropriate one of the two or three specified token streams.
//!   (The `( )` surrounding each argument are discarded.)
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

/// Does the work for one species.
///
/// **Internal to `ns_per_species_macros.rs`, do not use directly!**
///
///  * `$abbrev` is one of `vote`, `ns`, or `md` as applicable.
///
///  * `: $vote $ns $md $d` is always `: vote ns md $`.
///    `$d` is needed because it's not possible to write a literal `$`
///    in the expansion part of a proc macro, except at the end of a group (!)
///    (`$$` can do that but is is not stable.)
///    `$vote` etc. are needed to match the identifier hygiene of `$abbrev`.
macro_rules! ns_do_one_species { {
    $abbrev:ident : $vote:ident $ns:ident $md:ident $d:tt
} => {
    #[allow(unused)]
    macro_rules! ns_choose {
        {
            ( $d( $d $vote:tt )* )
            ( $d( $d $ns  :tt )* )
            ( $d( $d $md  :tt )* )
        } => {
            $d( $d $abbrev )*
        };
        {
            ( $d( $d vote:tt )* )
            ( $d( $d ns  :tt )* )
        } => { ns_choose! {
            ( $d( $d vote    )* )
            ( $d( $d ns      )* )
            ( $d( $d ns      )* )
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
    #[allow(clippy::duplicate_mod)]
    #[path = "per_species.rs"]
    mod per_species;
    #[allow(unused, unreachable_pub)] // There might not be any pub items.
    pub use per_species::*;
} }

/// Include species-agnostic items, for a vote, from `per_species.rs`.
///
/// Use within `vote.rs`.
#[allow(unused)] // TODO feature = "ns-vote"
macro_rules! ns_do_species_vote { {} => { ns_do_one_species! { vote : vote ns md $ } } }
use ns_do_species_vote;

/// Include species-agnostic items, for a full consensus, from `per_species.rs`.
///
/// Use within `ns.rs`.
macro_rules! ns_do_species_ns   { {} => { ns_do_one_species! { ns   : vote ns md $ } } }
use ns_do_species_ns;

/// Include species-agnostic items, for an md consensus, from `per_species.rs`.
///
/// Use within `md.rs`.
macro_rules! ns_do_species_md   { {} => { ns_do_one_species! { md   : vote ns md $ } } }
use ns_do_species_md;

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
/// All three modules `vote`, `ns`, and `md` must exist,
/// and must contain the same items.
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
        #[cfg(feature = "ns-vote")] // TODO ns-vote this feature doesn't exist yet
        #[cfg_attr(docsrs, doc(cfg(feature = "ns-vote")))]
        pub use { vote::$id as [<vote $($case)* $($infix)* $id>] };
        #[cfg(feature = "ns-consensus")]
        #[cfg_attr(docsrs, doc(cfg(feature = "ns-consensus")))]
        pub use { ns  ::$id as [<ns   $($case)* $($infix)* $id>] };
        // unconditional
        pub use { md  ::$id as [<md   $($case)* $($infix)* $id>] };
    } };
}
