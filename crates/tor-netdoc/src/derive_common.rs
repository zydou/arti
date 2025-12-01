//! Common macro elements for deriving parsers and encoders

use derive_deftly::define_derive_deftly_module;

/// Macro to help check that netdoc items in a derive input are in the right order
///
/// Used only by the `NetdocParseable` derive-deftly macro.
#[doc(hidden)]
#[macro_export]
macro_rules! netdoc_ordering_check {
    { } => { compile_error!("netdoc must have an intro item so cannot be empty"); };

    // When we have   K0 P0 K1 P1 ...
    //   * Check that P0 and P1 have a consistent ordr
    //   * Continue with   K1 P1 ...
    // So we check each consecutive pair of fields.
    { $k0:ident $f0:ident $k1:ident $f1:ident $($rest:tt)* } => {
        $crate::netdoc_ordering_check! { <=? $k0 $k1 $f1 }
        $crate::netdoc_ordering_check! { $k1 $f1 $($rest)* }
    };
    { $k0:ident $f0:ident } => {}; // finished

    // Individual ordering checks for K0 <=? K1
    //
    // We write out each of the allowed this-kind next-kind combinations:
    { <=? intro     $any:ident $f1:ident } => {};
    { <=? normal    normal     $f1:ident } => {};
    { <=? normal    subdoc     $f1:ident } => {};
    { <=? subdoc    subdoc     $f1:ident } => {};
    // Not in the allowed list, must be an error:
    { <=? $k0:ident $k1:ident  $f1:ident } => {
        compile_error!(concat!(
            "in netdoc, ", stringify!($k1)," field ", stringify!($f1),
            " may not come after ", stringify!($k0),
        ));
    };
}

define_derive_deftly_module! {
    /// Common definitions for any netdoc derives
    NetdocDeriveAnyCommon beta_deftly:

}

define_derive_deftly_module! {
    /// Common definitions for derives of structs containing items
    ///
    /// Used by `NetdocParseable`, `NetdocParseableFields`,
    /// `NetdocEncodable` and `NetdocEncodableFields`.
    ///
    /// Importer must also import `NetdocDeriveAnyCommon`.
    //
    // We have the call sites import the other modules, rather than using them here, because:
    //  - This avoids the human reader having to chase breadcrumbs
    //    to find out what a particular template is using.
    //  - The dependency graph is not a tree, so some things would be included twice
    //    and derive-deftly cannot deduplicate them.
    NetdocSomeItemsDeriveCommon beta_deftly:

}

define_derive_deftly_module! {
    /// Common definitions for derives of whole network documents
    ///
    /// Used by `NetdocParseable` and `NetdocEncodable`.
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocEntireDeriveCommon beta_deftly:

}

define_derive_deftly_module! {
    /// Common definitions for derives of flattenable network document fields structs
    ///
    /// Used by `NetdocParseableFields` and `NetdocEncodableFields`.
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocFieldsDeriveCommon beta_deftly:

}

define_derive_deftly_module! {
    /// Common definitions for derives of network document item value structs
    ///
    /// Used by `ItemValueParseable` and `ItemValueEncodable`.
    ///
    /// Importer must also import `NetdocDeriveAnyCommon`.
    NetdocItemDeriveCommon beta_deftly:

}
