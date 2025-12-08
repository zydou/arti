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
    /// Importing template must define these:
    ///
    ///  * **`F_INTRO`**, **`F_SUBDOC`**, **`F_SIGNATURE`**
    ///    conditions for the fundamental field kinds which aren't supported everywhere.
    ///
    ///    The `F_FLATTEN` and `F_NORMAL` field type conditions are defined here.
    ///
    /// Importer must also import `NetdocDeriveAnyCommon`.
    //
    // We have the call sites import the other modules, rather than using them here, because:
    //  - This avoids the human reader having to chase breadcrumbs
    //    to find out what a particular template is using.
    //  - The dependency graph is not a tree, so some things would be included twice
    //    and derive-deftly cannot deduplicate them.
    NetdocSomeItemsDeriveCommon beta_deftly:

    // Is this field `flatten`?
    ${defcond F_FLATTEN fmeta(netdoc(flatten))}
    // Is this field normal (non-structural)?
    ${defcond F_NORMAL not(any(F_SIGNATURE, F_INTRO, F_FLATTEN, F_SUBDOC))}

    // Field keyword as `&str`
    ${define F_KEYWORD_STR { ${concat
        ${if any(F_FLATTEN, F_SUBDOC) {
          ${if F_INTRO {
            ${error "#[deftly(netdoc(subdoc))] and (flatten) not supported for intro items"}
          } else {
            // Sub-documents and flattened fields have their keywords inside;
            // if we ask for the field-based keyword name for one of those then that's a bug.
            ${error "internal error, subdoc KeywordRef"}
          }}
        }}
        ${fmeta(netdoc(keyword)) as str,
          default ${concat ${kebab_case $fname}}}
    }}}
    // Field keyword as `&str` for debugging and error reporting
    ${define F_KEYWORD_REPORT ${concat
        ${if any(F_FLATTEN, F_SUBDOC) { $fname }
             else { $F_KEYWORD_STR }}
    }}
    // Field keyword as `KeywordRef`
    ${define F_KEYWORD { (KeywordRef::new_const($F_KEYWORD_STR)) }}
}

define_derive_deftly_module! {
    /// Common definitions for derives of whole network documents
    ///
    /// Used by `NetdocParseable` and `NetdocEncodable`.
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocEntireDeriveCommon beta_deftly:

    // Predicate for the toplevel
    ${defcond T_SIGNATURES tmeta(netdoc(signatures))}

    // Predicates for the field kinds
    ${defcond F_INTRO all(not(T_SIGNATURES), approx_equal($findex, 0))}
    ${defcond F_SUBDOC fmeta(netdoc(subdoc))}
    ${defcond F_SIGNATURE T_SIGNATURES} // signatures section documents have only signature fields

    // compile-time check that fields are in the right order in the struct
    ${define FIELD_ORDERING_CHECK {
        ${if not(T_SIGNATURES) { // signatures structs have only signature fields
          netdoc_ordering_check! {
            $(
                ${select1
                  F_INTRO     { intro     }
                  F_NORMAL    { normal    }
                  F_FLATTEN   { normal    }
                  F_SUBDOC    { subdoc    }
                }
                $fname
            )
          }
        }}
    }}
}

define_derive_deftly_module! {
    /// Common definitions for derives of flattenable network document fields structs
    ///
    /// Used by `NetdocParseableFields` and `NetdocEncodableFields`.
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocFieldsDeriveCommon beta_deftly:

    // Predicates for the field kinds, used by NetdocSomeItemsDeriveCommon etc.
    ${defcond F_INTRO false}
    ${defcond F_SUBDOC false}
    ${defcond F_SIGNATURE false}

    ${define DOC_NETDOC_FIELDS_DERIVE_SUPPORTED {
        ///  * The input struct can contain only normal non-structural items
        ///    (so it's not a sub-document with an intro item).
        ///  * The only attributes supported are the field attributes
        ///    `#[deftly(netdoc(keyword = STR))]`
        ///    `#[deftly(netdoc(default))]`
        ///    `#[deftly(netdoc(single_arg))]`
        ///    `#[deftly(netdoc(with = "MODULE"))]`
        ///    `#[deftly(netdoc(flatten))]`
    }}
}

define_derive_deftly_module! {
    /// Common definitions for derives of network document item value structs
    ///
    /// Used by `ItemValueParseable` and `ItemValueEncodable`.
    ///
    /// Importer must also import `NetdocDeriveAnyCommon`.
    NetdocItemDeriveCommon beta_deftly:

    ${defcond F_REST fmeta(netdoc(rest))}
    ${defcond F_OBJECT fmeta(netdoc(object))}
    ${defcond F_SIG_HASH fmeta(netdoc(sig_hash))}
    ${defcond F_NORMAL not(any(F_REST, F_OBJECT, F_SIG_HASH))}

    ${defcond T_IS_SIGNATURE not(approx_equal(${for fields { ${when F_SIG_HASH} 1 }}, {}))}
}
