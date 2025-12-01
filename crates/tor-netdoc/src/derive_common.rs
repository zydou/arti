//! Common macro elements for deriving parsers and encoders

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
