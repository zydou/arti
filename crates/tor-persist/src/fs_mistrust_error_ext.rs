//! [`FsMistrustErrorExt`]

use paste::paste;

use tor_error::ErrorKind;

use ErrorKind as EK;

/// Helper; `access_failed` should be `FooAccessFaile` for the appropriate `Foo`
fn mistrust_error_kind(e: &fs_mistrust::Error, access_failed: ErrorKind) -> ErrorKind {
    if e.is_bad_permission() {
        EK::FsPermissions
    } else {
        access_failed
    }
}

/// Generate the extension trait and its impl
///
/// Input is the set of "kinds of thing", each of which corresponds to an `ErrorKind`.
///
/// # Input syntax
///
/// ```text
///     thing, "DESCRIPTION";           // Provide thing_error_kind(), using ThingAccessFailed
///     [Prefix] THING, "DESCRIPTION";  // uses PrefixThingAccessFAiled
/// ```
macro_rules! accesses { {
    $( $([ $prefix:ident ])? $kind:ident, $description:tt; )*
} => { paste!{

    /// Extension trait for getting a [`tor_error::ErrorKind`] from a [`fs_mistrust::Error`]
    pub trait FsMistrustErrorExt: Sealed {
        $(

            #[doc = concat!("The error kind if we were trying to access", $description)]
            fn [<$kind _error_kind>](&self) -> ErrorKind;
        )*
    }

    impl FsMistrustErrorExt for fs_mistrust::Error {
        $(
            fn [<$kind _error_kind>](&self) -> tor_error::ErrorKind {
                mistrust_error_kind(self, EK::[<$($prefix)? $kind:camel AccessFailed>])
            }
        )*
    }

} } }

/// Sealed
pub trait Sealed {}
impl Sealed for fs_mistrust::Error {}

accesses! {
    cache, "a cache directory";
    [Persistent] state, "a persistent state directory";
    keystore, "a keystore"; // TODO #1215 probably tor-keymgr should be using this
}
