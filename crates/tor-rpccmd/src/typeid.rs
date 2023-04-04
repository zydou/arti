//! A kludgy replacement for [`std::any::TypeId`] that can be used in a constant context.

/// A less helpful variant of `std::any::TypeId` that can be used in a const
/// context.
///
/// Until the [relevant Rust feature] is stabilized, it's not possible to get a
/// TypeId for a type and store it in a const.  But sadly, we need to do so for
/// our dispatch code.
///
/// Thus, we use a nasty hack: we use the address of the function
/// `TypeId::of::<T>` as the identifier for the type of T.
///
/// This type and the module containing it are hidden: Nobody should actually
/// use it outside of our dispatch code.  Once we can use `TypeId` instead, we
/// should and will.
///
/// To make a type participate in this system, use the [`impl_const_type_id`]
/// macro.
///
/// **Do not mention this type outside of this module.**
///
/// [relevant Rust feature]: https://github.com/rust-lang/rust/issues/77125
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct ConstTypeId_(
    /// Sadly this has to be `pub` so we can construct these from other crates.
    ///
    /// We could make a constructor, but there is no point.
    pub *const (),
);

// Safety: We never actually access the pointer.
unsafe impl Send for ConstTypeId_ {}
// Safety: We never actually access the pointer.
unsafe impl Sync for ConstTypeId_ {}

/// An object for which we can access a [`ConstTypeId_`] dynamically.
///
/// **Do not mention this type outside of this module.**
pub trait GetConstTypeId_ {
    fn const_type_id(&self) -> ConstTypeId_;
}

/// An object for which we can get a [`ConstTypeId_`] at compile time.
///
/// This is precisely the functionality that [`std::any::TypeId`] doesn't
/// currently have.
///
/// **Do not mention this type outside of this module.**
pub trait HasConstTypeId_ {
    const CONST_TYPE_ID_: ConstTypeId_;
}

/// Implement [`GetConstTypeId_`] and [`HasConstTypeId_`] for one or more types.
///
/// To avoid truly unpleasant consequences, this macro only works on simple
/// identifiers, so you can't run it on arbitrary types, or on types in other
/// modules.
#[macro_export]
macro_rules! impl_const_type_id {
    { $($type:ident)* } => {
        $(
            impl $crate::typeid::HasConstTypeId_ for $type {
                const CONST_TYPE_ID_: $crate::typeid::ConstTypeId_ = $crate::typeid::ConstTypeId_(
                    std::any::TypeId::of::<$type> as *const ()
                );
            }

            impl $crate::typeid::GetConstTypeId_ for $type {
                fn const_type_id(&self) -> $crate::typeid::ConstTypeId_ {
                    <$type as $crate::typeid::HasConstTypeId_>::CONST_TYPE_ID_
                }
            }
        )*
    }
}
pub use impl_const_type_id;

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use assert_impl::assert_impl;

    struct Foo(usize);
    struct Bar {}

    crate::impl_const_type_id! {Foo Bar}

    #[test]
    fn typeid_basics() {
        use super::*;
        assert_impl!(Send: ConstTypeId_);
        assert_impl!(Sync: ConstTypeId_);
        let foo1 = Foo(3);
        let foo2 = Foo(4);
        let bar = Bar {};

        assert_eq!(foo1.const_type_id(), foo2.const_type_id());
        assert_ne!(foo1.const_type_id(), bar.const_type_id());
    }
}
