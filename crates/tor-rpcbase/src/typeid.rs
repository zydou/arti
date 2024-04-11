//! A kludgy replacement for [`std::any::TypeId`] that can be used in a constant context.

/// A less helpful variant of `std::any::TypeId` that can be created in a const
/// context.
///
/// Until the [relevant Rust feature] is stabilized, it's not possible to get a
/// TypeId for a type and store it in a const.  But sadly, we need to do so for
/// our dispatch code.
///
/// Thus, we use a nasty hack: we save the address of the function
/// `TypeId::of::<T>` and use it _later_ to get type of T.
///
/// This type and the module containing it are hidden: Nobody should actually
/// use it outside of our dispatch code.  Once we can use `TypeId` instead, we
/// should and will.
///
/// The [`ConstTypeId_`] function deliberately does not implement `Eq` and
/// friends. To compare two of these, use `TypeId::from()` to convert it into
/// a real `TypeId`.
///
/// **Do not mention this type outside of this module.**
///
/// [relevant Rust feature]: https://github.com/rust-lang/rust/issues/77125
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct ConstTypeId_(
    /// Sadly this has to be `pub` so we can construct these from other crates.
    ///
    /// We could make a constructor, but there is no point.
    pub fn() -> std::any::TypeId,
);

impl From<ConstTypeId_> for std::any::TypeId {
    fn from(value: ConstTypeId_) -> Self {
        (value.0)()
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use assert_impl::assert_impl;
    use derive_deftly::{define_derive_deftly, Deftly};

    // This is the code-blob we use declare a `CONST_TYPE_ID_` member.
    define_derive_deftly! { HasConstTypeId_ =
        impl <$ tgens > $ttype
        where $ttype: 'static, $twheres {
            /// A version of `TypeId` that we can use with `inventory`.
            #[allow(dead_code, unreachable_pub)]
            #[doc(hidden)]
            pub const CONST_TYPE_ID_ : $crate::typeid::ConstTypeId_ = $crate::typeid::ConstTypeId_(
                std::any::TypeId::of::<$ttype>
            );
        }
    }

    #[derive(Deftly)]
    #[derive_deftly(HasConstTypeId_)]
    struct Foo(#[allow(unused)] usize);

    #[derive(Deftly)]
    #[derive_deftly(HasConstTypeId_)]
    struct Bar {}

    #[derive(Deftly)]
    #[derive_deftly(HasConstTypeId_)]
    struct Baz<T: 'static>(#[allow(unused)] T);

    #[test]
    fn typeid_basics() {
        use super::*;
        use std::any::{Any, TypeId};
        assert_impl!(Send: ConstTypeId_);
        assert_impl!(Sync: ConstTypeId_);
        let foo1 = Foo(3);
        let foo2 = Foo(4);
        let bar = Bar {};

        assert_eq!(TypeId::from(Foo::CONST_TYPE_ID_), foo1.type_id());
        assert_eq!(TypeId::from(Foo::CONST_TYPE_ID_), foo2.type_id());
        assert_eq!(TypeId::from(Bar::CONST_TYPE_ID_), bar.type_id());
        assert_ne!(TypeId::from(Foo::CONST_TYPE_ID_), bar.type_id());

        let baz1: Baz<u8> = Baz(10);
        let baz2: Baz<u8> = Baz(11);
        let baz3: Baz<u16> = Baz(12);
        assert_eq!(TypeId::from(Baz::<u8>::CONST_TYPE_ID_), baz1.type_id());
        assert_eq!(TypeId::from(Baz::<u8>::CONST_TYPE_ID_), baz2.type_id());
        assert_eq!(TypeId::from(Baz::<u16>::CONST_TYPE_ID_), baz3.type_id());
        assert_ne!(TypeId::from(Baz::<u8>::CONST_TYPE_ID_), baz3.type_id());
    }
}
