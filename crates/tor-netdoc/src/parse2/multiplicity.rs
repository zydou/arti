//! Multiplicity of fields (Items and Arguments)
//!
//! This module supports type-based handling of multiplicity,
//! of Items (within Documents) and Arguments (in Item keyword lines).
//!
//! It is **for use by macros**, rather than directly.
//!
//! # Explanation
//!
//! We use autoref specialisation to allow macros to dispatch to
//! trait impls for `Vec<T: ItemValueParseable>`, `Option<T>` etc.
//! as well as simply unadorned `T`.
//!
//! For Items we have `struct `[`ItemSetSelector<Field>`] and `trait `[`ItemSetMethods`].
//!
//! `ItemSetMethods` is implemented for `ItemSetSelector<Field>`
//! for each supported `Field`.
//! So, for `ItemSetSelector<T>`, `ItemSetSelector<Option<T>>`, and `ItemSetSelector<Vec<T>>`.
//! *But*, for just `T`, the impl is on `&ItemSetSelector<T>`.
//!
//! When methods on `ItemSetSelector` are called, the compiler finds
//! the specific implementation for `ItemSetSelector<Option<_>>` or `..Vec<_>`,
//! or, failing that, derefs and finds the blanket impl on `&ItemSetSelector<T>`.
//!
//! For Arguments we have [`ArgumentSetSelector`] and [`ArgumentSetMethods`],
//! which work similarly.

use super::*;

/// Helper type that allows us to select an impl of `ItemSetMethods`
///
/// **For use by macros**.
///
/// See the [module-level docs](multiplicity), and
/// [Field type in `NetdocParseable`](derive_deftly_template_NetdocParseable#field-type).
///
/// # Example
///
/// The code in the (derive) macro output is roughly like this:
///
/// ```
/// use tor_netdoc::parse2::multiplicity::{ItemSetSelector, ItemSetMethods as _};
///
/// let selector = ItemSetSelector::<Vec<i32>>::default();
/// let mut accum = None;
/// selector.accumulate(&mut accum, 12).unwrap();
/// let out = selector.finish(accum, "item-set").unwrap();
///
/// assert_eq!(out, [12]);
/// ```
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct ItemSetSelector<Field>(PhantomData<fn() -> Field>);

/// Methods for handling some multiplicity of Items
///
/// **For use by macros**.
///
/// During parsing, we accumulate into a value of type `Option<Self::Field>`.
/// The semantics of this are item-set-implementation-dependent;
/// using a type which is generic over the field type in a simple way
/// allows the partially-parsed accumulation state for a whole netdoc to have a concrete type.
///
/// See [`ItemSetSelector`] and the [module-level docs](multiplicity).
pub trait ItemSetMethods: Copy + Sized {
    /// The value for each Item.
    type Each: Sized;

    /// The output type: the type of the field in the netdoc struct.
    type Field: Sized;

    /// Can we accumulate another item ?
    ///
    /// Can be used to help predict whether `accumulate` will throw.
    fn can_accumulate(self, acc: &Option<Self::Field>) -> Result<(), EP>;

    /// Accumulate one value into the accumulator.
    fn accumulate(self, acc: &mut Option<Self::Field>, one: Self::Each) -> Result<(), EP>;

    /// Resolve the accumulator into the output.
    fn finish(
        self,
        acc: Option<Self::Field>,
        item_keyword: &'static str,
    ) -> Result<Self::Field, EP>;

    /// If the contained type is a sub-document, call its `is_intro_item_keyword`.
    fn is_intro_item_keyword(self, kw: KeywordRef<'_>) -> bool
    where
        Self::Each: NetdocParseable,
    {
        Self::Each::is_intro_item_keyword(kw)
    }

    /// `finish` for if the contained type is a wsub-document
    ///
    /// Obtain the sub-document's intro keyword from its `doctype_for_error`.
    fn finish_subdoc(self, acc: Option<Self::Field>) -> Result<Self::Field, EP>
    where
        Self::Each: NetdocParseable,
    {
        self.finish(acc, Self::Each::doctype_for_error())
    }

    /// Check that the element type is an Item
    ///
    /// For providing better error messages when struct fields don't implement the right trait.
    /// See `derive.rs`, and search for this method name.
    fn check_item_value_parseable(self)
    where
        Self::Each: ItemValueParseable,
    {
    }
    /// Check that the element type is a Signature
    fn check_signature_item_parseable(self)
    where
        Self::Each: SignatureItemParseable,
    {
    }
    /// Check that the element type is a sub-document
    fn check_subdoc_parseable(self)
    where
        Self::Each: NetdocParseable,
    {
    }
    /// Check that the element type is an argument
    fn check_item_argument_parseable(self)
    where
        Self::Each: ItemArgumentParseable,
    {
    }
}
impl<T> ItemSetMethods for ItemSetSelector<Vec<T>> {
    type Each = T;
    type Field = Vec<T>;
    // We always have None, or Some(nonempty)
    fn can_accumulate(self, _acc: &Option<Vec<T>>) -> Result<(), EP> {
        Ok(())
    }
    fn accumulate(self, acc: &mut Option<Vec<T>>, item: T) -> Result<(), EP> {
        acc.get_or_insert_default().push(item);
        Ok(())
    }
    fn finish(self, acc: Option<Vec<T>>, _keyword: &'static str) -> Result<Vec<T>, EP> {
        Ok(acc.unwrap_or_default())
    }
}
impl<T> ItemSetMethods for ItemSetSelector<Option<T>> {
    type Each = T;
    type Field = Option<T>;
    // We always have None, or Some(Some(_))
    fn can_accumulate(self, acc: &Option<Option<T>>) -> Result<(), EP> {
        if acc.is_some() {
            Err(EP::ItemRepeated)?;
        }
        Ok(())
    }
    // We always have None, or Some(Some(_))
    fn accumulate(self, acc: &mut Option<Option<T>>, item: T) -> Result<(), EP> {
        self.can_accumulate(acc)?;
        *acc = Some(Some(item));
        Ok(())
    }
    fn finish(self, acc: Option<Option<T>>, _keyword: &'static str) -> Result<Option<T>, EP> {
        Ok(acc.flatten())
    }
}
impl<T> ItemSetMethods for &'_ ItemSetSelector<T> {
    type Each = T;
    type Field = T;
    fn can_accumulate(self, acc: &Option<T>) -> Result<(), EP> {
        if acc.is_some() {
            Err(EP::ItemRepeated)?;
        }
        Ok(())
    }
    fn accumulate(self, acc: &mut Option<T>, item: T) -> Result<(), EP> {
        self.can_accumulate(acc)?;
        *acc = Some(item);
        Ok(())
    }
    fn finish(self, acc: Option<T>, keyword: &'static str) -> Result<T, EP> {
        acc.ok_or(EP::MissingItem { keyword })
    }
}

/// Helper type that allows us to select an impl of `ArgumentSetMethods`
///
/// **For use by macros**.
///
/// See the [module-level docs](multiplicity), and
/// [Field type in `ItemValueParseable`](derive_deftly_template_ItemValueParseable#field-type).
///
/// # Example
///
/// The code in the (derive) macro output is roughly like this:
///
/// ```
/// use tor_netdoc::parse2::multiplicity::{ArgumentSetSelector, ArgumentSetMethods as _};
/// use tor_netdoc::parse2::{ItemArgumentParseable, ItemStream};
/// let doc = "intro-item 12 66\n";
/// let mut items = ItemStream::new(doc).unwrap();
/// let mut item = items.next().unwrap().unwrap();
///
/// let args = ArgumentSetSelector::<Vec<i32>>::default()
///     .parse_with(item.args_mut(), "number", ItemArgumentParseable::from_args)
///     .unwrap();
/// assert_eq!(args, [12, 66]);
/// ```
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct ArgumentSetSelector<Field>(PhantomData<fn() -> Field>);

/// Method for handling some multiplicity of Arguments
///
/// **For use by macros**.
///
/// See [`ArgumentSetSelector`] and the [module-level docs](multiplicity).
pub trait ArgumentSetMethods: Copy + Sized {
    /// The value for each Item.
    type Each: Sized;

    /// The output type: the type of the field in the Item struct.
    ///
    /// This is *not* the type of an individual netdoc argument;
    /// that is not explicity represented in the trait.
    type Field: Sized;

    /// Parse zero or more argument(s) into `Self::Field`.
    fn parse_with<P>(
        self,
        args: &mut ArgumentStream<'_>,
        field: &'static str,
        parser: P,
    ) -> Result<Self::Field, EP>
    where
        P: for<'s> Fn(&mut ArgumentStream<'s>, &'static str) -> Result<Self::Each, EP>;

    /// Check that the element type is an Argument
    ///
    /// For providing better error messages when struct fields don't implement the right trait.
    /// See `derive.rs`, and search for this method name.
    fn check_argument_value_parseable(self)
    where
        Self::Each: ItemArgumentParseable,
    {
    }
}
impl<T> ArgumentSetMethods for ArgumentSetSelector<Vec<T>> {
    type Each = T;
    type Field = Vec<T>;
    fn parse_with<P>(
        self,
        args: &mut ArgumentStream<'_>,
        field: &'static str,
        parser: P,
    ) -> Result<Self::Field, EP>
    where
        P: for<'s> Fn(&mut ArgumentStream<'s>, &'static str) -> Result<Self::Each, EP>,
    {
        let mut acc = vec![];
        while args.is_nonempty_after_trim_start() {
            acc.push(parser(args, field)?);
        }
        Ok(acc)
    }
}
impl<T> ArgumentSetMethods for ArgumentSetSelector<Option<T>> {
    type Each = T;
    type Field = Option<T>;
    fn parse_with<P>(
        self,
        args: &mut ArgumentStream<'_>,
        field: &'static str,
        parser: P,
    ) -> Result<Self::Field, EP>
    where
        P: for<'s> Fn(&mut ArgumentStream<'s>, &'static str) -> Result<Self::Each, EP>,
    {
        if !args.is_nonempty_after_trim_start() {
            return Ok(None);
        }
        Ok(Some(parser(args, field)?))
    }
}
impl<T> ArgumentSetMethods for &ArgumentSetSelector<T> {
    type Each = T;
    type Field = T;
    fn parse_with<P>(
        self,
        args: &mut ArgumentStream<'_>,
        field: &'static str,
        parser: P,
    ) -> Result<Self::Field, EP>
    where
        P: for<'s> Fn(&mut ArgumentStream<'s>, &'static str) -> Result<Self::Each, EP>,
    {
        parser(args, field)
    }
}

/// Helper type that allows us to select an impl of `ObjectSetMethods`
///
/// **For use by macros**.
///
/// See the [module-level docs](multiplicity), and
/// [Field type in `ItemValueParseable`](derive_deftly_template_ItemValueParseable#field-type).
///
/// # Example
///
/// The code in the (derive) macro output is roughly like this:
///
/// ```
/// use tor_netdoc::parse2::multiplicity::{ObjectSetSelector, ObjectSetMethods as _};
/// use tor_netdoc::parse2::ItemStream;
/// let doc = "intro-item\n-----BEGIN OBJECT-----\naGVsbG8=\n-----END OBJECT-----\n";
/// let mut items = ItemStream::new(doc).unwrap();
/// let mut item = items.next().unwrap().unwrap();
///
/// let selector = ObjectSetSelector::<Option<String>>::default();
/// let obj = item.object().map(|obj| {
///     let data = obj.decode_data().unwrap();
///     TryFrom::try_from(data)
/// }).transpose().unwrap();
/// let obj = selector.resolve_option(obj).unwrap();
/// assert_eq!(obj, Some("hello".to_owned()));
/// ```
#[derive(Educe)]
#[educe(Clone, Copy, Default)]
pub struct ObjectSetSelector<Field>(PhantomData<fn() -> Field>);

/// Method for handling some multiplicity of Objects
///
/// **For use by macros**.
///
/// See [`ObjectSetSelector`] and the [module-level docs](multiplicity).
pub trait ObjectSetMethods: Copy + Sized {
    /// The value for each Item.
    type Each: Sized;

    /// The output type: the type of the field in the Item struct.
    type Field: Sized;

    /// Parse zero or more argument(s) into `Self::Field`.
    fn resolve_option(self, found: Option<Self::Each>) -> Result<Self::Field, EP>;

    /// If the contained type is `ItemObjectParseable`, call its `check_label`
    fn check_label(self, label: &str) -> Result<(), EP>
    where
        Self::Each: ItemObjectParseable,
    {
        Self::Each::check_label(label)
    }

    /// Check that the contained type can be parsed as an object
    fn check_object_parseable(self)
    where
        Self::Each: ItemObjectParseable,
    {
    }
}
impl<T> ObjectSetMethods for ObjectSetSelector<Option<T>> {
    type Field = Option<T>;
    type Each = T;
    fn resolve_option(self, found: Option<Self::Each>) -> Result<Self::Field, EP> {
        Ok(found)
    }
}
impl<T> ObjectSetMethods for &ObjectSetSelector<T> {
    type Field = T;
    type Each = T;
    fn resolve_option(self, found: Option<Self::Each>) -> Result<Self::Field, EP> {
        found.ok_or(EP::MissingObject)
    }
}
