//! Config list builder for lists

/// Define a list builder struct and implement the conventional methods
///
/// The macro-generated builder struct contains `Option<Vec<ThingBuilder>>`, to allow it to
/// distinguish "never set" from "has been adjusted or set, possibly to the empty list".
///
/// `#[derive(Default, Clone, Deserialize)]` will be applied, but you can specify other attributes
/// too.  You should supply a doc comment for the builder struct, as shown in the example.
/// The doc comment should state the default value.
///
/// The `built` clause specifies the type of the built value, and how to construct it.
/// In the expression part, `things` (the field name) will be the resolved `Vec<Thing>`
/// and should be consumed by the expression.
/// If the built value is simply a `Vec`, you can just write `built: things;`.
///
/// The `default` clause must provide an expression evaluating to a `Vec<ThingBuilder>`.  If it is
/// nontrivial, you should put the actual defaulting functionality in a (probably-private)
/// function, as the macro will expand it twice.
///
/// The `item_build` clause, if supplied, provides a closure with type
/// `FnMut(&ThingBuilder) -> Result<Thing, ConfigBuildErro>`; the default is to call
/// `thing_builder.build()`.
///
/// ### Example - list of structs with builders
///
/// ```
/// use derive_builder::Builder;
/// use serde::Deserialize;
/// use tor_config::{define_list_config_builder, ConfigBuildError};
///
/// #[derive(Builder, Debug, Eq, PartialEq)]
/// #[builder(build_fn(error = "ConfigBuildError"))]
/// #[builder(derive(Deserialize))]
/// pub struct Thing { value: i32 }
///
/// #[derive(Debug)]
/// pub struct ThingList { things: Vec<Thing> }
///
/// define_list_config_builder! {
///    /// List of things, being built as part of the configuration
///    pub struct ThingListBuilder {
///        pub(crate) things: [ThingBuilder],
///    }
///    built: ThingList = ThingList { things };
///    default = vec![];
/// }
///
/// let mut thinglist = ThingListBuilder::default();
/// thinglist.append(ThingBuilder::default().value(42).clone());
/// assert_eq!{ thinglist.build().unwrap().things, &[Thing { value: 42 }] }
///
/// thinglist.replace(vec![ThingBuilder::default().value(38).clone()]);
/// assert_eq!{ thinglist.build().unwrap().things, &[Thing { value: 38 }] }
/// ```
///
/// ### Example - list of trivial values
///
/// ```
/// use derive_builder::Builder;
/// use serde::Deserialize;
/// use tor_config::{define_list_config_builder, ConfigBuildError};
///
/// #[derive(Debug)]
/// pub struct ValueList { values: Vec<u32> }
///
/// define_list_config_builder! {
///    /// List of values, being built as part of the configuration
///    pub struct ValueListBuilder {
///        pub(crate) values: [u32],
///    }
///    built: ValueList = ValueList { values };
///    default = vec![27];
///    item_build: |&value| Ok(value);
/// }
///
/// let mut valuelist = ValueListBuilder::default();
/// assert_eq!{ valuelist.build().unwrap().values, &[27] }
///
/// valuelist.append(12);
/// assert_eq!{ valuelist.build().unwrap().values, &[27, 12] }
/// ```

#[macro_export]
macro_rules! define_list_config_builder {
    {
        $(#[ $docs_and_attrs:meta ])*
        $vis:vis struct $ListBuilder:ident {
            $field_vis:vis $things:ident : [$EntryBuilder:ty] $(,)?
        }
        built: $Built:ty = $built:expr;
        default = $default:expr;
        $( item_build: $item_build:expr; )?
    } => {
        $(#[ $docs_and_attrs ])*
        #[derive(Default, Clone, $crate::serde::Deserialize)]
        #[serde(transparent)]
        ///
        /// This is a builder pattern struct which will be resolved
        /// during configuration resolution, via the `build` method.
        $vis struct $ListBuilder {
            /// The list, as overridden
            $field_vis $things: Option<Vec<$EntryBuilder>>,
        }
        impl $ListBuilder {
            /// Add one item to the end of the list.
            ///
            /// If the list hasn't been set or adjusted yet, it is initialised to the default.
            /// Then `item` is added.
            $vis fn append(&mut self, item: $EntryBuilder) -> &mut Self {
                self.$things
                    .get_or_insert_with(|| $default)
                    .push(item);
                self
            }

            /// Set the list to the supplied one, discarding any previous settings.
            ///
            /// After `replace` has been called, the default list will no longer be used.
            $vis fn replace(&mut self, list: impl IntoIterator<Item = $EntryBuilder>) -> &mut Self {
                self.$things = Some(list.into_iter().collect());
                self
            }

            /// Checks whether any calls have been made to set or adjust the list.
            ///
            /// If `append` or `replace` have been called, this will return `true`.
            $vis fn is_unmodified_default(&self) -> bool {
                self.$things.is_none()
            }

            /// Resolve this list to a list of built items.
            ///
            /// If the value is still the [`Default`],
            /// a built-in default list will be built and returned;
            /// otherwise each applicable item will be built,
            /// and the results collected into a single built list.
            $vis fn build(&self) -> Result<$Built, $crate::ConfigBuildError> {
                let default_buffer;
                let $things = match &self.$things {
                    Some($things) => $things,
                    None => {
                        default_buffer = $default;
                        &default_buffer
                    }
                };

                let $things = $things
                    .iter()
                    .map(
                        $crate::macro_first_nonempty!{
                            [ $( $item_build )? ],
                            [ |item| item.build() ],
                        }
                    )
                    .collect::<Result<_, $crate::ConfigBuildError>>()?;
                Ok($built)
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn nonempty_default() {
        define_list_config_builder! {
            struct ListBuilder {
                chars: [char],
            }
            built: List = chars;
            default = vec!['a'];
            item_build: |&c| Ok(c);
        }

        type List = Vec<char>;

        let mut b = ListBuilder::default();
        assert!(b.is_unmodified_default());
        assert_eq! { (&b).build().expect("build failed"), ['a'] };

        b.append('b');
        assert!(!b.is_unmodified_default());
        assert_eq! { (&b).build().expect("build failed"), ['a', 'b'] };

        for mut b in IntoIterator::into_iter([b, ListBuilder::default()]) {
            b.replace(vec!['x', 'y']);
            assert!(!b.is_unmodified_default());
            assert_eq! { (&b).build().expect("build failed"), ['x', 'y'] };
        }
    }
}
