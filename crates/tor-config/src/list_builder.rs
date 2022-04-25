//! Config list builder for lists

/// Define a list builder struct and implement the conventional methods
///
/// The macro-generated builder struct contains `Option<Vec<ThingBuilder>>`, to allow it to
/// distinguish "never set" from "has been adjusted or set, possibly to the empty list".
///
/// `#[derive(Default, Clone, Deserialize)]` will be applied, but you can specify other attributes
/// too.  You should supply a doc comment for the builder struct, as shown in the example.
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
/// thinglist.set(vec![ThingBuilder::default().value(38).clone()]);
/// assert_eq!{ thinglist.build().unwrap().things, &[Thing { value: 38 }] }
/// ```
#[macro_export]
macro_rules! define_list_config_builder {
    {
        $(#[ $docs_and_attrs:meta ])*
        pub struct $ListBuilder:ident {
            $field_vis:vis $things:ident : [$EntryBuilder:ty] $(,)?
        }
        built: $Built:ty = $built:expr;
        default = $default:expr;
        $( item_build: $item_build:expr; )?
    } => {
        $(#[ $docs_and_attrs ])*
        #[derive(Default, Clone, Deserialize)]
        #[serde(transparent)]
        ///
        /// This is a builder pattern struct which will be resolved
        /// during configuration resolution, via the `build` method.
        pub struct $ListBuilder {
            /// The list, as overridden
            $field_vis $things: Option<Vec<$EntryBuilder>>,
        }
        impl $ListBuilder {
            /// Add one
            pub fn append(&mut self, item: $EntryBuilder) -> &mut Self {
                self.$things
                    .get_or_insert_with(|| $default)
                    .push(item);
                self
            }

            /// Set the list to the supplied one, discarding any previous settings
            pub fn set(&mut self, list: impl IntoIterator<Item = $EntryBuilder>) -> &mut Self {
                self.$things = Some(list.into_iter().collect());
                self
            }

            /// Checks whether any calls have been made to set or adjust the list
            pub fn is_unmodified_default(&self) -> bool {
                self.$things.is_none()
            }

            /// Resolve to a list of built items
            pub fn build(&self) -> Result<$Built, ConfigBuildError> {
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
                        $crate::macro_coalesce_args!{
                            [ $( $item_build )? ],
                            [ |item| item.build() ],
                        }
                    )
                    .collect::<Result<_, ConfigBuildError>>()?;
                Ok($built)
            }
        }
    }
}
