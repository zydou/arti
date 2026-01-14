//! Deriving `NetdocEncodable`

use super::*;

use derive_deftly::{define_derive_deftly, define_derive_deftly_module};

/// Not `Copy`, used to detect when other arguments come after a `rest` field
///
/// Implementation detail of the encoding derives.
#[doc(hidden)]
#[allow(clippy::exhaustive_structs)]
pub struct RestMustComeLastMarker;

/// Displays `T` using the `fmt` function `F`
///
/// Implementation detail of the encoding derives.
#[doc(hidden)]
#[allow(clippy::exhaustive_structs)]
pub struct DisplayHelper<'t, T, F>(pub &'t T, pub F)
where
    F: Fn(&T, &mut fmt::Formatter) -> fmt::Result;

impl<'t, T, F> Display for DisplayHelper<'t, T, F>
where
    F: Fn(&T, &mut fmt::Formatter) -> fmt::Result,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.1(self.0, f)
    }
}

define_derive_deftly_module! {
    /// Common definitions for `NetdocEncodable` and `NetdocEncodableFields`
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocSomeItemsEncodableCommon beta_deftly:

    ${define P { $crate::encode }}

    // Suffix for error handling - specifically to add field informaton.
    //
    // Usage:
    //    some_function().$BUG_CONTEXT?;
    ${define BUG_CONTEXT {
        // We use .map_err() rather than .bug_context() so that we nail down the error type
        map_err(|bug: Bug| bug.bug_context(
            ${concat "in netdoc " $ttype ", in field " $F_KEYWORD_REPORT}
        ))
    }}

    // Body of an encoding function.
    //
    //    | <- macro conditions and loops are aligned starting here
    //    |         | <- we line up the normal Rust statements starting here
    ${define ENCODE_ITEMS_BODY {
                    $EMIT_DEBUG_PLACEHOLDER

          // Add an item with keyword $F_KEYWORD_STR and value `item`
          ${define ENCODE_ITEM_VALUE {
                    #[allow(unused_mut)]
                    let mut item_out = out.item($F_KEYWORD_STR);
            ${if fmeta(netdoc(with)) {
                    ${fmeta(netdoc(with)) as path}
                        ::${paste_spanned $fname write_item_value_onto}
                        (item, item_out)
                        .$BUG_CONTEXT?;
            } else if fmeta(netdoc(single_arg)) {
                    selector.${paste_spanned $fname check_item_argument_encodable}();
                    ItemArgument::${paste_spanned $fname write_arg_onto}
                        (item, &mut item_out)
                        .$BUG_CONTEXT?;
                    item_out.finish();
            } else {
                    selector.${paste_spanned $fname check_item_value_encodable}();
                    ItemValueEncodable
                        ::${paste_spanned $fname write_item_value_onto}
                        (item, item_out)
                        .$BUG_CONTEXT?;
            }}
          }}

          // Bind `selector` to an appropriate selector ZST.
          ${define LET_SELECTOR {
                         let selector = MultiplicitySelector::<$ftype>::default();
                         let selector = selector.selector();
          }}

          ${for fields {
                    { // Rust block for bindings for this field (notably `selector`, `item`

            // ignore #[deftly(netdoc(default))] precisely like NetdocSomeItemsParseableCommon
            ${if not(F_INTRO) {
                ${if fmeta(netdoc(default)) {}}
            }}

            ${select1
              F_INTRO {
                        #[allow(unused)] // `with` can make this unused
                        let selector = SingletonMultiplicitySelector::<$ftype>::default();
                        let item = &self.$fname;
                        $ENCODE_ITEM_VALUE
              }
              F_NORMAL {
                        $LET_SELECTOR
                        for item in selector.iter_ordered(&self.$fname) {
                            $ENCODE_ITEM_VALUE
                        }
              }
              F_FLATTEN {
                        <$ftype as NetdocEncodableFields>::encode_fields
                            (&self.$fname, out)
                            .$BUG_CONTEXT?;
              }
              F_SUBDOC {
                        $LET_SELECTOR
                        selector.${paste_spanned $fname check_netdoc_encodable}();
                        for subdoc in selector.iter_ordered(&self.$fname) {
                            NetdocEncodable::encode_unsigned(subdoc, out)
                                .$BUG_CONTEXT?;
                        }
              }
              F_SKIP {
              }
            }
                    } // field block.
          }} // ${for fields ..}

                    Ok(())
    }}
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocEntireDeriveCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsEncodableCommon;

    /// Derive [`NetdocEncodable`] for a document (or sub-document)
    ///
    // NB there is very similar wording in the NetdocParseable derive docs.
    // If editing any of this derive's documentation, considering editing that too.
    //
    // We could conceivably template this, but without a `$///` string templater in derive-deftly
    // that would be very tiresome, and it might be a bad idea anyway.
    //
    /// ### Expected input structure
    ///
    /// Should be applied named-field struct, where each field is
    /// an Item which may appear in the document,
    /// or a sub-document.
    ///
    /// The first field will be the document's intro Item.
    /// The output Keyword for each Item will be kebab-case of the field name.
    ///
    /// ### Field type
    ///
    /// Each field must be
    ///  * `impl `[`ItemValueEncodable`] for an "exactly once" field,
    ///  * `Vec<T: ItemValueEncodable>` for "zero or more", or
    ///  * `BTreeSet<T: ItemValueEncodable + Ord>`, or
    ///  * `Option<T: ItemValueEncodable>` for "zero or one".
    ///
    /// We don't directly support "at least once"; if the value is empty,
    /// the encoder will produce a structurally correct but semantically invalid document.
    ///
    /// (Multiplicity is implemented via types in the [`multiplicity`] module,
    /// specifically [`MultiplicitySelector`] and [`MultiplicityMethods`].)
    ///
    /// ### Signed documents
    ///
    /// TODO NETDOC ENCODE this is not yet supported.
    ///
    /// ### Top-level attributes:
    ///
    /// * **`#[deftly(netdoc(signatures))]`**:
    ///
    ///   This type is the signatures section of another document.
    ///   TODO NETDOC ENCODE This is not yet supported, and will fail to compile.
    ///
    $DOC_DEBUG_PLACEHOLDER
    ///
    /// # **`#[deftly(netdoc(doctype_for_error = "EXPRESSION"))]`**:
    ///
    ///   Ignored.  (The encoder does not report errors this way.)
    ///
    ///   Accepted for alignment with `NetdocParseable`,
    ///   so that a struct which only conditionally derives `NetdocParseable`
    ///   does not need to conditionally mark this attribute.
    ///
    /// ### Field-level attributes:
    ///
    /// * **`#[deftly(netdoc(keyword = STR))]`**:
    ///
    ///   Use `STR` as the Keyword for this Item.
    ///
    /// * **`#[deftly(netdoc(single_arg))]`**:
    ///
    ///   The field type implements `ItemArgument`,
    ///   instead of `ItemValueEncodable`,
    ///   and is encoded as if `(FIELD_TYPE,)` had been written.
    ///
    /// * **`#[deftly(netdoc(with = "MODULE"))]`**:
    ///
    ///   Instead of `ItemValueEncodable`, the item is parsed with
    ///   `MODULE::write_item_value_onto`,
    ///   which must have the same signature as [`ItemValueEncodable::write_item_value_onto`].
    ///
    ///   (Not supported for sub-documents, signature items, or field collections.)
    ///
    /// * **`#[deftly(netdoc(flatten))]`**:
    ///
    ///   This field is a struct containing further individual normal fields.
    ///   The Items for those individual fields appear in this
    ///   outer document here, so interspersed with other normal fields.
    ///
    ///   The field type must implement [`NetdocEncodableFields`].
    ///
    /// * **`#[deftly(netdoc(skip))]`**:
    ///
    ///   This field doesn't really appear in the network document.
    ///   It will be ignored during encoding.
    ///
    /// * **`#[deftly(netdoc(subdoc))]`**:
    ///
    ///   This field is a sub-document.
    ///   The value type `T` must implment [`NetdocEncodable`]
    ///   *instead of* `ItemValueEncodable`.
    ///
    ///   The field name is not used for parsging;
    ///   the sub-document's intro keyword is used instead.
    ///
    /// # **`#[deftly(netdoc(default))]`**:
    ///
    ///   Ignored.  (The encoder always encodes the field, regardless of the value.)
    ///
    ///   Accepted for alignment with `NetdocParseable`.
    ///
    /// # Example
    ///
    /// TODO NETDOC ENCODE provide an example when signatures are implemented.
    export NetdocEncodable beta_deftly, for struct, expect items:

    ${if T_SIGNATURES { ${error "Encoding of signatures sub-documents is not yet supported" }}}

    impl<$tgens> $P::NetdocEncodable for $ttype {
        fn encode_unsigned(&self, out: &mut $P::NetdocEncoder) -> Result<(), $P::Bug> {
            use $P::*;

            $FIELD_ORDERING_CHECK
            $ENCODE_ITEMS_BODY
        }
    }
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocFieldsDeriveCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsEncodableCommon;

    /// Derive [`NetdocEncodableFields`] for a struct with individual items
    ///
    /// Similar to
    /// [`#[derive_deftly(NetdocEncodable)]`](derive_deftly_template_NetdocEncodable),
    /// but:
    ///
    ///  * Derives [`NetdocEncodableFields`]
    $DOC_NETDOC_FIELDS_DERIVE_SUPPORTED
    ///
    export NetdocEncodableFields beta_deftly, for struct, expect items:

    impl<$tgens> $P::NetdocEncodableFields for $ttype {
        fn encode_fields(&self, out: &mut $P::NetdocEncoder) -> Result<(), $P::Bug> {
            use $P::*;

            $ENCODE_ITEMS_BODY
        }
    }
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocItemDeriveCommon;

    /// Derive `ItemValueEncodable`
    ///
    // NB there is very similar wording in the ItemValuePareable derive docs.
    // If editing any of this derive's documentation, considering editing that too.
    //
    /// Fields in the struct are emitted as keyword line arguments,
    /// in the order they appear in the struct.
    ///
    /// ### Field type
    ///
    /// Each field should be:
    ///
    ///  * `impl `[`ItemArgument`] (one argument),
    ///  * `Option<impl ItemArgument>` (one optional argument), or
    ///  * `Vec<impl ItemArgument + EncodeOrd>` (zero or more arguments).
    ///  * `BTreeSet<impl ItemArgument>` (zero or more arguments).
    ///
    /// `ItemArgument` can be implemented via `impl Display`,
    /// by writing `impl NormalItemArgument`.
    ///
    /// (Multiplicity is implemented via types in the [`multiplicity`] module,
    /// specifically [`MultiplicitySelector`] and [`MultiplicityMethods`].)
    ///
    /// ### Top-level attributes:p
    ///
    ///  * **`#[deftly(netdoc(no_extra_args))]**:
    ///
    ///    Ignored.
    ///    (Obviously, the encoder never emits arguments that aren't in the document struct.)
    ///
    ///    Accepted for alignment with `ItemValueParseable`,
    ///    so that a struct which only conditionally derives `ItemValueParseable`
    ///    does not need to conditionally mark this attribute.
    ///
    ///    (May not be combined with `#[deftly(netdoc(rest))]`.)
    ///
    $DOC_DEBUG_PLACEHOLDER
    ///
    /// ### Field-level attributes:
    ///
    ///  * **`#[deftly(netdoc(rest))]**:
    ///
    ///    The field is the whole rest of the line.
    ///    Must come after any other normal argument fields.
    ///    Only allowed once.
    ///
    ///    The field type must implement `ToString` (normally, via `Display`).
    ///    (I.e. `Vec` , `Option` etc., are not allowed, and `ItemArgumen` is not used.)
    ///
    ///  * **`#[deftly(netdoc(object))]**:
    ///
    ///    The field is the Object.
    ///    It must implement [`ItemObjectEncodable`].
    ///    (or be `Option<impl ItemObjectEncodable>`).
    ///
    ///    Only allowed once.
    ///
    ///  * **`#[deftly(netdoc(object(label = "LABEL")))]**:
    ///
    ///    Sets the expected label for an Object.
    ///    If not supplied, uses [`ItemObjectEncodable::label`].
    ///
    ///  * **`#[deftly(netdoc(with = "MODULE")]**:
    ///
    ///    Instead of `ItemArgument`, the argument is encoded with `MODULE::write_arg_onto`,
    ///    which must have the same signature as [`ItemArgument::write_arg_onto`].
    ///
    ///    With `#[deftly(netdoc(rest))]`, `MODULE::fmt_args_rest` replaces `Display::fmt`.
    ///
    ///    With `#[deftly(netdoc(object))]`, uses `MODULE::write_object_onto`
    ///    instead of `tor_netdoc::Writeable::write_onto`.
    ///    LABEL must also be specified unless the object also implements `ItemObjectEncodable`.
    ///
    ///  * **`#[deftly(netdoc(sig_hash = "HASH_METHOD"))]**:
    ///
    ///    TODO NETDOC ENCODE.  Encoding of signed documents is not yet implemented.
    export ItemValueEncodable beta_deftly, for struct, expect items:

    ${define P { $crate::encode }}

    ${define LET_SELECTOR {
                    let selector = MultiplicitySelector::<$ftype>::default();
                    let selector = selector.selector();
    }}

    ${define BUG_CONTEXT {
        // We use .map_err() rather than .bug_context() so that we nail down the error type
        map_err(|bug: Bug| bug.bug_context(
            ${concat "in item " $ttype ", in field " $fname}
        ))
    }}

    impl<$tgens> $P::ItemValueEncodable for $ttype {
        fn write_item_value_onto(
            &self,
            #[allow(unused)]
            mut out: $P::ItemEncoder,
        ) -> $P::Result<(), $P::Bug> {
          //  | <- macro conditions and loops are aligned starting here
          //  |         | <- we line up the normal Rust statements starting here
                        #[allow(unused_imports)]
                        use $P::*;
                        #[allow(unused_imports)]
                        use tor_error::BugContext as _;

                        $EMIT_DEBUG_PLACEHOLDER

                        // ignore #[deftly(netdoc(doctype_for_error = EXPR))]
                        let _: &str = ${tmeta(netdoc(doctype_for_error)) as expr, default {""}};

                        #[allow(unused)]
                        let rest_must_come_last_marker = RestMustComeLastMarker;

              ${for fields {
                        {
                ${select1
                  F_NORMAL {
                            let _ = &rest_must_come_last_marker;
                            $LET_SELECTOR
                      ${if not(fmeta(netdoc(with))) {
                            selector.${paste_spanned $fname check_item_argument_encodable}();
                      }}
                            for arg in selector.iter_ordered(&self.$fname) {
                      ${fmeta(netdoc(with)) as path, default {
                                ItemArgument
                      }}
                                    ::${paste_spanned $fname write_arg_onto}
                                    (arg, &mut out)
                                    .$BUG_CONTEXT?;
                            }
                  }
                  F_REST {
                            let _moved = rest_must_come_last_marker;
                            out.args_raw_string(&DisplayHelper(
                                &self.$fname,
                      ${if fmeta(netdoc(with)) {
                                ${fmeta(netdoc(with)) as path}
                                ::${paste_spanned $fname fmt_args_rest}
                      } else {
                                <$ftype as Display>::fmt
                      }}
                                ));
                  }
                  F_SIG_HASH {
                    ${error "NYI"}
                  }
                  F_OBJECT {
                            // We do this one later, in case it's not last in the struct.
                            // It consumes `out`.
                  }
                }
                        } // per-field local variables scope
              }}

                // Look at some almost-entirely-ignored attributes.
                ${if tmeta(netdoc(no_extra_args)) {
                        let _consume = rest_must_come_last_marker;
                }}

              ${for fields {
                ${when F_OBJECT}

                        $LET_SELECTOR
                        if let Some(object) = selector.as_option(&self.$fname) {
                ${define CHECK_OBJECT_ENCODABLE {
                            selector.${paste_spanned $fname check_item_object_encodable}();
                }}
                            // Bind to `label`
                            let label =
                ${fmeta(netdoc(object(label))) as str, default {
                                {
                                    $CHECK_OBJECT_ENCODABLE
                                    ItemObjectEncodable::label(object)
                                }
                }}
                                ;

                            // Obtain the `data`
                            let mut data: Vec<u8> = vec![];
                      ${fmeta(netdoc(with)) as path, default {
                                ItemObjectEncodable
                      }}
                                ::${paste_spanned $fname write_object_onto}
                                (object, &mut data)
                                .map_err(into_internal!("failed to encode byte array!"))
                                .$BUG_CONTEXT?;

                            out.object(label, data);

                        } // if let Some(field)
              }}

                        Ok(())
            }
    }
}
