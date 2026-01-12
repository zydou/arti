//! Deriving `NetdocParseable`

use super::*;

/// Helper to implemnet `dtrace!` inside `NetdocParseable` derive-deftly macro.
#[doc(hidden)]
pub fn netdoc_parseable_derive_debug(ttype: &str, msg: &str, vals: &[&dyn Debug]) {
    // Take a lock like this so that all our output appears at once,
    // rather than possibly being interleaved with similar output for other types.
    let mut out = std::io::stderr().lock();
    (|| {
        write!(out, "netdoc {ttype} parse: {msg}")?;
        for val in vals {
            write!(out, ", {val:?}")?;
        }
        writeln!(out)
    })()
    .expect("write to stderr failed");
}

define_derive_deftly_module! {
    /// Common definitions for `NetdocParseable` and `NetdocParseableFields`
    ///
    ///  * **`THIS_ITEM`**: consumes the next item and evaluates to it as an `UnparsedItem`.
    ///    See the definition in `NetdocParseable`.
    ///
    ///  * **`F_ACCUMULATE_VAR`** the variable or field into which to accumulate
    ///    normal items for this field.  Must be of type `&mut $F_ACCUMULATE_TYPE`.
    ///
    /// Importer must also import `NetdocSomeItemsDeriveCommon` and `NetdocDeriveAnyCommon`.
    NetdocSomeItemsParseableCommon beta_deftly:

    // Convenience alias for our prelude
    ${define P { $crate::parse2::internal_prelude }}

    // Defines the `dtrace` macro.
    ${define DEFINE_DTRACE {
        #[allow(unused_macros)]
        macro_rules! dtrace { { $$msg:literal $$(, $$val:expr )* $$(,)? } => {
          ${if tmeta(netdoc(debug)) {
              $P::netdoc_parseable_derive_debug(
                  ${concat $ttype},
                  $$msg,
                  &[ $$( &&$$val as _, )* ],
              )
          }}
        }}
    }}

    // The effective field type for parsing.
    //
    // Handles #[deftly(netdoc(default))], in which case we parse as if the field was Option,
    // and substitute in the default at the end.
    //
    ${define F_EFFECTIVE_TYPE {
        ${if all(fmeta(netdoc(default))) {
            Option::<$ftype>
        } else {
            $ftype
        }}
    }}

    // Provide `$<selector_ $fname>` for every (suitable) field.
    ${define ITEM_SET_SELECTORS {
        $(
          ${when not(any(F_FLATTEN, F_SKIP))}

          // See `mod multiplicity`.
        ${if not(all(F_INTRO, fmeta(netdoc(with)))) {
          // If the intro it has `with`, we don't check its trait impl, and this ends up unused
          let $<selector_ $fname> = $F_SELECTOR_VALUE;
        }}
        )
    }}
    // The item set selector for this field.
    // We must provide this, rather than expanding $<selector_ $fname> at the use sites,
    // because the identifier `selector_` has different macro_rules hygiene here vs there!
    // TODO derive-deftly#130
    ${define F_SELECTOR $<selector_ $fname>}
    // The selector value for this field.  Used where we don't want to bind a selector
    // for every field with $ITEM_SET_SELECTORS (and within $ITEM_SET_SELECTORS).
    ${define F_SELECTOR_VALUE {( MultiplicitySelector::<$F_EFFECTIVE_TYPE>::default() )}}
    // Check that every field type implements the necessary trait.
    ${define CHECK_FIELD_TYPES_PARSEABLE {
        $(
          ${when not(any(F_FLATTEN, F_SKIP))}

          // Expands to `selector_FIELD.check_SOMETHING();`
          //
          // If the relevant trait isn't implemented, rustc reports the error by
          // pointing at the `check-something` call.  We re-span that identifier
          // to point to the field name, so that's where the error is reported.
          //
          // Without this, we just get a report that `item` doesn't implement the required
          // trait - but `item` is a local variable here, so the error points into the macro
        ${if not(all(any(F_INTRO, F_NORMAL), fmeta(netdoc(with)))) {
          $<selector_ $fname> . ${paste_spanned $fname ${select1
                  any(F_INTRO, F_NORMAL){
                      // For the intro item, this is not completely precise, because the
                      // it will allow Option<> and Vec<> which aren't allowed there.
                      ${if
                        fmeta(netdoc(single_arg)) { check_item_argument_parseable }
                        else { check_item_value_parseable }
                      }
                  }
                  F_SIGNATURE { check_signature_item_parseable }
                  F_SUBDOC    { check_subdoc_parseable         }
          }} ();
        }}
        )
    }}

    // Convert the UnparsedItem (in `item` to the value (to accumulate).
    // Expands to an expression.
    ${define ITEM_VALUE_FROM_UNPARSED {
        ${if fmeta(netdoc(with)) {
          ${fmeta(netdoc(with)) as path}
              ::${paste_spanned $fname from_unparsed}
              (item)?
        } else if fmeta(netdoc(single_arg)) { {
          let item = ItemValueParseable::from_unparsed(item)?;
          let (item,) = item;
          item
        } } else {
          ItemValueParseable::from_unparsed(item)?
        }}
    }}

    // Type into which we accumulate value(s) of this field
    ${define F_ACCUMULATE_TYPE {
        ${if F_FLATTEN {
            <$ftype as $P::NetdocParseableFields>::Accumulator
        } else {
            Option::<$F_EFFECTIVE_TYPE>
        }
    }}}

    // Accumulates `item` (which must be `ItemSetMethods::Each`) into `$F_ACCUMULATE_VAR`
    ${define ACCUMULATE_ITEM_VALUE { {
        $F_SELECTOR.${paste_spanned $fname accumulate}($F_ACCUMULATE_VAR, item)?;
    } }}

    // Handle a nonstructural field, parsing and accumulating its value
    //
    // Looks at `kw` for the keyword.
    //
    // Expands to a series of `if ... { ... } else`.
    // The use site must provide (maybe further arms) and a fallback block!
    //
    // If the item is the intro item for this document, evaluates `break` -
    // so if `f_INTRO` is not trivially false, must be expanded within a field loop.
    ${define NONSTRUCTURAL_ACCUMULATE_ELSE {
        ${for fields {
          ${when not(any(F_FLATTEN, F_SUBDOC, F_SKIP))}

          if kw == $F_KEYWORD {
            ${select1
              F_NORMAL {
                let item = $THIS_ITEM;
                dtrace!("is normal", item);
                let item = $ITEM_VALUE_FROM_UNPARSED;
                $ACCUMULATE_ITEM_VALUE
              }
              F_SIGNATURE {
                let hash_inputs = input
                      .peek_signature_hash_inputs(signed_doc_body)?
                      .expect("not eof, we peeked kw");

                let item = $THIS_ITEM;
                dtrace!("is signature", item);
                let item =
                    SignatureItemParseable::from_unparsed_and_body(item, &hash_inputs)?;
                $ACCUMULATE_ITEM_VALUE
              }
              F_INTRO {
                dtrace!("is intro", kw);
                break;
              } // start of next similar document
            }
          } else
        }}
        ${for fields {
          ${when F_FLATTEN}

          if $ftype::is_item_keyword(kw) {
              dtrace!(${concat "is flatten in " $fname}, kw);
              let item = $THIS_ITEM;
              <$ftype as NetdocParseableFields>::accumulate_item($F_ACCUMULATE_VAR, item)?;
          } else
        }}
    }}

    // Completes a document
    //
    // The fields accumulated so far must be in `$fpatname` (as a value, not a ref,
    // and therefore not in $F_ACCUMULATE_VAR).
    //
    // Expands to code which resolves the fields, and ends with `Ok(document value)`.
    ${define FINISH_RESOLVE {
        ${for fields {
            ${select1
              F_INTRO {}
              any(F_NORMAL, F_SIGNATURE) {
                  let $fpatname = $F_SELECTOR.finish($fpatname, $F_KEYWORD_REPORT)?;
              }
              F_FLATTEN {
                  let $fpatname = <$ftype as NetdocParseableFields>::finish($fpatname)?;
              }
              F_SUBDOC {
                  let $fpatname = $F_SELECTOR.finish_subdoc($fpatname)?;
              }
              F_SKIP {
                  #[allow(non_snake_case)]
                  let $fpatname = Default::default();
              }
            }
        }}
        $(
            ${when not(any(F_INTRO, F_SKIP))}
            // These conditions are mirrored in NetdocSomeItemsEncodableCommon,
            // which is supposed to recognise netdoc(default) precisely when we do.
          ${if fmeta(netdoc(default)) {
            let $fpatname = Option::unwrap_or_default($fpatname);
          }}
        )
        Ok($vpat)
    }}
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocEntireDeriveCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsParseableCommon;

    /// Derive [`NetdocParseable`] for a document (or sub-document)
    ///
    // NB there is very similar wording in the NetdocEncodable derive docs.
    // If editing any of this derive's documentation, considering editing that too.
    //
    /// ### Expected input structure
    ///
    /// Should be applied named-field struct, where each field is
    /// an Item which may appear in the document,
    /// or a sub-document.
    ///
    /// The first field will be the document's intro Item.
    /// The expected Keyword for each Item will be kebab-case of the field name.
    ///
    /// ### Field type
    ///
    /// Each field must be
    ///  * `impl `[`ItemValueParseable`] for an "exactly once" field,
    ///  * `Vec<T: ItemValueParseable>` for "zero or more", or
    ///  * `BTreeSet<T: ItemValueParseable + Ord>`, or
    ///  * `Option<T: ItemValueParseable>` for "zero or one".
    ///
    /// We don't directly support "at least once":
    /// the parsed network document doesn't imply the invariant
    /// that at least one such item was present.
    // We could invent a `NonemptyVec` or something for this.
    ///
    /// (This is implemented via types in the [`multiplicity`] module,
    /// specifically [`ItemSetSelector`].)
    ///
    /// ### Signed documents
    ///
    /// To handle signed documents define two structures:
    ///
    ///  * `Foo`, containing only the content, not the signatures.
    ///    Derive `NetdocParseable` and [`NetdocSigned`](derive_deftly_template_NetdocSigned).
    ///  * `FooSignatures`, containing only the signatures.
    ///    Derive `NetdocParseable` with `#[deftly(netdoc(signatures))]`.
    ///
    /// Don't mix signature items with non-signature items in the same struct.
    /// (This wouldn't compile, because the field type would implement the wrong trait.)
    ///
    /// ### Top-level attributes:
    ///
    /// * **`#[deftly(netdoc(doctype_for_error = "EXPRESSION"))]`**:
    ///
    ///   Specifies the value to be returned from
    ///   [`NetdocParseable::doctype_for_error`].
    ///
    ///   Note, must be an expression, so for a literal, nested `""` are needed.
    ///
    ///   The default is the intro item keyword.
    ///
    /// * **`#[deftly(netdoc(signatures))]`**:
    ///
    ///   This type is the signatures section of another document.
    ///   Signature sections have no separate intro keyword:
    ///   every field is structural and they are recognised in any order.
    ///
    ///   Fields must implement [`SignatureItemParseable`],
    ///   rather than [`ItemValueParseable`],
    ///
    ///   This signatures sub-document will typically be included in a
    ///   `FooSigned` struct derived with
    ///   [`NetdocSigned`](derive_deftly_template_NetdocSigned),
    ///   rather than included anywhere manually.
    ///
    /// * **`#[deftly(netdoc(debug))]`**:
    ///
    ///   The generated implementation will generate copious debug output
    ///   to the program's stderr when it is run.
    ///   Do not enable in production!
    ///
    /// ### Field-level attributes:
    ///
    /// * **`#[deftly(netdoc(keyword = STR))]`**:
    ///
    ///   Use `STR` as the Keyword for this Item.
    ///
    /// * **`#[deftly(netdoc(single_arg))]`**:
    ///
    ///   The field type implements `ItemArgumentParseable`,
    ///   instead of `ItemValueParseable`,
    ///   and is parsed as if `(FIELD_TYPE,)` had been written.
    ///
    /// * **`#[deftly(netdoc(with = "MODULE"))]`**:
    ///
    ///   Instead of `ItemValueParseable`, the item is parsed with `MODULE::from_unparsed`,
    ///   which must have the same signature as [`ItemValueParseable::from_unparsed`].
    ///
    ///   (Not supported for sub-documents, signature items, or field collections.)
    ///
    /// * **`#[deftly(netdoc(default))]`**:
    ///
    ///   This field is optional ("at most once");
    ///   if not present, `FIELD_TYPE::default()` will be used.
    ///
    ///   This is an alternative to declaring the field type as `Option`
    ///   With `netdoc(default)`, the field value doesn't need unwrapping.
    ///   With `Option` it is possible to see if the field was provided.
    ///
    /// * **`#[deftly(netdoc(flatten))]`**:
    ///
    ///   This field is a struct containing further individual normal fields.
    ///   The Items for those individual fields can appear in *this*
    ///   outer document in any order, interspersed with other normal fields.
    ///
    ///   The field type must implement [`NetdocParseableFields`].
    ///
    /// * **`#[deftly(netdoc(skip))]`**:
    ///
    ///   This field doesn't really appear in the network document.
    ///   It won't be recognised during parsing.
    ///   Instead, `Default::default()` will be used for the field value.
    ///
    /// * **`#[deftly(netdoc(subdoc))]`**:
    ///
    ///   This field is a sub-document.
    ///   The value type `T` must implment [`NetdocParseable`]
    ///   *instead of* `ItemValueParseable`.
    ///
    ///   The field name is not used for parsging;
    ///   the sub-document's intro keyword is used instead.
    ///
    ///   Sub-documents are expected to appear after all normal items,
    ///   in the order presented in the struct definition.
    ///
    /// # Example
    ///
    /// ```
    /// use derive_deftly::Deftly;
    /// use tor_netdoc::derive_deftly_template_NetdocParseable;
    /// use tor_netdoc::derive_deftly_template_NetdocSigned;
    /// use tor_netdoc::derive_deftly_template_ItemValueParseable;
    /// use tor_netdoc::parse2::{parse_netdoc, ParseInput, VerifyFailed};
    /// use tor_netdoc::parse2::{SignatureItemParseable, SignatureHashInputs};
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(NetdocParseable, NetdocSigned)]
    /// pub struct NdThing {
    ///     pub thing_start: (),
    ///     pub value: (String,),
    /// }
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(NetdocParseable)]
    /// #[deftly(netdoc(signatures))]
    /// pub struct NdThingSignatures {
    ///     pub signature: FoolishSignature,
    /// }
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(ItemValueParseable)]
    /// pub struct FoolishSignature {
    ///     pub doc_len: usize,
    ///
    ///     #[deftly(netdoc(sig_hash = "use_length_as_foolish_hash"))]
    ///     pub doc_len_actual_pretending_to_be_hash: usize,
    /// }
    ///
    /// fn use_length_as_foolish_hash(body: &SignatureHashInputs) -> usize {
    ///     body.body().body().len()
    /// }
    ///
    /// let doc_text =
    /// r#"thing-start
    /// value something
    /// signature 28
    /// "#;
    ///
    /// impl NdThingSigned {
    ///     pub fn verify_foolish_timeless(self) -> Result<NdThing, VerifyFailed> {
    ///         let sig = &self.signatures.signature;
    ///         if sig.doc_len != sig.doc_len_actual_pretending_to_be_hash {
    ///             return Err(VerifyFailed::VerifyFailed);
    ///         }
    ///         Ok(self.body)
    ///     }
    /// }
    ///
    /// let input = ParseInput::new(&doc_text, "<input>");
    /// let doc: NdThingSigned = parse_netdoc(&input).unwrap();
    /// let doc = doc.verify_foolish_timeless().unwrap();
    /// assert_eq!(doc.value.0, "something");
    /// ```
    export NetdocParseable for struct, expect items, beta_deftly:

    ${define F_ACCUMULATE_VAR { (&mut $fpatname) }}

    impl<$tgens> $P::NetdocParseable for $ttype {
        fn doctype_for_error() -> &'static str {
            ${tmeta(netdoc(doctype_for_error)) as expr,
              default ${concat ${for fields { ${when F_INTRO} $F_KEYWORD_STR }}}}
        }

        fn is_intro_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
            use $P::*;

            ${for fields {
                ${when any(F_SIGNATURE, F_INTRO)}
                kw == $F_KEYWORD
            }}
        }

        fn is_structural_keyword(kw: $P::KeywordRef<'_>) -> Option<$P::IsStructural> {
            #[allow(unused_imports)] // not used if there are no subdocs
            use $P::*;

            if Self::is_intro_item_keyword(kw) {
                return Some(IsStructural)
            }

            ${for fields {
                ${when F_SUBDOC}
                if let y @ Some(_) = $F_SELECTOR_VALUE.is_structural_keyword(kw) {
                    return y;
                }
            }}

            None
        }

        //##### main parsing function #####

        #[allow(clippy::redundant_locals)] // let item = $THIS_ITEM, which might be item
        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            outer_stop: $P::stop_at!(),
        ) -> $P::Result<$ttype, $P::ErrorProblem> {
            use $P::*;
            $DEFINE_DTRACE
            $FIELD_ORDERING_CHECK

            //----- prepare item set selectors for every field -----
            $ITEM_SET_SELECTORS
            $CHECK_FIELD_TYPES_PARSEABLE

            // Is this an intro item keyword ?
            //
            // Expands to an appropriate `is_intro_item_keyword` method invocation,
            // but *without arguments*.  So, something a bit like an expression of type
            //    fn(KeywordRef) -> bool
            ${define F_SUBDOC_IS_INTRO_ITEM_KEYWORD {
                ${if not(F_SUBDOC) { ${error "internal-error: subdoc kw, but not subdoc field"} }}
                $F_SELECTOR.is_intro_item_keyword
            }}

            //----- Helper fragments for parsing individual pieces of the document -----

            // Peeks a keyword, and returns it but only if it's part of this (sub)doc.
            // Return `None` if it was in outer_stop
            let peek_keyword = |input: &mut ItemStream<'s>| -> Result<Option<KeywordRef<'s>>, EP> {
                let Some(kw) = input.peek_keyword()? else {
                    dtrace!("stopping, because EOF");
                    return Ok(None)
                };
                if outer_stop.stop_at(kw) {
                    dtrace!("stopping, because peeked", kw);
                    return Ok(None)
                }
                Ok(Some(kw))
            };

            // Returns the actual item as an UnparsedItem, committing to consuming it.
            // Can panic if called without previous `peek_keyword`.
            ${define THIS_ITEM  {
                input.next_item()?.expect("peeked")
            }}

            //----- keyword classification closures -----

            // Is this a keyword for one of our sub-documents?
            let is_subdoc_kw = ${for fields {
                ${when F_SUBDOC}
                StopAt(|kw: KeywordRef<'_>| $F_SUBDOC_IS_INTRO_ITEM_KEYWORD(kw)) |
              }}
                StopAt(false)
            ;
            // Is this a keyword for one of our parents or sub-documents?
            let inner_stop = outer_stop | is_subdoc_kw;

            //========== actual parsing ==========

            // For each parsing loop/section, where we aren't looking for precisely one thing,
            // we should explicitly decide what to do with each of:
            //   - F_INTRO - intro item for this document (maybe next instance in parent)
            //   - F_NORMAL - normal items
            //   - subdocuments, is_subdoc_kw and F_SUBDOC
            //   - F_SIGNATURE
            //   - our parent's structural keywords, outer_stop
            // 5 cases in all.

            // Note the body of the document (before the signatures)
          ${if T_SIGNATURES {
            let signed_doc_body = input.body_sofar_for_signature();
          }}

            //----- Parse the intro item, and introduce bindings for the other items. -----
            dtrace!("looking for intro item");

          $( ${select1 F_INTRO {

            let item = input.next_item()?.ok_or(EP::EmptyDocument)?;
            dtrace!("intro", item);
            if !Self::is_intro_item_keyword(item.keyword()) {
                Err(EP::WrongDocumentType)?;
            }
            let $fpatname: $ftype = $ITEM_VALUE_FROM_UNPARSED;

          } F_SKIP {

          } else {

            let mut $fpatname = $F_ACCUMULATE_TYPE::default();

          }})

            //----- Parse the normal items -----
            dtrace!("looking for normal items");

            while let Some(kw) = peek_keyword(input)? {
                dtrace!("for normal, peeked", kw);
                if inner_stop.stop_at(kw) {
                    dtrace!("is inner stop", kw);
                    break;
                };

                $NONSTRUCTURAL_ACCUMULATE_ELSE
                {
                    dtrace!("is unknown (in normal)");
                    let _: UnparsedItem = $THIS_ITEM;
                }
            }

            //----- Parse the subdocs, in order -----
            dtrace!("looking for subdocs");

          ${for fields {
            ${when F_SUBDOC}
            dtrace!("looking for subdoc", $F_KEYWORD_REPORT);

            loop {
                let Some(kw) = peek_keyword(input)? else { break };
                dtrace!("for subdoc, peek", kw);

                if !$F_SUBDOC_IS_INTRO_ITEM_KEYWORD(kw) {
                    dtrace!("is not this subdoc", kw);
                    break;
                };

                $F_SELECTOR.can_accumulate(&mut $fpatname)?;

                dtrace!("is this subdoc", kw);
                let item = NetdocParseable::from_items(input, inner_stop);
                dtrace!("parsed this subdoc", item.as_ref().map(|_| ()));
                let item = item?;

                $ACCUMULATE_ITEM_VALUE
            }
          }}

            // Resolve all the fields
            dtrace!("reached end, resolving");

            $FINISH_RESOLVE
        }
    }
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocFieldsDeriveCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsParseableCommon;

    /// Derive [`NetdocParseableFields`] for a struct with individual items
    ///
    /// Defines a struct `FooNetdocParseAccumulator` to be the
    /// `NetdocParseableFields::Accumulator`.
    ///
    /// Similar to
    /// [`#[derive_deftly(NetdocParseable)]`](derive_deftly_template_NetdocParseable),
    /// but:
    ///
    ///  * Derives [`NetdocParseableFields`]
    $DOC_NETDOC_FIELDS_DERIVE_SUPPORTED
    ///
    export NetdocParseableFields for struct , expect items, beta_deftly:

    ${define THIS_ITEM item}
    ${define F_ACCUMULATE_VAR { (&mut acc.$fname) }}

    #[doc = ${concat "Partially parsed `" $tname "`"}]
    ///
    /// Used for [`${concat $P::NetdocParseableFields::Accumulator}`].
    #[derive(Default, Debug)]
    $tvis struct $<$tname NetdocParseAccumulator><$tdefgens> { $(
        $fname: $F_ACCUMULATE_TYPE,
    ) }

    impl<$tgens> $P::NetdocParseableFields for $ttype {
        type Accumulator = $<$ttype NetdocParseAccumulator>;

        fn is_item_keyword(
            #[allow(unused_variables)] // If there are no fields, this is unused
            kw: $P::KeywordRef<'_>,
        ) -> bool {
            #[allow(unused_imports)] // false positives in some situations
            use $P::*;

          ${for fields {
            ${when not(F_FLATTEN)}
            kw == $F_KEYWORD ||
          }}
          ${for fields {
            ${when F_FLATTEN}
            <$ftype as NetdocParseableFields>::is_item_keyword(kw) ||
          }}
            false
        }

        #[allow(clippy::redundant_locals)] // let item = $THIS_ITEM, which might be item
        fn accumulate_item(
            #[allow(unused_variables)] // If there are no fields, this is unused
            acc: &mut Self::Accumulator,
            #[allow(unused_variables)] // If there are no fields, this is unused
            item: $P::UnparsedItem<'_>,
        ) -> $P::Result<(), $P::ErrorProblem> {
            #[allow(unused_imports)] // false positives in some situations
            use $P::*;
            $DEFINE_DTRACE

            $ITEM_SET_SELECTORS
            $CHECK_FIELD_TYPES_PARSEABLE

            #[allow(unused_variables)] // If there are no fields, this is unused
            let kw = item.keyword();

            $NONSTRUCTURAL_ACCUMULATE_ELSE
            {
                panic!("accumulate_item called though is_intro_item_keyword returns false");
            }

            #[allow(unreachable_code)] // If there are no fields!
            Ok(())
        }

        fn finish(
            #[allow(unused_variables)] // If there are no fields, this is unused
            acc: Self::Accumulator
        ) -> $P::Result<Self, $P::ErrorProblem> {
            #[allow(unused_imports)] // false positives in some situations
            use $P::*;
            $DEFINE_DTRACE

            dtrace!("finish, resolving");

            $ITEM_SET_SELECTORS

         $( let $fpatname = acc.$fname; )
            $FINISH_RESOLVE
        }
    }
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;

    /// Derive `FooSigned` from `Foo`
    ///
    /// Apply this derive to the main body struct `Foo`.
    ///
    /// Usually, provide suitable `.verify_...` methods.
    ///
    /// The body and signature types have to implement `Clone` and `Debug`.
    ///
    /// ### Top-level attributes:
    ///
    /// * **`#[deftly(netdoc(signature = "TYPE"))]`**:
    ///   Type of the signature(s) section.
    ///
    ///   TYPE must implement `NetdocParseable`,
    ///   with `is_intro_item_keyword` reporting *every* signature keyword.
    ///   Normally this is achieved with
    ///   `#[derive_deftly(NetdocParseable)] #[deftly(netdoc(signatures))]`.
    ///
    $DOC_DEBUG_PLACEHOLDER
    ///
    /// ### Generated struct
    ///
    /// ```
    /// # struct Foo; struct FooSignatures;
    /// pub struct FooSigned {
    ///     body: Foo,
    ///     pub signatures: FooSignatures,
    /// }
    ///
    /// # #[cfg(all())] { r##"
    /// impl NetdocParseable for FooSigned { .. }
    /// impl NetdocSigned for FooSigned { .. }
    /// # "##; }
    /// ```
    //
    // We don't make this a generic struct because the defining module (crate)
    // will want to add verification methods, which means they must define the struct.
    export NetdocSigned for struct, expect items, beta_deftly:

    // Convenience alias for our prelude
    ${define P { $crate::parse2::internal_prelude }}

    // FooSignatures (type name)
    ${define SIGS_TYPE { $< ${tmeta(netdoc(signatures)) as ty, default $<$ttype Signatures>} > }}

    #[doc = ${concat "Signed (unverified) form of [`" $tname "`]"}]
    ///
    /// Embodies:
    ///
    #[doc = ${concat "  * **[`" $tname "`]**: document body"}]
    #[doc = ${concat "  * **[`" $SIGS_TYPE "`]**: signatures"}]
    ///
    /// If this type was parsed from a document text,
    /// the signatures have *not* yet been verified.
    ///
    /// Use a `.verify_...` method to obtain useable, verified, contents.
    #[derive(Debug, Clone)]
    $tvis struct $<$ttype Signed> {
        /// The actual body
        //
        // Misuse is prevented by this field not being public.
        // It can be accessed only in this module, where the verification functions are.
        body: $ttype,

        /// Signatures
        $tvis signatures: $SIGS_TYPE,
    }

    impl<$tgens> $P::NetdocParseable for $<$ttype Signed> {
        fn doctype_for_error() -> &'static str {
            $ttype::doctype_for_error()
        }

        fn is_intro_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
            $ttype::is_intro_item_keyword(kw)
        }

        fn is_structural_keyword(kw: $P::KeywordRef<'_>) -> Option<$P::IsStructural> {
            $ttype::is_structural_keyword(kw)
                .or_else(|| $SIGS_TYPE::is_structural_keyword(kw))
        }

        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            outer_stop: $P::stop_at!(),
        ) -> $P::Result<$<$ttype Signed>, $P::ErrorProblem> {
            $EMIT_DEBUG_PLACEHOLDER
            input.parse_signed(outer_stop)
        }
    }

    impl<$tgens> $P::NetdocSigned for $<$ttype Signed> {
        type Body = $ttype;
        type Signatures = $SIGS_TYPE;
        fn inspect_unverified(&self) -> (&Self::Body, &Self::Signatures) {
            (&self.body, &self.signatures)
        }
        fn unwrap_unverified(self) -> (Self::Body, Self::Signatures) {
            (self.body, self.signatures)
        }
        fn from_parts(body: Self::Body, signatures: Self::Signatures) -> Self {
            Self { body, signatures }
        }
    }
}

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocItemDeriveCommon;

    /// Derive `ItemValueParseable`
    ///
    // NB there is very similar wording in the ItemValueEncodable derive docs.
    // If editing any of this derive's documentation, considering editing that too.
    //
    /// Fields in the struct are parsed from the keyword line arguments,
    /// in the order they appear in the struct.
    ///
    /// ### Field type
    ///
    /// Each field should be:
    ///
    ///  * `impl `[`ItemArgumentParseable`] (one argument),
    ///  * `Option<impl ItemArgumentParseable>` (one optional argument),
    ///  * `Vec<impl ItemArgumentParseable>` (zero or more arguments), or
    ///  * `BTreeSet<impl ItemArgumentParseable + Ord>` (zero or more arguments).
    ///
    /// `ItemArgumentParseable` can be implemented via `impl FromStr`,
    /// by writing `impl NormalItemArgument`.
    ///
    /// For `Option` or `Vec`, we expect that *if* there are any further arguments,
    /// they are for this field.
    /// So absence of any optional argument means absence of following arguments,
    /// and no arguments can follow a `Vec`.
    ///
    /// Some Tor netdocs have optional arguments followed by other data,
    /// with unclear/ambiguous parsing rules.
    /// These cases typically require manual implementation of [`ItemValueParseable`].
    ///
    /// (Multiplicity is implemented via types in the [`multiplicity`] module,
    /// specifically [`ArgumentSetSelector`] and [`ArgumentSetMethods`].)
    ///
    /// ### Top-level attributes:
    ///
    ///  * **`#[deftly(netdoc(no_extra_args))]**:
    ///
    ///    Reject, rather than ignore, additional arguments found in the document
    ///    which aren't described by the struct.
    ///
    /// * **`#[deftly(netdoc(debug))]`**:
    ///
    ///   Currently implemented only as a placeholde
    ///
    ///   The generated implementation may in future generate copious debug output
    ///   to the program's stderr when it is run.
    ///   Do not enable in production!
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
    ///    The field type must implement `FromStr`.
    ///    (I.e. `Vec` , `Option` etc., are not allowed, and `ItemArgumentParseable` is not used.)
    ///
    ///  * **`#[deftly(netdoc(object))]**:
    ///
    ///    The field is the Object.
    ///    It must implement [`ItemObjectParseable`]
    ///    (or be `Option<impl ItemObjectParseable>`).
    ///
    ///    Only allowed once.
    ///    If omittted, any object is rejected.
    ///
    ///  * **`#[deftly(netdoc(object(label = "LABEL")))]**:
    ///
    ///    Sets the expected label for an Object.
    ///    If not supplied, uses [`ItemObjectParseable::check_label`].
    ///
    ///  * **`#[deftly(netdoc(with = "MODULE")]**:
    ///
    ///    Instead of `ItemArgumentParseable`, the argument is parsed with `MODULE::from_args`,
    ///    which must have the same signature as [`ItemArgumentParseable::from_args`].
    ///
    ///    With `#[deftly(netdoc(rest))]`, the argument is parsed with `MODULE::from_args_rest`,
    ///    must have the signature
    ///    `fn from_args_rest(s: &str) -> Result<FIELD, _>`).
    ///    and replaces `<FIELD as FromStr>::from_str`.
    ///
    ///    With `#[deftly(netdoc(object))]`, uses `MODULE::try_from`
    ///    which must have the signature `fn(Vec<u8>) -> Result<OBJECT, _>;
    ///    like `TryFrom::<Vec<u8>>>::try_from`.
    ///    LABEL must also be specified
    ///    unless the object also implements `ItemObjectParseable`.
    ///    Errors from parsing will all be collapsed into
    ///    [`ErrorProblem::ObjectInvalidData`].
    ///
    ///  * **`#[deftly(netdoc(sig_hash = "HASH_METHOD"))]**:
    ///
    ///    This item is a signature item.
    ///    [`SignatureItemParseable`] will be implemented instead of [`ItemValueParseable`].
    ///
    ///    This field is a document hash.
    ///    The hash will be computed using `HASH_METHOD`,
    ///    which will be resolved with `sig_hash_methods::*` in scope.
    ///
    ///    `fn HASH_METHOD(body: &SignatureHashInputs) -> HASH_FIELD_VALUE`.
    export ItemValueParseable for struct, expect items, beta_deftly:

    ${define P { $crate::parse2::internal_prelude }}

    ${define TRAIT ${if T_IS_SIGNATURE { SignatureItemParseable } else { ItemValueParseable }}}
    ${define METHOD ${if T_IS_SIGNATURE { from_unparsed_and_body } else { from_unparsed }}}

    impl<$tgens> $P::$TRAIT for $ttype {
        fn $METHOD<'s>(
            mut input: $P::UnparsedItem<'s>,
          ${if T_IS_SIGNATURE {
            document_body: &SignatureHashInputs<'_>,
          }}
        ) -> $P::Result<Self, $P::EP>
        {
            #[allow(unused_imports)] // false positive when macro is used with prelude in scope
            use $P::*;

            $EMIT_DEBUG_PLACEHOLDER

            let object = input.object();
            #[allow(unused)]
            let mut args = input.args_mut();
          $(
            let $fpatname = ${select1
              F_NORMAL { {
                  let selector = MultiplicitySelector::<$ftype>::default();
                ${if not(fmeta(netdoc(with))) {
                  selector.${paste_spanned $fname check_argument_value_parseable}();
                }}
                  selector.parse_with(
                      &mut args,
                      ${fmeta(netdoc(with))
                        as path,
                        default { ItemArgumentParseable }}::${paste_spanned $fname from_args},
                  ).map_err(args.error_handler(stringify!($fname)))?
              } }
              F_OBJECT { {
                  let selector = MultiplicitySelector::<$ftype>::default();
                  let object = object.map(|object| {
                      let data = object.decode_data()?;
                      ${if fmeta(netdoc(object(label))) {
                          if object.label() != ${fmeta(netdoc(object(label))) as str} {
                              return Err(EP::ObjectIncorrectLabel)
                          }
                      } else {
                          selector.check_label(object.label())?;
                      }}
                      ${if fmeta(netdoc(with)) {
                          ${fmeta(netdoc(with)) as path}::${paste_spanned $fname try_from}
                              (data)
                              .map_err(|_| EP::ObjectInvalidData)
                      } else {
                          selector.${paste_spanned $fname check_object_parseable}();
                          ItemObjectParseable::from_bytes(&data)
                      }}
                  }).transpose()?;
                  selector.resolve_option(object)?
              } }
              F_REST { {
                  // consumes `args`, leading to compile error if the rest field
                  // isn't last (or is combined with no_extra_args).
                  let args_consume = args;
                  ${if fmeta(netdoc(with)) {
                      ${fmeta(netdoc(with)) as path}::${paste_spanned $fname from_args_rest}
                  } else {
                      <$ftype as FromStr>::from_str
                  }}
                      (args_consume.into_remaining())
                      .map_err(|_| AE::Invalid)
                      .map_err(args_consume.error_handler(stringify!($fname)))?
              } }
              F_SIG_HASH { {
                  #[allow(unused_imports)]
                  use $P::sig_hash_methods::*;
                  ${fmeta(netdoc(sig_hash)) as path}(&document_body)
              } }
            };
          )
          ${if approx_equal({}, $( ${when F_OBJECT} $fname )) {
            if object.is_some() {
                return Err(EP::ObjectUnexpected);
            }
          }}
          ${if tmeta(netdoc(no_extra_args)) {
            args.reject_extra_args()?;
          }}
            Ok($tname { $( $fname: $fpatname, ) })
        }
    }
}
