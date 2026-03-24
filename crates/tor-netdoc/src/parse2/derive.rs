//! Deriving `NetdocParseable`

use super::*;

//==================== Common definitions used by many of the macros ====================

/// Helper to implemnet `dtrace!` inside `NetdocParseable` derive-deftly macro.
#[doc(hidden)]
#[allow(clippy::print_stderr)]
pub fn netdoc_parseable_derive_debug(ttype: &str, msg: &str, vals: &[&dyn Debug]) {
    // We use `eprintln!` so that the output is captured as expected under cargo test.
    // We buffer the output into a string so that it a;ll appears at once,
    // rather than possibly being interleaved with similar output for other types.
    let mut out = String::new();
    (|| {
        write!(out, "netdoc {ttype} parse: {msg}")?;
        for val in vals {
            write!(out, ", {val:?}")?;
        }
        writeln!(out)
    })()
    .expect("write to string failed");

    eprint!("{out}");
}

define_derive_deftly_module! {
    /// Common definitions for `NetdocParseable`, `NetdocParseableFields`,
    /// and `NetdocParseableSignatures`
    ///
    /// The including macro is expected to define:
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
          }} (
              ${if F_SIGNATURE { sig_hashes, }}
          );
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

    // Parse the intro item and bind `$fpatname` accumulator for each field.
    //
    // For the intro item, parse it and bind it to $fpatname.
    //
    // For other items, set up a mutable $fpatname, initialised to `default()` (normally None).
    ${define INIT_ACCUMULATE_VARS {
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
    }}

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
                let item = SignatureItemParseable::from_unparsed_and_body(
                    item,
                    &hash_inputs,
                    AsMut::as_mut(sig_hashes),
                )?;
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

//==================== Main whole document parsing impl ====================
//
// deftly module ` NetdocParseable`:
//
//   * IMPL_NETDOC_PARSEABLE expanding to `impl NetdocParseable { ... }`
//
// Much of the heavy lifting is done in the NetdocSomeItemsParseableCommon deftly module.

define_derive_deftly_module! {
    /// Provides `IMPL_NETDOC_PARSEABLE` which impls `NetdocParseable`
    ///
    /// Used by the `NetdocParseable` and `NetdocParseableUnverified` derives.
    NetdocParseable beta_deftly:

    use NetdocDeriveAnyCommon;
    use NetdocEntireDeriveCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsParseableCommon;

    ${define F_ACCUMULATE_VAR { (&mut $fpatname) }}

  ${define IMPL_NETDOC_PARSEABLE {
    impl<$tgens> $P::NetdocParseable for $NETDOC_PARSEABLE_TTYPE {
        fn doctype_for_error() -> &'static str {
            ${tmeta(netdoc(doctype_for_error)) as expr,
              default ${concat ${for fields { ${when F_INTRO} $F_KEYWORD_STR }}}}
        }

        fn is_intro_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
            use $P::*;

            ${for fields {
                ${when F_INTRO}
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
        ) -> $P::Result<Self, $P::ErrorProblem> {
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
            //   - our parent's structural keywords, outer_stop
            //     (this includes signature items for the signed version of this doc)
            // 5 cases in all.

            //----- Parse the intro item, and introduce bindings for the other items. -----

            dtrace!("looking for intro item");
            $INIT_ACCUMULATE_VARS

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

            $FINISH_RESOLVE_PARSEABLE
        }
    }
  }}
}

//==================== NetdocParseable user-facing derive macro ====================
//
// deftly template `NetdocParseable`:
//
//  * main entrypoint for deriving the `NetdocParseable` trait
//  * docs for the meta attributes we support during document parsing
//
// The actual implementation is in  the `NetdocParseable` deftly module, above.

define_derive_deftly! {
    use NetdocParseable;

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
    ///    Derive [`NetdocParseableUnverified`](derive_deftly_template_NetdocUnverified).
    ///  * `FooSignatures`, containing only the signatures.
    ///    Derive `NetdocParseableSignatures`.
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
    ///   The value type `T` must implement [`NetdocParseable`]
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
    /// use tor_netdoc::derive_deftly_template_AsMutSelf;
    /// use tor_netdoc::derive_deftly_template_NetdocParseableSignatures;
    /// use tor_netdoc::derive_deftly_template_NetdocParseableUnverified;
    /// use tor_netdoc::derive_deftly_template_ItemValueParseable;
    /// use tor_netdoc::parse2::{
    ///     parse_netdoc, ErrorProblem, ParseInput, VerifyFailed,
    ///     SignatureItemParseable, SignatureHashesAccumulator, SignatureHashInputs,
    /// };
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(NetdocParseableUnverified)]
    /// pub struct NdThing {
    ///     pub thing_start: (),
    ///     pub value: (String,),
    /// }
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(NetdocParseableSignatures)]
    /// #[deftly(netdoc(signatures(hashes_accu = "UseLengthAsFoolishHash")))]
    /// pub struct NdThingSignatures {
    ///     pub signature: FoolishSignature,
    /// }
    ///
    /// #[derive(Deftly, Debug, Clone)]
    /// #[derive_deftly(ItemValueParseable)]
    /// #[deftly(netdoc(signature(hash_accu = "UseLengthAsFoolishHash")))]
    /// pub struct FoolishSignature {
    ///     pub doc_len: usize,
    /// }
    ///
    /// #[derive(Deftly, Debug, Default, Clone)]
    /// #[derive_deftly(AsMutSelf)]
    /// pub struct UseLengthAsFoolishHash {
    ///     pub doc_len_actual_pretending_to_be_hash: Option<usize>,
    /// }
    /// impl SignatureHashesAccumulator for UseLengthAsFoolishHash {
    ///     fn update_from_netdoc_body(
    ///         &mut self,
    ///         document_body: &SignatureHashInputs<'_>,
    ///     ) -> Result<(), ErrorProblem> {
    ///         self
    ///             .doc_len_actual_pretending_to_be_hash
    ///             .get_or_insert_with(|| document_body.body().body().len());
    ///         Ok(())
    ///     }
    /// }
    ///
    /// let doc_text =
    /// r#"thing-start
    /// value something
    /// signature 28
    /// "#;
    ///
    /// impl NdThingUnverified {
    ///     pub fn verify_foolish_timeless(self) -> Result<NdThing, VerifyFailed> {
    ///         let sig = &self.sigs.sigs.signature;
    ///         let hash = self.sigs.hashes.doc_len_actual_pretending_to_be_hash
    ///             .as_ref().ok_or(VerifyFailed::Bug)?;
    ///         if sig.doc_len != *hash {
    ///             return Err(VerifyFailed::VerifyFailed);
    ///         }
    ///         Ok(self.body)
    ///     }
    /// }
    ///
    /// let input = ParseInput::new(&doc_text, "<input>");
    /// let doc: NdThingUnverified = parse_netdoc(&input).unwrap();
    /// let doc = doc.verify_foolish_timeless().unwrap();
    /// assert_eq!(doc.value.0, "something");
    /// ```
    export NetdocParseable for struct, expect items, beta_deftly:

    ${define NETDOC_PARSEABLE_TTYPE { $ttype }}
    ${define FINISH_RESOLVE_PARSEABLE $FINISH_RESOLVE}

    $IMPL_NETDOC_PARSEABLE
}

//==================== NetdocParseableSignatures user-facing derive macro ====================
//
// deftly template `NetdocParseableSignatures`:
//
//  * entrypoint for deriving the `NetdocParseableSignatures` trait
//  * docs for the signatures-section-specific attributes
//  * implementation of that derive
//
// Much of the heavy lifting is done in the NetdocSomeItemsParseableCommon deftly module.

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocSomeItemsDeriveCommon;
    use NetdocSomeItemsParseableCommon;

    /// Derive [`NetdocParseable`] for the signatures section of a network document
    ///
    /// This type is the signatures section of another document.
    /// Signature sections have no separate intro keyword:
    /// every field is structural and they are recognised in any order.
    ///
    /// This signatures sub-document will typically be included in a
    /// `FooUnverified` struct derived with
    /// [`NetdocUnverified`](derive_deftly_template_NetdocUnverified),
    /// rather than included anywhere manually.
    ///
    /// ### Expected input structure
    ///
    /// Should be applied named-field struct, where each field
    /// implements [`SignatureItemParseable`],
    /// or is a `SignatureItemParseable` in `Vec` or `BTreeSet` or `Option`.
    ///
    /// ### Attributes
    ///
    ///  * The following top-level attributes are supported:
    ///    `#[deftly(netdoc(debug))]`
    ///
    ///  * The following field-level attributes are supported:
    ///    `#[deftly(netdoc(keyword = STR))]`
    ///    `#[deftly(netdoc(default))]`
    ///    `#[deftly(netdoc(single_arg))]`
    ///    `#[deftly(netdoc(with = "MODULE"))]`
    ///    `#[deftly(netdoc(flatten))]`
    ///    `#[deftly(netdoc(skip))]`
    ///
    /// ### Signature item ordering, and signatures covering signatures
    ///
    /// The derived code does not impose any mutual ordering of signatures.
    /// If signatures are independent, hashing can be done with [`SignedDocumentBody`]
    /// (from [`SignatureHashInputs::body`]).
    ///
    /// In sane netdoc signature scheme, no signatures would cover other signatures,
    /// and there would be no ordering requirement on signatures on the same document.
    ///  A relying party would verify the signatures that they are proposing to rely on
    /// (which would generally include signatures for *one* algorithm, not several)
    /// and ignore the others.
    ///
    /// (Such a signature, which also does not include any of its own item encoding
    /// in its hash, is called Orderly.  See [SignedDocumentBody].)
    ///
    /// Unfortunately, many Tor netdocs have signature schemes
    /// which are not sane (by this definition).
    ///
    /// When signatures are specified to cover other signatures,
    /// the signature item implementation must contain ad-hoc code in
    /// [`SignatureItemParseable::from_unparsed_and_body`].
    /// to hash not only the body, but also the prior signatures.
    /// Methods on [`SignatureHashInputs`] are available to get
    /// the relevant parts of the input document text
    /// (eg, [`document_sofar`](SignatureHashInputs::document_sofar)).
    ///
    /// When the spec states a required ordering on signature items,
    /// this should be enforced by ad-hoc code in implementation(s) of
    /// `SignatureItemParseable`.
    /// The implementation should use
    /// [`HashAccu`](SignatureItemParseable::HashAccu)
    /// to store any necessary state.
    /// Usually, this can be achieved by using the same Rust struct for the
    /// `HashAccu` of each of the signature items:
    /// that will make the signature hashes computed so far, for items seen so far,
    /// visible to subsequent items;
    /// the subsequent items can check that the prior items filled in the hash,
    /// thus imposing an ordering.
    ///
    /// Alternatively, the ordering could be enforced in the user-supplied
    /// ad-hoc `verify` function(s) on `FooUUnverified`.
    ///
    /// Note that this enforcement should be done for protocol compliance
    /// and availability reasons, but is not a security issue.
    /// There is not a security risk from accepting documents some of whose signatures
    /// aren't covered by other signatures even though the protocol specifies they should be:
    /// relying parties *verify* the signatures but do not treat them as trusted data.
    /// So there is no engineered safeguard against failing to implement
    /// signature item ordering checks.
    export NetdocParseableSignatures for struct, expect items, beta_deftly:

    ${defcond F_INTRO false}
    ${defcond F_SUBDOC false}
    ${defcond F_SIGNATURE true}

    // NetdocParseableSignatures::HashesAccu
    ${define SIGS_HASHES_ACCU_TYPE { ${tmeta(netdoc(signatures(hashes_accu))) as ty} }}

    ${define THIS_ITEM { input.next_item()?.expect("peeked") }}
    ${define F_ACCUMULATE_VAR { (&mut $fpatname) }}

    impl<$tgens> $P::NetdocParseableSignatures for $ttype {
        type HashesAccu = $SIGS_HASHES_ACCU_TYPE;

        fn is_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
            use $P::*;
            ${for fields {
                kw == $F_KEYWORD ||
            }}
                false
        }

        #[allow(clippy::redundant_locals)] // let item = $THIS_ITEM, which might be item
        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            signed_doc_body: $P::SignedDocumentBody<'s>,
            sig_hashes: &mut $SIGS_HASHES_ACCU_TYPE,
            outer_stop: $P::stop_at!(),
        ) -> $P::Result<$ttype, $P::ErrorProblem> {
            use $P::*;
            $DEFINE_DTRACE

            //----- prepare item set selectors for every field -----
            $ITEM_SET_SELECTORS
            $CHECK_FIELD_TYPES_PARSEABLE
            $INIT_ACCUMULATE_VARS

            //----- parse the items -----
            dtrace!("looking for signature items");

            while let Some(kw) = input.peek_keyword()? {
                dtrace!("for signatures, peeked", kw);
                if outer_stop.stop_at(kw) {
                    dtrace!("is outer stop", kw);
                    break;
                };

                $NONSTRUCTURAL_ACCUMULATE_ELSE
                {
                    dtrace!("is unknown (in signatures)");
                    let _: UnparsedItem = $THIS_ITEM;
                }
            }

            // Resolve all the fields
            dtrace!("reached end, resolving");

            $FINISH_RESOLVE
        }
    }
}

//==================== NetdocParseableFields user-facing derive macro ====================
//
// deftly template `NetdocParseableFields`
//
//  * entrypoint for deriving the `NetdocParseableFields` trait
//  * docs and implementation for that derive
//
// Much of the heavy lifting is done in the NetdocSomeItemsParseableCommon deftly module.

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
                panic!("accumulate_item called though is_item_keyword returns false");
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

//==================== NetdocParseableUnverified user-facing derive macro ====================
//
// deftly template `NetdocParseableUnverified`
//
//  * entrypoint for deriving the `FooUnverified` struct implementing `NetdocParseable`
//    (and supporting items such as `FooUnverifiedParsedBody` structs and its impl).
//  * docs for that derive, including doc-level signatures-related attributes
//  * implementation glue for those derived impls
//
// The principal derived parsing impl on the body type `Foo` is expanded by this macro,
// but that is implemented via IMPL_NETDOC_PARSEABLE in the NetdocParseable deftly module.
//
// The substantive code to implement `NetdocParseable` for `FooUnverified` is
// in the `ItemStream::parse_signed` helper function; a call to that is expanded here.

define_derive_deftly! {
    use NetdocParseable;

    /// Derive `NetdocParseable` for a top-level signed document
    ///
    /// ### Expected input structure
    ///
    /// Apply this derive to the main body struct `Foo`,
    /// which should meet all the requirements to derive
    /// [`NetdocParseable`](derive_deftly_template_NetdocParseable).
    ///
    /// Usually, the caller will provide suitable ad-hoc `.verify_...` methods
    /// on `FooUnverified`.
    ///
    /// ### Generated code
    ///
    /// Supposing your input structure is `Foo`, this macro will
    /// generate a `**struct FooUnverified`**
    /// implementing [`NetdocParseable`] and [`NetdocUnverified`]:
    ///
    /// ```rust,ignore
    /// # struct Foo; struct FooSignatures;
    /// pub struct FooUnverified {
    ///     body: Foo,
    ///     pub sigs: SignaturesData<FooUnverified>,
    /// }
    /// ```
    ///
    /// Also generated is `FooUnverifiedParsedBody`
    /// and an impl of [`HasUnverifiedParsedBody`] on `Foo`.
    /// These allow the generated code to call [`ItemStream::parse_signed`]
    /// and it should not normally be necessary to use them elsewhere.
    ///
    /// ### Required top-level attributes:
    ///
    /// * **`#[deftly(netdoc(signature = "TYPE"))]`**:
    ///   Type of the signature(s) section.
    ///
    ///   TYPE must implement `NetdocParseable`,
    ///   with `is_intro_item_keyword` reporting *every* signature keyword.
    ///   Normally this is achieved with
    ///   `#[derive_deftly(NetdocParseable)] #[deftly(netdoc(signatures))]`.
    ///
    /// ### Optional attributes
    ///
    /// All the attributes supported by the `NetdocParseable` derive are supported.
    //
    // We don't make NetdocUnverified a generic struct because
    //  - the defining module (crate) will want to add verification methods,
    //    which means they must define the struct
    //  - that lets the actual `body` field be private to the defining module.
    export NetdocParseableUnverified for struct, expect items, beta_deftly:

    ${define NETDOC_PARSEABLE_TTYPE { $<$ttype UnverifiedParsedBody> }}
    ${define FINISH_RESOLVE_PARSEABLE {
        { $FINISH_RESOLVE }
        .map(|unverified| $<$tname UnverifiedParsedBody> { unverified })
    }}

    $IMPL_NETDOC_PARSEABLE

    // FooSignatures (type name)
    ${define SIGS_TYPE { $< ${tmeta(netdoc(signatures)) as ty, default $<$ttype Signatures>} > }}
    ${define SIGS_DATA_TYPE { $P::SignaturesData<$<$ttype Unverified>> }}
    ${define SIGS_HASHES_ACCU_TYPE { <$SIGS_TYPE as $P::NetdocParseableSignatures>::HashesAccu }}

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
    $tvis struct $<$ttype Unverified> {
        /// The actual body
        //
        // Misuse is prevented by this field not being public.
        // It can be accessed only in this module, where the verification functions are.
        body: $ttype,

        /// Signatures
        $tvis sigs: $SIGS_DATA_TYPE,
    }

    /// The parsed but unverified body part of a signed network document (working type)
    ///
    #[doc = ${concat "Contains a " $tname " which has been parsed"}]
    /// as part of a signed document,
    /// but the signatures aren't embodied here, and have not been verified.
    ///
    /// Not very useful to callers, who should use the `BodyUnverified` type instead,
    /// and its implementation of `NetdocParseable`.
    //
    // We implement NetdocParseable on FooUnverified using ItemStream::parse_signed.
    // ItemStream::parse_signed is a fairly normal but ad-hoc
    // implementation of NetdocParseable which uses as subroutines implementations
    // of NetdocParseable for the body and NetdocParseableSignatures for the signatures.
    //
    // We need a newtype because we don't want to implement `NetdocParseable`
    // for a type which is just the body.  Such an impl would be usable by mistake,
    // via the top-level parse2 functions, and it would then simply discard the signatures
    // and return unverified data, bypassing our efforts to prevent such bugs.
    //
    // Ideally we would have a generic `UnverifiedParsedBody<B>` type or something
    // but then this macro, invoked in other crates, couldn't impl NetdocParseable for
    // UnverifiedParsedBody<TheirType>, due to trait coherence rules.
    //
    #[derive(derive_more::From)]
    pub struct $NETDOC_PARSEABLE_TTYPE<$tdefgens> {
        /// The unverified body
        unverified: $ttype,
    }

    impl<$tgens> $P::NetdocParseable for $<$ttype Unverified> {
        fn doctype_for_error() -> &'static str {
            $NETDOC_PARSEABLE_TTYPE::doctype_for_error()
        }

        fn is_intro_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
            $NETDOC_PARSEABLE_TTYPE::is_intro_item_keyword(kw)
        }

        fn is_structural_keyword(kw: $P::KeywordRef<'_>) -> Option<$P::IsStructural> {
            $NETDOC_PARSEABLE_TTYPE::is_structural_keyword(kw)
                .or_else(|| <$SIGS_TYPE as $P::NetdocParseableSignatures>::is_item_keyword(kw).then_some($P::IsStructural))
        }

        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            outer_stop: $P::stop_at!(),
        ) -> $P::Result<$<$ttype Unverified>, $P::ErrorProblem> {
            $EMIT_DEBUG_PLACEHOLDER
            input.parse_signed(outer_stop)
        }
    }

    impl<$tgens> $P::NetdocUnverified for $<$ttype Unverified> {
        type Body = $ttype;
        type Signatures = $SIGS_TYPE;
        fn inspect_unverified(&self) -> (&Self::Body, &$SIGS_DATA_TYPE) {
            (&self.body, &self.sigs)
        }
        fn unwrap_unverified(self) -> (Self::Body, $SIGS_DATA_TYPE) {
            (self.body, self.sigs)
        }
        fn from_parts(body: Self::Body, sigs: $SIGS_DATA_TYPE) -> Self {
            Self { body, sigs }
        }
    }

    impl<$tgens> $P::HasUnverifiedParsedBody for $ttype {
        type UnverifiedParsedBody = $NETDOC_PARSEABLE_TTYPE;
        fn unverified_into_inner_unchecked(unverified: Self::UnverifiedParsedBody) -> Self {
            unverified.unverified
        }
    }
}

//==================== ItemValueParseable user-facing derive macro ====================
//
// deftly template `ItemValueParseable`
//
//  * entrypoint for deriving the `ItemValueParseable` and `SignatureItemParseable` traits
//  * docs for the meta attributes we support during *item* parsing
//  * implementation of those derives

define_derive_deftly! {
    use NetdocDeriveAnyCommon;
    use NetdocItemDeriveCommon;

    /// Derive `ItemValueParseable` (or `SignatureItemParseable`)
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
    ///  * **`#[deftly(netdoc(signature(hash_accu = "HASH_ACCU"))]**:
    ///
    ///    This item is a signature item.
    ///    [`SignatureItemParseable`] will be implemented instead of [`ItemValueParseable`].
    ///
    ///    **`HASH_ACCU`** is the type in which the hash(es) for this item will be accumulated,
    ///    and must implement [`SignatureHashesAccumulator`].
    ///    It is used as [`SignatureItemParseable::HashAccu`].
    ///
    /// * **`#[deftly(netdoc(debug))]`**:
    ///
    ///   Currently implemented only as a placeholder
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
    export ItemValueParseable for struct, expect items, beta_deftly:

    ${define P { $crate::parse2::internal_prelude }}

    ${define TRAIT ${if T_IS_SIGNATURE { SignatureItemParseable } else { ItemValueParseable }}}
    ${define METHOD ${if T_IS_SIGNATURE { from_unparsed_and_body } else { from_unparsed }}}

    // SignatureItemParseable::HashAccu
    ${define SIG_HASH_ACCU_TYPE ${tmeta(netdoc(signature(hash_accu))) as ty}}

    impl<$tgens> $P::$TRAIT for $ttype {
      ${if T_IS_SIGNATURE {
        type HashAccu = $SIG_HASH_ACCU_TYPE;
      }}

        fn $METHOD<'s>(
            mut input: $P::UnparsedItem<'s>,
          ${if T_IS_SIGNATURE {
            document_body: &SignatureHashInputs<'_>,
            hash_accu: &mut $SIG_HASH_ACCU_TYPE,
          }}
        ) -> $P::Result<Self, $P::EP>
        {
            #[allow(unused_imports)] // false positive when macro is used with prelude in scope
            use $P::*;

            $EMIT_DEBUG_PLACEHOLDER

            ${if T_IS_SIGNATURE {
                <$SIG_HASH_ACCU_TYPE as SignatureHashesAccumulator>::update_from_netdoc_body(
                    hash_accu,
                    document_body
                )?;
            }}

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
