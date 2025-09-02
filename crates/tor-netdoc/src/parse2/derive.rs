//! Deriving `NetdocParseable`

use super::*;

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

/// Helper to implemnet `dtrace!` inside `NetdocParseable` derive-deftly macro.
#[doc(hidden)]
pub fn netdoc_parseable_derive_debug(ttype: &str, msg: &str, vals: &[&dyn Debug]) {
    let mut out = std::io::stderr().lock();
    (|| {
        write!(out, "netdoc {ttype} parse: {msg}")?;
        for val in vals {
            write!(out, ", {val:?}")?;
        }
        writeln!(out)
    })()
    .expect("write to String failed");
}

define_derive_deftly! {
    /// Derive [`NetdocParseable`] for a document (or sub-document)
    ///
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
    /// use tor_netdoc::parse2::{parse_netdoc, VerifyFailed};
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
    /// let doc: NdThingSigned = parse_netdoc(&doc_text, "<input>").unwrap();
    /// let doc = doc.verify_foolish_timeless().unwrap();
    /// assert_eq!(doc.value.0, "something");
    /// ```
    export NetdocParseable for struct, expect items, beta_deftly:

    // Convenience alias for our prelude
    ${define P { $crate::parse2::internal_prelude }}

    // Predicate for the toplevel
    ${defcond T_SIGNATURES tmeta(netdoc(signatures))}

    // Predicates for the field kinds
    ${defcond F_INTRO all(not(T_SIGNATURES), approx_equal($findex, 0))}
    ${defcond F_FLATTEN fmeta(netdoc(flatten))}
    ${defcond F_SUBDOC fmeta(netdoc(subdoc))}
    ${defcond F_SIGNATURE T_SIGNATURES} // signatures section documents have only signature fields
    ${defcond F_NORMAL not(any(F_SIGNATURE, F_INTRO, F_FLATTEN, F_SUBDOC))}

    // Field keyword as `&str`
    ${define F_KEYWORD_STR { ${concat
        ${if any(F_FLATTEN, F_SUBDOC) {
            // Sub-documents and flattened fields have their keywords inside;
            // if we ask for the field-based keyword name for one of those then that's a bug.
            ${error "internal error, subdoc KeywordRef"}
        }}
        ${fmeta(netdoc(keyword)) as str,
          default ${concat ${kebab_case $fname}}}
    }}}
    // Field keyword as `&str` for debugging and error reporting
    ${define F_KEYWORD_REPORT {
        ${if F_SUBDOC { ${concat $fname} }
             else { $F_KEYWORD_STR }}
    }}
    // Field keyword as `KeywordRef`
    ${define F_KEYWORD { (KeywordRef::new_const($F_KEYWORD_STR)) }}

    // The effective field type for parsing.
    //
    // Handles #[deftly(netdoc(default))], in which case we parse as if the field was Option,
    // and substitute in the default at the end.
    ${define F_EFFECTIVE_TYPE {
        ${if all(fmeta(netdoc(default)), not(F_INTRO)) {
            Option::<$ftype>
        } else {
            $ftype
        }}
    }}

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

        //##### main parsing function #####

        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            outer_stop: $P::stop_at!(),
        ) -> Result<$ttype, $P::ErrorProblem> {
            use $P::*;

            //----- compile-time check that fields are in the right order in the struct -----

            ${if not(T_SIGNATURES) { // signatures structs have only signature fields
              netdoc_ordering_check! {
                $(
                    ${select1
                      F_INTRO     { intro     }
                      F_NORMAL    { normal    }
                      F_FLATTEN   { normal    }
                      F_SUBDOC    { subdoc    }
                    }
                    $fname
                )
              }
            }}

            //----- Debugging -----

            macro_rules! dtrace { { $$msg:literal $$(, $$val:expr )* $$(,)? } => {
              ${if tmeta(netdoc(debug)) {
                  netdoc_parseable_derive_debug(
                      ${concat $ttype},
                      $$msg,
                      &[ $$( &&$$val as _, )* ],
                  )
              }}
            }}

            //----- prepare item set selectors for every field -----

          $(
            ${when not(any(F_INTRO, F_FLATTEN))}

            // See `mod multiplicity`.
            let $<selector_ $fname> = ItemSetSelector::<$F_EFFECTIVE_TYPE>::default();

            // Expands to `selector_FIELD.check_SOMETHING();`
            //
            // If the relevant trait isn't implemented, rustc reports the error by
            // pointing at the `check-something` call.  We re-span that identifier
            // to point to the field name, so that's where the error is reported.
            //
            // Without this, we just get a report that `item` doesn't implement the required
            // trait - but `item` is a local variable here, so the error points into the macro
            $<selector_ $fname> . ${paste_spanned $fname ${select1
                    F_NORMAL    { check_item_value_parseable     }
                    F_SIGNATURE { check_signature_item_parseable }
                    F_SUBDOC    { check_subdoc_parseable         }
            }} ();
          )

            // Is this an intro item keyword ?
            //
            // Expands to an appropriate `is_intro_item_keyword` method invocation,
            // but *without arguments*.  So, something a bit like an expression of type
            //    fn(KeywordRef) -> bool
            ${define F_SUBDOC_IS_INTRO_ITEM_KEYWORD {
                ${if not(F_SUBDOC) { ${error "internal-error: subdoc kw, but not subdoc field"} }}
                $<selector_ $fname>.is_intro_item_keyword
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

            // Accumulates `item` (which must be DataSet::Value) into `Putnam`
            ${define ACCUMULATE_ITEM_VALUE { {
                $<selector_ $fname>.accumulate(&mut $fpatname, item)?;
            } }}

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
            let $fpatname: $ftype = <$ftype as ItemValueParseable>::from_unparsed(item)?;

          } F_FLATTEN {

            let mut $fpatname = <$ftype as NetdocParseableFields>::Accumulator::default();

          } else {

            let mut $fpatname: Option<$F_EFFECTIVE_TYPE> = None;

          }})

            //----- Parse the normal items -----
            dtrace!("looking for normal items");

            while let Some(kw) = peek_keyword(input)? {
                dtrace!("for normal, peeked", kw);
                if inner_stop.stop_at(kw) {
                    dtrace!("is inner stop", kw);
                    break;
                };
              ${for fields {
                ${when not(any(F_FLATTEN, F_SUBDOC))}

                if kw == $F_KEYWORD {
                  ${select1
                    F_NORMAL {
                      let item = $THIS_ITEM;
                      dtrace!("is normal", item);
                      let item = ItemValueParseable::from_unparsed(item)?;
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
                    $ftype::accumulate_item(&mut $fpatname, item)?;
                } else
              }}
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

                $<selector_ $fname>.can_accumulate(&mut $fpatname)?;

                dtrace!("is this subdoc", kw);
                let item = NetdocParseable::from_items(input, inner_stop);
                dtrace!("parsed this subdoc", item.as_ref().map(|_| ()));
                let item = item?;

                $ACCUMULATE_ITEM_VALUE
            }
          }}

            // Resolve all the fields
            dtrace!("reached end, resolving");

          ${for fields {
            ${select1
              F_INTRO {}
              any(F_NORMAL, F_SIGNATURE) {
                  let $fpatname = $<selector_ $fname>.finish($fpatname, $F_KEYWORD_REPORT)?;
              }
              F_FLATTEN {
                  let $fpatname = <$ftype as NetdocParseableFields>::finish($fpatname)?;
              }
              F_SUBDOC {
                  let $fpatname = $<selector_ $fname>.finish_subdoc($fpatname)?;
              }
          }}}
          $(
            ${when not(F_INTRO)}
          ${if fmeta(netdoc(default)) {
            let $fpatname = Option::unwrap_or_default($fpatname);
          }}
          )

            let r = $vpat;

            Ok(r)
        }
    }
}

define_derive_deftly! {
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
    ///  * The input struct can contain only normal non-structural items
    ///    (so it's not a sub-document with an intro item).
    ///  * The only attribute supported is the field attribute
    ///    `#[deftly(netdoc(keyword = STR))]`
    export NetdocParseableFields for struct , expect items, beta_deftly:

    // TODO deduplicate with copy in NetdocParseableafter after rust-derive-deftly#39

    // Convenience alias for our prelude
    ${define P { $crate::parse2::internal_prelude }}

    // The effective field type for parsing.
    //
    // Handles #[deftly(netdoc(default))], in which case we parse as if the field was Option,
    // and substitute in the default at the end.
    //
    ${define F_EFFECTIVE_TYPE {
        ${if all(fmeta(netdoc(default)), not(F_INTRO)) {
            Option::<$ftype>
        } else {
            $ftype
        }}
    }}
    ${define F_ITEM_SET_SELECTOR {
        ItemSetSelector::<$F_EFFECTIVE_TYPE>::default()
    }}

    // NOTE! These keyword defines are simpler than the ones for NetdocParseable.
    // Care must be taken if they are deduplicated as noted above.
    // Field keyword as `&str`
    ${define F_KEYWORD_STR { ${concat
        ${fmeta(netdoc(keyword)) as str,
          default ${kebab_case $fname}}
    }}}
    // Field keyword as `KeywordRef`
    ${define F_KEYWORD { (KeywordRef::new_const($F_KEYWORD_STR)) }}

    #[derive(Default, Debug)]
    $tvis struct $<$tname NetdocParseAccumulator><$tdefgens> { $(
        $fname: Option<$F_EFFECTIVE_TYPE>,
    ) }

    impl<$tgens> $P::NetdocParseableFields for $ttype {
        type Accumulator = $<$ttype NetdocParseAccumulator>;

        fn is_item_keyword(kw: $P::KeywordRef<'_>) -> bool {
          ${for fields {
            kw == $F_KEYWORD ||
          }}
            false
        }

        fn accumulate_item(
            acc: &mut Self::Accumulator,
            item: $P::UnparsedItem<'_>,
        ) -> Result<(), $P::ErrorProblem> {
          $(
            if item.keyword() == $F_KEYWORD {
                let selector = $F_ITEM_SET_SELECTOR;
                selector.${paste_spanned $fname check_item_value_parseable}();
                let item = ItemValueParseable::from_unparsed(item)?;
                selector.accumulate(&mut acc.$fname, item)
            } else
          )
            {
                panic!("accumulate_item called though is_intro_item_keyword returns false");
            }
        }

        fn finish(acc: Self::Accumulator) -> Result<Self, $P::ErrorProblem> {
            Ok($tname {
              $(
                $fname: $F_ITEM_SET_SELECTOR.finish(acc.$fname, $F_KEYWORD_STR)?,
              )
            })
        }
    }
}

define_derive_deftly! {
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

        fn from_items<'s>(
            input: &mut $P::ItemStream<'s>,
            outer_stop: $P::stop_at!(),
        ) -> Result<$<$ttype Signed>, $P::ErrorProblem> {
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
    /// Derive `ItemValueParseable`
    ///
    /// Fields in the struct are parsed from the keyword line arguments,
    /// in the order they appear in the struct.
    ///
    /// ### Field type
    ///
    /// Each field should be:
    ///
    ///  * `impl `[`ItemArgumentParseable`] (one argument),
    ///  * `Option<impl ItemArgumentParseable>` (one optional argument), or
    ///  * `Vec<impl ItemArgumentParseable>` (zero or more arguments).
    ///
    /// `ItemArgumentParseable` is implemented for every `impl FromStr`,
    /// so `impl FromStr`, `Option<impl FromStr>` and `Vec<impl FromStr>`
    /// are supported.
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
    /// ### Field-level attributes:
    ///
    ///  * **`#[deftly(netdoc(object))]**:
    ///
    ///    The field is the Object.
    ///    It must implement [`ItemObjectParseable`]
    ///    (so it can be be `Option<impl ItemObjectParseable>`
    ///    for an optional item.)
    ///
    ///    Only allowed once.
    ///    If omittted, any object is rejected.
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
    export ItemValueParseable for struct, expect items:

    ${define P { $crate::parse2::internal_prelude }}

    ${defcond F_REST fmeta(netdoc(rest))}
    ${defcond F_OBJECT fmeta(netdoc(object))}
    ${defcond F_SIG_HASH fmeta(netdoc(sig_hash))}
    ${defcond F_NORMAL not(any(F_REST, F_OBJECT, F_SIG_HASH))}

    ${defcond T_IS_SIGNATURE not(approx_equal(${for fields { ${when F_SIG_HASH} 1 }}, {}))}
    ${define TRAIT ${if T_IS_SIGNATURE { SignatureItemParseable } else { ItemValueParseable }}}
    ${define METHOD ${if T_IS_SIGNATURE { from_unparsed_and_body } else { from_unparsed }}}

    impl<$tgens> $P::$TRAIT for $ttype {
        fn $METHOD<'s>(
            mut input: $P::UnparsedItem<'s>,
          ${if T_IS_SIGNATURE {
            document_body: &SignatureHashInputs<'_>,
          }}
        ) -> Result<Self, $P::EP>
        {
            #[allow(unused_imports)] // false positive when macro is used with prelude in scope
            use $P::*;

            let object = input.object();
            #[allow(unused)]
            let mut args = input.args_mut();
          $(
            let $fpatname = ${select1
              F_NORMAL {
                  <$ftype as ItemArgumentParseable>::from_args(&mut args, stringify!($fname))?
              }
              all(F_OBJECT, not(fmeta(netdoc(object(label))))) {
                  <$ftype as ItemObjectParseable>::from_bytes_option(
                      object
                          .map(|object| object.decode_data()).transpose()?
                          .as_deref()
                  )?
              }
              all(F_OBJECT, fmeta(netdoc(object(label)))) { {
                  let object = object.ok_or_else(|| EP::MissingObject)?;
                  if object.label() != ${fmeta(netdoc(object(label))) as str} {
                      return Err(EP::ObjectIncorrectLabel)
                  }
                  object.decode_data()?
              } }
              F_REST {
                  // consumes `args`, leading to compile error if the rest field
                  // isn't last (or is combined with no_extra_args).
                  <$ftype as FromStr>::parse(args.into_rest())?
              }
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
