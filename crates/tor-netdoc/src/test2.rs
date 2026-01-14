// @@ begin test lint list maintained by maint/add_warning @@
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::dbg_macro)]
#![allow(clippy::mixed_attributes_style)]
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::unchecked_time_subtraction)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_pass_by_value)]
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
#![allow(clippy::needless_borrows_for_generic_args)] // TODO add to maint/add_warning

use std::fmt::{self, Debug};
use std::mem;
use std::slice;

use anyhow::Context as _;
use derive_deftly::Deftly;
use itertools::{Itertools, chain};
use testresult::TestResult;
use tor_error::{Bug, ErrorReport as _};

use crate::encode::{ItemEncoder, ItemObjectEncodable, NetdocEncodable, NetdocEncoder};
use crate::parse2::{
    ArgumentError as P2AE, ArgumentStream, ErrorProblem as P2EP, ItemObjectParseable,
    NetdocParseable, ParseError, ParseInput, UnparsedItem, parse_netdoc, parse_netdoc_multiple,
    parse_netdoc_multiple_with_offsets,
};
use crate::types::{Ignored, NotPresent};

fn default<T: Default>() -> T {
    Default::default()
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct Top {
    top_intro: (),
    needed: (String,),
    optional: Option<(String,)>,
    several: Vec<(String,)>,
    not_present: NotPresent,
    #[deftly(netdoc(default))]
    defaulted: (i32,),
    #[deftly(netdoc(keyword = "renamed"))]
    t4_renamed: Option<(String,)>,
    #[deftly(netdoc(subdoc))]
    sub1: Sub1,
    #[deftly(netdoc(subdoc))]
    sub2: Option<Sub2>,
    #[deftly(netdoc(subdoc))]
    sub3: Vec<Sub3>,
    #[deftly(netdoc(subdoc, default))]
    sub4: Sub4,
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct Sub1 {
    sub1_intro: (),
    sub1_field: Option<(String,)>,
    #[deftly(netdoc(flatten))]
    flatten: Flat1,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodableFields, NetdocParseableFields)]
struct Flat1 {
    flat_needed: (String,),
    flat_optional: Option<(String,)>,
    flat_several: Vec<(String,)>,
    flat_defaulted: Option<(String,)>,
    #[deftly(netdoc(single_arg))]
    flat_arg_needed: String,
    #[deftly(netdoc(single_arg))]
    flat_arg_optional: Option<String>,
    #[deftly(netdoc(single_arg))]
    flat_arg_several: Vec<String>,
    #[deftly(netdoc(single_arg, default))]
    flat_arg_defaulted: i32,
    #[deftly(netdoc(with = "needs_with_parse"))]
    flat_with_needed: NeedsWith,
    #[deftly(netdoc(with = "needs_with_parse"))]
    flat_with_optional: Option<NeedsWith>,
    #[deftly(netdoc(with = "needs_with_parse"))]
    flat_with_several: Vec<NeedsWith>,
    #[deftly(netdoc(flatten))]
    flat_flat: FlatInner,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodableFields, NetdocParseableFields)]
struct FlatInner {
    flat_inner_optional: Option<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct Sub2 {
    #[deftly(netdoc(with = "needs_with_intro"))]
    sub2_intro: NeedsWith,
    sub2_field: Option<(String,)>,
    #[deftly(netdoc(single_arg))]
    arg_needed: String,
    #[deftly(netdoc(single_arg))]
    arg_optional: Option<String>,
    #[deftly(netdoc(single_arg))]
    arg_several: Vec<String>,
    #[deftly(netdoc(single_arg, default))]
    arg_defaulted: i32,
    #[deftly(netdoc(with = "needs_with_parse"))]
    with_needed: NeedsWith,
    #[deftly(netdoc(with = "needs_with_parse"))]
    with_optional: Option<NeedsWith>,
    #[deftly(netdoc(with = "needs_with_parse"))]
    with_several: Vec<NeedsWith>,
    #[deftly(netdoc(subdoc))]
    subsub: SubSub,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct Sub3 {
    sub3_intro: (),
    sub3_field: Option<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct Sub4 {
    sub4_intro: (),
    sub4_field: Option<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct SubSub {
    #[deftly(netdoc(single_arg))]
    subsub_intro: String,
    subsub_field: Option<(String,)>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct NeedsWith;

impl NeedsWith {
    fn parse_expecting(exp: &str, args: &mut ArgumentStream<'_>) -> Result<NeedsWith, P2AE> {
        let got = args.next().ok_or(P2AE::Missing)?;
        (got == exp).then_some(NeedsWith).ok_or(P2AE::Invalid)
    }
}

mod needs_with_parse {
    use super::*;
    pub(super) fn from_unparsed(mut item: UnparsedItem<'_>) -> Result<NeedsWith, P2EP> {
        NeedsWith::parse_expecting("normal", item.args_mut())
            .map_err(item.args().error_handler("in needs with"))
    }
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn write_item_value_onto(_: &NeedsWith, out: ItemEncoder) -> Result<(), Bug> {
        out.arg(&"normal");
        Ok(())
    }
}
mod needs_with_intro {
    use super::*;
    pub(super) fn from_unparsed(mut item: UnparsedItem<'_>) -> Result<NeedsWith, P2EP> {
        NeedsWith::parse_expecting("intro", item.args_mut())
            .map_err(item.args().error_handler("in needs with"))
    }
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn write_item_value_onto(_: &NeedsWith, out: ItemEncoder) -> Result<(), Bug> {
        out.arg(&"intro");
        Ok(())
    }
}
mod needs_with_arg {
    use super::*;
    pub(super) fn from_args(args: &mut ArgumentStream) -> Result<NeedsWith, P2AE> {
        NeedsWith::parse_expecting("arg", args)
    }
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn write_arg_onto(_self: &NeedsWith, out: &mut ItemEncoder<'_>) -> Result<(), Bug> {
        out.args_raw_string(&"arg");
        Ok(())
    }
    pub(super) fn from_args_rest(s: &str) -> Result<NeedsWith, ()> {
        (s == "rest of line").then_some(NeedsWith).ok_or(())
    }
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn fmt_args_rest(_self: &NeedsWith, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rest of line")
    }
}

/// Test parsing and encoding of a single-document file
///
/// `doc_spec` is the document to parse.
/// `exp` is what it should parse as.
///
/// `doc_spec` can have magic instructions at end of each line.
/// These allow the re-encoding to be not quite identical to the input document.
///
///  * **`@ re-encoded:`:
///    This line is re-encoded differently.  The *next* source line is the encoding.
///
///  * **`@ not re-encoded`:
///    This line is omitted from the re-encoding.
///
///  * **`@ re-encoded later N`:
///    This line is reordered, to later in the re-encoding, by `N` lines.
///
///  * **`@ re-encoded only`:
///    This line eppears only in the re-encoding.
///    Prefer `re-encoded later` or `re-encoded:` if possible as they're clearer.
fn t_ok<D>(doc_spec: &str, exp: &D) -> TestResult<()>
where
    D: NetdocEncodable + NetdocParseable + Debug + PartialEq,
{
    t_ok_multi::<D>(&[], doc_spec, slice::from_ref(exp))
}

/// Test parsing and encoding of a multi-document file
///
/// The de/re-encoding syntax is as above.
//
// It would perhaps be better if `doc_boundaries` were obtained from magic instructions,
// but there's only one test case with a fragile hardcoded byte offset ATM.
fn t_ok_multi<D>(doc_boundaries: &[usize], doc_spec: &str, exp: &[D]) -> TestResult<()>
where
    D: NetdocEncodable + NetdocParseable + Debug + PartialEq,
{
    eprintln!("#####");
    eprint!("====== doc_spec ======\n{doc_spec}");
    eprintln!("====== exp ======\n{exp:#?}");

    let mut lines = doc_spec.split_inclusive('\n');
    let mut doc = String::new();
    let mut enc = String::new();

    // indices are line numbers but starting at 0
    let mut moved = Vec::<String>::new();
    let process_moved = |enc: &mut String, moved: &mut Vec<String>| {
        if moved.is_empty() {
            return;
        }
        loop {
            let lno = enc.lines().count();
            let Some(m) = moved.get_mut(lno) else {
                eprintln!("PN {lno:2} nothing");
                break;
            };
            if m.is_empty() {
                eprintln!("PN {lno:2} empty");
                break;
            }
            eprintln!("PN {lno:2} adding {m:?}");
            *enc += &mem::take(m);
        }
    };

    while let Some(l) = lines.next() {
        if let Some((l, insn)) = l.split_once('@') {
            eprintln!("LL    insn  {l:?}");
            let insn = insn.trim();
            let l = &format!("{}\n", l.trim_end());
            let insn = insn.trim_end();
            if insn == "re-encoded:" {
                doc += l;
                enc += lines.next().expect(r#""re-encoded:" needs re-encoded"#);
            } else if insn == "not re-encoded" {
                doc += l;
            } else if insn == "re-encoded only" {
                enc += l;
            } else if let Some(later) = insn.strip_prefix("re-encoded later ") {
                doc += l;
                let later: usize = later.parse().expect(later);
                let lno = later + enc.lines().count();
                loop {
                    if let Some(m) = moved.get_mut(lno) {
                        *m += l;
                        break;
                    }
                    moved.push("".into());
                }
            } else {
                panic!("unknown insn {insn:?} in {doc_spec:?}");
            }
        } else {
            eprintln!("LL    line  {l:?}");
            doc += l;
            enc += l;
        }
        process_moved(&mut enc, &mut moved);
    }
    process_moved(&mut enc, &mut moved);
    for (i, l) in moved.iter().enumerate() {
        assert_eq!(l, "", "line too late! {}: {l:?}", i + 1);
    }

    eprint!("====== doc ======\n{doc}");
    eprint!("====== enc exp ======\n{enc}");
    eprintln!("======");

    let input = ParseInput::new(&doc, "<literal>");

    if exp.len() == 1 {
        let got = parse_netdoc::<D>(&input).context(doc.clone())?;
        assert_eq!(got, exp[0], "parse 1 mismatch");
    }

    let got = parse_netdoc_multiple::<D>(&input)?;
    assert_eq!(got, exp, "parse_multiple mismatch");

    let got_with_offsets = parse_netdoc_multiple_with_offsets::<D>(&input)?;
    for (i, (got, start, end)) in got_with_offsets.iter().enumerate() {
        assert_eq!(got, &exp[i], "parse_multiple_with_offsets mismatch");
        assert_eq!(*start, if i == 0 { 0 } else { doc_boundaries[i - 1] });
        assert_eq!(*end, doc_boundaries.get(i).copied().unwrap_or(doc.len()));
    }

    let reenc = {
        let mut encoder = NetdocEncoder::default();
        for d in exp {
            d.encode_unsigned(&mut encoder)?;
        }
        encoder.finish()?
    };

    eprintln!("====== enc got ======\n{reenc}====== end ======");

    assert_eq!(
        &enc,
        &reenc,
        "re-encode mismatch:\n{}",
        Itertools::zip_longest(
            chain!(["EXPECTED"], enc.lines()),
            chain!(["GOT"], reenc.lines()),
        )
        .enumerate()
        .map(|(i, eob)| {
            let lno = i + 1;
            let [l, r] = [eob.clone().left(), eob.right()];
            let yn = if l == r { "  " } else { "!=" };
            let [l, r] = [l, r].map(|s| s.unwrap_or_default());
            format!(" {lno:2} {l:30} {yn} {r}\n")
        })
        .collect::<String>(),
    );

    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // Result for consistency
fn t_err_raw<D>(
    exp_lno: usize,
    exp_col: Option<usize>,
    exp_err: &str,
    doc: &str,
) -> TestResult<ParseError>
where
    D: NetdocParseable + Debug,
{
    let input = ParseInput::new(doc, "<massaged>");
    let got = parse_netdoc::<D>(&input).expect_err("unexpectedly parsed ok");
    let got_err = got.problem.to_string();
    assert_eq!(
        (got.lno, got.column),
        (exp_lno, exp_col),
        "doc\n====\n{doc}====\n got={}\n exp={exp_err}",
        got_err
    );
    assert_eq!(
        got_err, exp_err,
        "doc\n====\n{doc}====\n got={}\n exp={exp_err}",
        got_err
    );
    Ok(got)
}

/// Test an error case with embedded error message
///
/// `case` should be the input document, but exactly one line should
/// contain `" # "`, with the expected error message as a "comment".
///
/// Iff the expected message is supposed to have a column number,
/// the comment part should end with ` @<column>`.
///
/// `t_err` will check that that error is reported, at that line.
fn t_err<D>(mut case: &str) -> TestResult<ParseError>
where
    D: NetdocParseable + Debug,
{
    let mut exp = None;
    let mut doc = String::new();
    let mut lno = 0;
    while let Some((l, r)) = case.split_once('\n') {
        lno += 1;
        case = r;
        if let Some((l, r)) = l.split_once(" # ") {
            assert!(exp.is_none());
            exp = Some((lno, r.trim()));
            let l = l.trim_end();
            doc += l;
        } else {
            doc += l;
        }
        doc += "\n";
    }
    if !case.is_empty() {
        panic!("missing final newline");
    }
    let (exp_lno, exp_err) = exp.expect("missing # error indication in test case");
    let (exp_err, exp_col) = if let Some((l, r)) = exp_err.rsplit_once(" @") {
        (l, Some(r.parse().unwrap()))
    } else {
        (exp_err, None)
    };
    println!("==== 8<- ====\n{doc}==== ->8 ====");
    t_err_raw::<D>(exp_lno, exp_col, exp_err, &doc)
}

/// Test an error case with embedded error message
///
/// `case` should be the input document, but exactly one line should
/// contain `" # "`, with the expected error message as a "comment".
///
/// Iff the expected message is supposed to have a column number,
/// the comment part should end with ` @<column>`.
///
/// `t_err` will check that that error is reported, at that column.
fn t_err_chk_msg<D>(case: &str, msg: &str) -> TestResult
where
    D: NetdocParseable + Debug,
{
    let err = t_err::<D>(case)?;
    assert_eq!(err.report().to_string(), msg);
    Ok(())
}

#[test]
fn various_docs() -> TestResult<()> {
    let val = |s: &str| (s.to_owned(),);
    let sval = |s: &str| Some(val(s));

    let sub1_minimal = Sub1 {
        flatten: Flat1 {
            flat_needed: val("FN"),
            flat_arg_needed: "FAN".into(),
            ..default()
        },
        ..default()
    };
    let subsub_minimal = SubSub {
        subsub_intro: "SSI".into(),
        ..default()
    };
    let sub2_minimal = Sub2 {
        arg_needed: "AN".into(),
        subsub: subsub_minimal.clone(),
        ..default()
    };

    t_ok(
        r#"top-intro
needed N
defaulted 0                             @ re-encoded only
sub1-intro
flat-needed FN
flat-arg-needed FAN
flat-arg-defaulted 0                    @ re-encoded only
flat-with-needed normal
sub4-intro                              @ re-encoded only
"#,
        &Top {
            needed: val("N"),
            sub1: sub1_minimal.clone(),
            ..default()
        },
    )?;

    t_ok(
        r#"top-intro
needed N
defaulted 0                             @ re-encoded only
sub1-intro
flat-needed FN
flat-arg-needed FAN
flat-arg-defaulted 0                    @ re-encoded only
flat-with-needed normal
sub2-intro intro
with-needed normal                      @ re-encoded later 2
arg-needed AN
arg-defaulted 0                         @ re-encoded only
subsub-intro SSI
sub3-intro
sub3-intro
sub4-intro
"#,
        &Top {
            needed: val("N"),
            sub1: sub1_minimal.clone(),
            sub2: Some(sub2_minimal.clone()),
            sub3: vec![default(); 2],
            ..default()
        },
    )?;

    t_ok(
        r#"top-intro
needed N
optional O
several 1
not-present oh yes it is                @ not re-encoded
not-present but it is ignored           @ not re-encoded
several 2
defaulted -1
renamed R
sub1-intro
flat-several FS1                        @ re-encoded later 3
flat-needed FN                          @ re-encoded later 1
flat-with-needed normal                 @ re-encoded later 11
flat-inner-optional nested              @ re-encoded later 15
sub1-field A
flat-with-several normal                @ re-encoded later 11
flat-with-several normal                @ re-encoded later 11
flat-optional FO
flat-arg-needed FAN                     @ re-encoded later 2
flat-with-optional normal               @ re-encoded later 8
flat-several FS2
flat-defaulted FD
flat-arg-optional FAO
flat-arg-several FAS1 ignored           @ re-encoded:
flat-arg-several FAS1
flat-arg-several FAS2
flat-arg-defaulted 31
sub2-intro intro
with-several normal                     @ re-encoded later 8
with-several normal                     @ re-encoded later 8
with-several normal                     @ re-encoded later 8
sub2-field B
arg-needed AN
arg-optional AO
with-optional normal                    @ re-encoded later 4
arg-defaulted 4                         @ re-encoded later 2
arg-several A1
arg-several A2
with-needed normal
subsub-intro SSI
subsub-field BS
sub3-intro
sub3-field C1
sub3-intro
sub3-field C2
sub4-intro
sub4-field D
"#,
        &Top {
            needed: val("N"),
            optional: sval("O"),
            several: ["1", "2"].map(val).into(),
            defaulted: (-1,),
            t4_renamed: sval("R"),
            sub1: Sub1 {
                sub1_field: sval("A"),
                flatten: Flat1 {
                    flat_needed: val("FN"),
                    flat_optional: sval("FO"),
                    flat_several: ["FS1", "FS2"].map(val).into(),
                    flat_defaulted: sval("FD"),
                    flat_arg_needed: "FAN".into(),
                    flat_arg_several: ["FAS1", "FAS2"].map(Into::into).into(),
                    flat_arg_optional: Some("FAO".into()),
                    flat_arg_defaulted: 31,
                    flat_with_optional: Some(NeedsWith),
                    flat_with_several: vec![NeedsWith; 2],
                    flat_flat: FlatInner {
                        flat_inner_optional: sval("nested"),
                    },
                    ..Flat1::default()
                },
                ..default()
            },
            sub2: Some(Sub2 {
                sub2_field: sval("B"),
                arg_optional: Some("AO".into()),
                arg_defaulted: 4,
                arg_several: ["A1", "A2"].map(Into::into).into(),
                with_optional: Some(NeedsWith),
                with_several: vec![NeedsWith; 3],
                subsub: SubSub {
                    subsub_field: sval("BS"),
                    ..subsub_minimal.clone()
                },
                ..sub2_minimal.clone()
            }),
            sub3: ["C1", "C2"]
                .map(|s| Sub3 {
                    sub3_field: sval(s),
                    ..default()
                })
                .into(),
            sub4: Sub4 {
                sub4_field: sval("D"),
                ..default()
            },
            ..default()
        },
    )?;

    t_err_raw::<Top>(0, None, "empty document", r#""#)?;

    let wrong_document = r#"wrong-keyword # wrong document type
"#;
    t_err_chk_msg::<Top>(
        wrong_document,
        "error: failed to parse network document, type top-intro: <massaged>:1: wrong document type",
    )?;

    t_err::<Top>(
        r#"top-intro
sub4-intro # missing item needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
flat-arg-needed arg
flat-with-needed normal
sub4-intro # missing item flat-needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
flat-needed flat
flat-with-needed normal
sub4-intro # missing item flat-arg-needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
flat-arg-needed FAN
flat-with-needed normal
flat-needed FN
sub4-intro # missing item needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
needed N
sub3-intro
sub4-intro # missing item sub1-intro
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
needed N
sub1-intro
flat-needed FN1
flat-arg-needed FAN
flat-with-needed normal
sub1-intro # item repeated when not allowed
flat-needed FN2
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
needed N
sub2-intro # missing argument in needs with
"#,
    )?;

    let wrong_value = r#"top-intro
needed N
sub2-intro wrong-value # invalid value for argument in needs with @12
"#;
    t_err_chk_msg::<Top>(
        wrong_value,
        "error: failed to parse network document, type top-intro: <massaged>:3.12: invalid value for argument in needs with",
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
flat-needed FN
flat-arg-needed arg
sub4-intro # missing item flat-with-needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
flat-needed FN
flat-arg-needed arg
flat-with-needed normal
sub2-intro intro
arg-needed AN
flat-arg-needed arg
sub3-intro # missing item with-needed
"#,
    )?;

    Ok(())
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocEncodable, NetdocParseable)]
struct TopMinimal {
    test_item0: TestItem0,
    test_item: Option<TestItem>,
    test_item_rest: Option<TestItemRest>,
    test_item_rest_with: Option<TestItemRestWith>,
    test_item_object_not_present: Option<TestItemObjectNotPresent>,
    test_item_object_ignored: Option<TestItemObjectIgnored>,
    #[deftly(netdoc(skip))]
    __test_skip: (),
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
#[deftly(netdoc(no_extra_args))]
struct TestItem0 {
    #[deftly(netdoc(object(label = "UTF-8 STRING"), with = "string_data_object"))]
    object: Option<String>,
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
struct TestItem {
    needed: String,
    #[deftly(netdoc(with = "needs_with_arg"))]
    optional: Option<NeedsWith>,
    rest: Vec<String>,
    #[deftly(netdoc(object))]
    object: TestObject,
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
struct TestItemRest {
    optional: Option<String>,
    #[deftly(netdoc(rest))]
    rest: String,
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
struct TestItemRestWith {
    #[deftly(netdoc(rest, with = "needs_with_arg"))]
    rest: NeedsWith,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
struct TestObject(String);

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
struct TestItemObjectNotPresent {
    #[deftly(netdoc(object))]
    object: NotPresent,
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(ItemValueEncodable, ItemValueParseable)]
struct TestItemObjectIgnored {
    #[deftly(netdoc(object))]
    object: Ignored,
}

/// Conversion module for `String` as Object with [`ItemValueParseable`]
mod string_data_object {
    /// Parse the data
    pub(super) fn try_from(data: Vec<u8>) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(data)
    }

    /// Encode the data
    #[allow(clippy::unnecessary_wraps)] // signature must match the derive's expectation
    pub(super) fn write_object_onto<B>(self_: &String, b: &mut B) -> tor_bytes::EncodeResult<()>
    where
        B: tor_bytes::Writer + ?Sized,
    {
        b.write_all(self_.as_bytes());
        Ok(())
    }
}

impl ItemObjectParseable for TestObject {
    fn check_label(label: &str) -> Result<(), P2EP> {
        if label != "TEST OBJECT" {
            return Err(P2EP::ObjectIncorrectLabel);
        }
        Ok(())
    }
    fn from_bytes(data: &[u8]) -> Result<Self, P2EP> {
        Ok(TestObject(
            String::from_utf8(data.to_owned()).map_err(|_| P2EP::ObjectInvalidData)?,
        ))
    }
}
impl ItemObjectEncodable for TestObject {
    fn label(&self) -> &'static str {
        "TEST OBJECT"
    }
    fn write_object_onto(&self, b: &mut Vec<u8>) -> Result<(), Bug> {
        b.extend(self.0.as_bytes());
        Ok(())
    }
}

#[test]
fn various_items() -> TestResult<()> {
    let test_item_minimal = TestItem {
        needed: "N".into(),
        object: TestObject("hello".into()),
        ..default()
    };

    t_ok(
        r#"test-item0
"#,
        &TopMinimal { ..default() },
    )?;

    t_ok(
        r#"test-item0
test-item N
-----BEGIN TEST OBJECT-----
aGVsbG8=
-----END TEST OBJECT-----
"#,
        &TopMinimal {
            test_item: Some(test_item_minimal.clone()),
            ..default()
        },
    )?;

    t_ok(
        r#"test-item0
test-item N arg
-----BEGIN TEST OBJECT-----
aGVsbG8=
-----END TEST OBJECT-----
"#,
        &TopMinimal {
            test_item: Some(TestItem {
                optional: Some(NeedsWith),
                ..test_item_minimal.clone()
            }),
            ..default()
        },
    )?;

    t_ok(
        r#"test-item0
-----BEGIN UTF-8 STRING-----
aGVsbG8=
-----END UTF-8 STRING-----
test-item N arg R1 R2
-----BEGIN TEST OBJECT-----
aGVsbG8=
-----END TEST OBJECT-----
test-item-rest O  and  the rest                 @ re-encoded:
test-item-rest O and  the rest
test-item-rest-with   rest of line              @ re-encoded:
test-item-rest-with rest of line
test-item-object-not-present
test-item-object-ignored
-----BEGIN TEST OBJECT-----                     @ not re-encoded
aGVsbG8=         @ not re-encoded
-----END TEST OBJECT-----                       @ not re-encoded
"#,
        &TopMinimal {
            test_item0: TestItem0 {
                object: Some("hello".into()),
            },
            test_item: Some(TestItem {
                optional: Some(NeedsWith),
                rest: ["R1", "R2"].map(Into::into).into(),
                ..test_item_minimal.clone()
            }),
            test_item_rest: Some(TestItemRest {
                optional: Some("O".into()),
                rest: "and  the rest".into(),
            }),
            test_item_rest_with: Some(TestItemRestWith { rest: NeedsWith }),
            test_item_object_not_present: Some(TestItemObjectNotPresent { object: NotPresent }),
            test_item_object_ignored: Some(TestItemObjectIgnored { object: Ignored }),
            __test_skip: (),
        },
    )?;

    t_ok_multi(
        &[11],
        r#"test-item0
test-item0
test-item-rest optional resty rest
"#,
        &[
            TopMinimal::default(),
            TopMinimal {
                test_item_rest: Some(TestItemRest {
                    optional: Some("optional".into()),
                    rest: "resty rest".into(),
                }),
                ..default()
            },
        ],
    )?;

    t_err::<TopMinimal>(
        r#"test-item0 wrong # too many arguments @12
"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0 # base64-encoded Object label is not as expected
-----BEGIN WRONG LABEL-----
aGVsbG8=
-----END WRONG LABEL-----
"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0 # base64-encoded Object END label does not match BEGIN
-----BEGIN UTF-8 STRING-----
aGVsbG8=
-----END WRONG LABEL-----
"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0
test-item-object-not-present # base64-encoded Object found where none expected
-----BEGIN TEST OBJECT-----
aGVsbG8=
-----END TEST OBJECT-----
"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0 # base64-encoded Object has incorrectly formatted delimiter lines
-----BEGIN UTF-8 STRING-----
aGVsbG8=
-----END UTF-8 STRING
"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0 # base64-encoded Object contains invalid base64
-----BEGIN UTF-8 STRING-----
bad b64 !
-----END UTF-8 STRING-----

"#,
    )?;
    t_err::<TopMinimal>(
        r#"test-item0 # base64-encoded Object contains invalid data
-----BEGIN UTF-8 STRING-----
hU6Qo2fW7+9PXkcrEyiB62ZDne/gwKPHXBo8lMeV8JCOfVBF5vT4BtKRLP+Jw66x
-----END UTF-8 STRING-----
"#,
    )?;

    Ok(())
}
