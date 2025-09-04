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
#![allow(clippy::needless_borrows_for_generic_args)] // TODO add to maint/add_warning

use super::*;
use anyhow::Context as _;
use testresult::TestResult;

fn default<T: Default>() -> T {
    Default::default()
}

#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseable)]
struct Top {
    top_intro: (),
    needed: (String,),
    optional: Option<(String,)>,
    several: Vec<(String,)>,
    #[deftly(netdoc(default))]
    defaulted: (String,),
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
#[derive_deftly(NetdocParseable)]
struct Sub1 {
    sub1_intro: (),
    sub1_field: Option<(String,)>,
    #[deftly(netdoc(flatten))]
    flatten: Flat1,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseableFields)]
struct Flat1 {
    flat_needed: (String,),
    flat_optional: Option<(String,)>,
    flat_several: Vec<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseable)]
struct Sub2 {
    sub2_intro: (),
    sub2_field: Option<(String,)>,
    #[deftly(netdoc(subdoc))]
    subsub: SubSub,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseable)]
struct Sub3 {
    sub3_intro: (),
    sub3_field: Option<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseable)]
struct Sub4 {
    sub4_intro: (),
    sub4_field: Option<(String,)>,
}
#[derive(Deftly, Debug, Default, Clone, Eq, PartialEq)]
#[derive_deftly(NetdocParseable)]
struct SubSub {
    subsub_intro: (),
    subsub_field: Option<(String,)>,
}

fn t_ok<D>(doc: &str, exp: &[D]) -> TestResult<()>
where
    D: NetdocParseable + Debug + PartialEq,
{
    if exp.len() == 1 {
        let got = parse_netdoc::<D>(doc, "<literal>").context(doc.to_owned())?;
        assert_eq!(got, exp[0], "doc={doc}");
    }

    let got = parse_netdoc_multiple::<D>(doc, "<literal>")?;
    assert_eq!(got, exp, "doc={doc}");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)] // Result for consistency
fn t_err_raw<D>(exp_lno: usize, exp_err: &str, doc: &str) -> TestResult
where
    D: NetdocParseable + Debug,
{
    let got = parse_netdoc::<D>(doc, "<massaged>").expect_err("unexpectedly parsed ok");
    let got_err = got.problem.to_string();
    assert_eq!(
        got.lno, exp_lno,
        "doc\n====\n{doc}====\n got={}\n exp={exp_err}",
        got_err
    );
    assert_eq!(
        got_err, exp_err,
        "doc\n====\n{doc}====\n got={}\n exp={exp_err}",
        got_err
    );
    Ok(())
}

/// Test an error case with embedded error message
///
/// `case` should be the input document, but exactly one line should
/// contain `" # "`, with the expected error message as a "comment".
///
/// `t_err` will check that that error is reported, at that line.
fn t_err<D>(mut case: &str) -> TestResult
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
    println!("==== 8<- ====\n{doc}==== ->8 ====");
    t_err_raw::<D>(exp_lno, exp_err, &doc)?;
    Ok(())
}

#[test]
fn various() -> TestResult<()> {
    let val = |s: &str| (s.to_owned(),);
    let sval = |s: &str| Some(val(s));

    let sub1_minimal = Sub1 {
        flatten: Flat1 {
            flat_needed: val("FN"),
            ..default()
        },
        ..default()
    };

    t_ok(
        r#"top-intro
needed N
sub1-intro
flat-needed FN
"#,
        &[Top {
            needed: val("N"),
            sub1: sub1_minimal.clone(),
            ..default()
        }],
    )?;

    t_ok(
        r#"top-intro
needed N
sub1-intro
flat-needed FN
sub2-intro
subsub-intro
sub3-intro
sub3-intro
sub4-intro
"#,
        &[Top {
            needed: val("N"),
            sub1: sub1_minimal.clone(),
            sub2: Some(default()),
            sub3: vec![default(); 2],
            ..default()
        }],
    )?;

    t_ok(
        r#"top-intro
needed N
optional O
several 1
several 2
defaulted D
renamed R
sub1-intro
flat-several FS1
flat-needed FN
sub1-field A
flat-optional FO
flat-several FS2
sub2-intro
sub2-field B
subsub-intro
subsub-field BS
sub3-intro
sub3-field C1
sub3-intro
sub3-field C2
sub4-intro
sub4-field D
"#,
        &[Top {
            needed: val("N"),
            optional: sval("O"),
            several: ["1", "2"].map(val).into(),
            defaulted: val("D"),
            t4_renamed: sval("R"),
            sub1: Sub1 {
                sub1_field: sval("A"),
                flatten: Flat1 {
                    flat_needed: val("FN"),
                    flat_optional: sval("FO"),
                    flat_several: ["FS1", "FS2"].map(val).into(),
                },
                ..default()
            },
            sub2: Some(Sub2 {
                sub2_field: sval("B"),
                subsub: SubSub {
                    subsub_field: sval("BS"),
                    ..default()
                },
                ..default()
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
        }],
    )?;

    t_err_raw::<Top>(0, "empty document", r#""#)?;

    t_err::<Top>(
        r#"wrong-keyword # wrong document type
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub4-intro # missing item needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
sub4-intro # missing item flat-needed
"#,
    )?;

    t_err::<Top>(
        r#"top-intro
sub1-intro
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
sub1-intro # item repeated when not allowed
flat-needed FN2
"#,
    )?;

    Ok(())
}
