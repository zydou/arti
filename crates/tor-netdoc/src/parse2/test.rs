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
        let got = parse_netdoc::<D>(doc, "<literal>")?;
        assert_eq!(got, exp[0]);
    }

    let got = parse_netdoc_multiple::<D>(doc, "<literal>")?;
    assert_eq!(got, exp);
    Ok(())
}

#[test]
fn various() -> TestResult<()> {
    let val = |s: &str| (s.to_owned(),);
    let sval = |s: &str| Some(val(s));

    t_ok(
        r#"top-intro
needed N
sub1-intro
"#,
        &[Top {
            needed: val("N"),
            ..default()
        }],
    )?;

    t_ok(
        r#"top-intro
needed N
sub1-intro
sub2-intro
subsub-intro
sub3-intro
sub3-intro
sub4-intro
"#,
        &[Top {
            needed: val("N"),
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
sub1-field A
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
            optional: Some(val("O")),
            several: ["1", "2"].map(val).into(),
            defaulted: val("D"),
            t4_renamed: sval("R"),
            sub1: Sub1 {
                sub1_field: sval("A"),
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

    Ok(())
}
