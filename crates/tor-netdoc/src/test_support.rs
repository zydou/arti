//! Support functions for testing, also expoeted
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
#![allow(clippy::string_slice)] // See arti#2571
//! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

use crate::parse2::{NetdocParseableFields, ParseInput, parse_netdoc};
use derive_deftly::Deftly;
use itertools::chain;

/// Parse a test case from a netdoc-style test case string
///
/// `T` must be `NetdocParseableFields`.
/// (a surrounding document type with an intro item will be used internally.)
///
/// The input string is preprocessed:
///
///  - `#`-comments are stripped
///  - each line is trimmed (so the input can be inden ted)
///  - blank lines are removed
pub fn parse_testcase_from_netdoc<T: NetdocParseableFields>(input_doc: &str) -> T {
    #[derive(Deftly)]
    #[derive_deftly(NetdocParseable)]
    struct Document<T: NetdocParseableFields> {
        /// Intro item, not present in test case doc strings
        #[allow(unused)]
        parse_testcase_from_netdoc_intro: (),

        #[deftly(netdoc(flatten))]
        fields: T,
    }

    eprintln!("\n&&&&&&& input test case\n{input_doc}");
    let doc = chain!(
        ["parse-testcase-from-netdoc-intro\n"],
        input_doc
            .lines()
            .map(|l| l.split_once('#').map(|(l, _)| l).unwrap_or(l).trim())
            .filter(|l| !l.is_empty())
            .flat_map(|l| [l, "\n"]),
    )
    .collect::<String>();

    eprintln!(
        "---- tidied \n{}----",
        doc.split_inclusive('\n')
            // show line numbers in case of parse errors, what a faff
            .enumerate()
            .map(|(lno, l)| format!("| {:5} {l}", lno + 1))
            .collect::<String>()
    );

    let pinput = ParseInput::new(&doc, "<input doc>");
    let case: Document<T> = parse_netdoc(&pinput).expect("parse failed");

    case.fields
}
