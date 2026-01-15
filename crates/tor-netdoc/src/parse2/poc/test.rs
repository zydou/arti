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

use super::*;
use authcert::DirAuthKeyCert;

use std::fs;

use humantime::parse_rfc3339;

#[test]
fn parse_consensus_ns() -> anyhow::Result<()> {
    let file = "testdata2/cached-consensus";
    let text = fs::read_to_string(&file)?;
    let now = parse_rfc3339("2000-01-01T00:02:05Z")?;

    let input = ParseInput::new(&text, file);
    let doc: netstatus::NetworkStatusSignedNs = parse_netdoc(&input)?;

    let file = "testdata2/cached-certs";
    let text = fs::read_to_string(&file)?;
    let input = ParseInput::new(&text, file);
    let certs: Vec<authcert::DirAuthKeyCertSigned> = parse_netdoc_multiple(&input)?;
    let certs = certs
        .into_iter()
        .map(|cert| cert.verify_selfcert(now))
        .collect::<Result<Vec<DirAuthKeyCert>, _>>()?;

    let doc = doc.verify(
        now,
        &certs.iter().map(|cert| *cert.fingerprint).collect_vec(),
        &certs.iter().collect_vec(),
    )?;

    println!("{doc:?}");

    Ok(())
}

#[test]
fn parse_consensus_md() -> anyhow::Result<()> {
    let file = "testdata2/cached-microdesc-consensus";
    let text = fs::read_to_string(&file)?;

    let input = ParseInput::new(&text, file);
    let doc: netstatus::md::NetworkStatusSigned = parse_netdoc(&input)?;

    println!("{doc:?}");

    Ok(())
}

#[test]
fn parse_authcert() -> anyhow::Result<()> {
    let file = "testdata2/cached-certs--1";
    let now = parse_rfc3339("2000-06-01T00:00:05Z")?;
    let text = fs::read_to_string(file)?;
    let input = ParseInput::new(&text, file);
    let doc: authcert::DirAuthKeyCertSigned = parse_netdoc(&input)?;
    let doc = doc.verify_selfcert(now)?;
    println!("{doc:?}");
    assert_eq!(
        doc.fingerprint.0.to_string(),
        "$cbc82f96a5000a5fe0d6fb69519b79ea0c03ebe1",
    );
    Ok(())
}
