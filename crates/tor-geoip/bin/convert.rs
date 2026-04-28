//! Convert a database from the CSV (or "maxmind"[^mm]) format
//! into the binary format embedded in `tor-geoip-db`.
//
//! This tool is not stable.
//! Eventually we integrate it with `geoip-db-tool`,
//! which is currently shipped with the C tor implementation.
//!
//! [^mm]: Although the format is based on the format once used by maxmind,
//!    we no longer use their database due to licensing restrictions.

use std::{borrow::Cow, env, fs, path::PathBuf, process};

/// Arguments parsed from the command line.
///
/// (I'm not using `clap` here because this tool is temporary, and
/// adding a binary-only dependency to tor-geoip would be silly.)
#[derive(Clone, Debug)]
struct Args {
    /// A file where we can find IPv4 data in CSV format.
    ipv4_source: Option<PathBuf>,

    /// A file where we can find IPv6 data in CSV format.
    ipv6_source: Option<PathBuf>,

    /// A directory into which we should write the comments from the input files.
    doc_output_dir: Option<PathBuf>,

    /// A directory into which we should write the raw extracted data
    /// in the format expected by `tor-geoip-db`.
    output_dir: PathBuf,
}

/// Try to parse a set of command-line `args`.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, Error> {
    fn get_path(s: Option<String>) -> Result<PathBuf, Error> {
        Ok(
            s.ok_or(Error::InvalidArguments("Missing argument for flag".into()))?
                .into(),
        )
    }

    let mut ipv4_source = None;

    let mut ipv6_source = None;
    let mut output_dir = None;
    let mut doc_output_dir = None;

    let mut help = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "-h" => help = true,
            "-o" => output_dir = Some(get_path(args.next())?),
            "-m" => doc_output_dir = Some(get_path(args.next())?),
            "-4" => ipv4_source = Some(get_path(args.next())?),
            "-6" => ipv6_source = Some(get_path(args.next())?),
            other => {
                return Err(Error::InvalidArguments(
                    format!("Unrecognized flag {other:?}").into(),
                ));
            }
        }
    }

    if help {
        println!("Syntax: geoip-convert-mm-format -o <output_dir>");
        println!("                [-d <docs_output_dir> [-6 <ipv6_db>] [-4 <ipv4_db>]");
        println!("'geoip-convert-mm-format -h' to see this message.");
        process::exit(0);
    }

    Ok(Args {
        ipv4_source,
        ipv6_source,
        doc_output_dir,
        output_dir: output_dir
            .ok_or(Error::InvalidArguments("No output directory given".into()))?,
    })
}

/// An error from an attempted conversion.
///
/// This is not an exported type, and this script is temporary,
/// so we do not obey all our usual error conventions here.
#[derive(Debug, thiserror::Error)]
enum Error {
    /// Command-line arguments weren't correct.
    #[error("Invalid arguments: {0}\nRun with -h for usage information.")]
    InvalidArguments(Cow<'static, str>),

    /// Error while reading or writing.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// One of the databases was in an unrecognizable format.
    #[error("Unable to parse GeoIp data: {0}")]
    Parse(#[from] tor_geoip::Error),
}

/// Represent a slice of integers as little-endian bytes.
///
/// This function should only be called on a slice of integers;
/// using it on other types may give confusing (but safe) results.
#[cfg(target_endian = "little")]
fn to_bytes<T>(slice: &[T]) -> &[u8] {
    // SAFETY: anything has a valid representation a slice of u8;
    // u8 has no alignment requirements.
    let (pre, data, post) = unsafe { slice.align_to::<u8>() };
    assert!(pre.is_empty());
    assert!(post.is_empty());
    data
}

/// Extract all the `#`-prefixed comments from `s`, remove their prefix,
/// and put them in a new output string.
///
/// This is not suitable for all possible use-cases, but it generates
/// reasonable outputs for our current inputs.
fn extract_docs(s: &str) -> String {
    let mut output = String::new();
    for line in s.lines() {
        if let Some(comment) = line.trim_ascii_start().strip_prefix('#') {
            output.push_str(comment.trim_ascii_start());
            output.push('\n');
        }
    }
    output
}

fn main() -> Result<(), Error> {
    let args = parse_args(env::args().skip(1))?;

    if args.ipv4_source.is_none() && args.ipv6_source.is_none() {
        println!("(No inputs; nothing to do)");
        return Ok(());
    }

    let ipv4_text = match &args.ipv4_source {
        Some(fname) => fs::read_to_string(fname)?,
        None => "".to_owned(),
    };

    let ipv6_text = match &args.ipv6_source {
        Some(fname) => fs::read_to_string(fname)?,
        None => "".to_owned(),
    };

    let include_asn = false;
    let geoip_db = tor_geoip::GeoipDb::new_from_legacy_format(&ipv4_text, &ipv6_text, include_asn)?;

    let data = geoip_db.export_raw();

    fs::write(
        args.output_dir.join("geoip_data_v4s"),
        to_bytes(data.ipv4_starts),
    )?;
    fs::write(
        args.output_dir.join("geoip_data_v4c"),
        to_bytes(data.ipv4_ccs),
    )?;
    fs::write(
        args.output_dir.join("geoip_data_v6s"),
        to_bytes(data.ipv6_starts),
    )?;
    fs::write(
        args.output_dir.join("geoip_data_v6c"),
        to_bytes(data.ipv6_ccs),
    )?;

    if let Some(doc_output_dir) = args.doc_output_dir {
        fs::write(
            doc_output_dir.join("export-info-v4.txt"),
            extract_docs(&ipv4_text),
        )?;
        fs::write(
            doc_output_dir.join("export-info-v6.txt"),
            extract_docs(&ipv6_text),
        )?;
    }

    Ok(())
}
