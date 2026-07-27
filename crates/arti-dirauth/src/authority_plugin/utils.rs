//! Utilities

use std::fs::{self, File};
use std::io::{self, BufWriter, Write as _};
use std::str::FromStr;

use anyhow::{Context as _, anyhow};

use super::CliError;

/// Command line filename argument, allowing `-` for stdin/stdout
//
// TODO DIRAUTH currently this can only be used for output file arguments,
// but we will implement using this for an input file argument too.
//
// TODO move this somewhere deeper in the stack (tor-basic-utils even maybe?)
// and replace open-coding in eg crates/arti/src/subcommands/hsc.rs display_service_discovery_key
// If we do that:
//   - consider whether we should preserve file permissions
//   - see the comment about leftover `.tmp` files in `write`, below
#[derive(Debug, Clone)]
pub(super) enum FilenameOrStdio {
    /// Filename
    Path(String),
    /// `-`
    Stdio,
}

impl FromStr for FilenameOrStdio {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Err(anyhow!("empty filename")),
            "-" => Ok(FilenameOrStdio::Stdio),
            other => Ok(FilenameOrStdio::Path(other.to_owned())),
        }
    }
}

impl FilenameOrStdio {
    /// Write the output file, with write-to-`.tmp`-and-rename
    ///
    /// `writer` should generate the actual output.
    /// It shouldn't fail other than for write errors.
    ///
    /// Makes no attempt to preserve file permissions.
    pub(super) fn write<W>(&self, writer: W) -> Result<(), CliError>
    where
        W: FnOnce(&mut dyn io::Write) -> io::Result<()>,
    {
        match self {
            FilenameOrStdio::Stdio => writer(&mut io::stdout().lock()).context("write to stdout"),
            FilenameOrStdio::Path(p) => (|| {
                let tmp = format!("{p}.tmp");
                let f = File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
                let mut f = BufWriter::new(f);
                (|| {
                    writer(&mut f)?;
                    f.flush()
                })()
                .with_context(|| format!("write {tmp:?}"))?;
                fs::rename(&tmp, p).with_context(|| format!("install {tmp:?} as {p:?}"))
            })(),
        }
        // If this fails, we can leave a `.tmp` file lying about.  This is fine for
        // the C Tor Arti consensus method plugin.
        //
        // If we promote this code we might want to make an effort to clean up leftover `.tmp`
        // files.  Note however that it is not possible to make that cleanup reliable.
        // Therefore whatever invokes us will need to be able to clean up such garbage, anyway.
        // It might be better to rely entirely on that, avoiding the situation where
        // a caller fails to have any cleanup functionality and very occasionally
        // `.tmp` files get left over anyway (and *this* code unjustifiably gets the blame).
        .context("write output")
        .map_err(CliError::OperationalError)
    }
}
