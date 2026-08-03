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

/// Output file currently being written to
///
/// See [`FilenameOrStdio::start_writing`].
pub(super) struct Writing {
    /// Actual open-file
    handle: Box<dyn io::Write>,
    /// Filenames
    files: Option<WritingFiles>,
}

/// Filenames when writing an output file
struct WritingFiles {
    /// The `.tmp` file
    tmp: String,
    /// The main file
    main: String,
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
    ///
    /// ### `.tmp` file cleanup
    ///
    /// If this fails, we can leave a `.tmp` file lying about.  This is fine for
    /// the C Tor Arti consensus method plugin.
    ///
    /// If we promote this code we might want to make an effort to clean up leftover `.tmp`
    /// files.  Note however that it is not possible to make that cleanup reliable.
    /// Therefore whatever invokes us will need to be able to clean up such garbage, anyway.
    /// It might be better to rely entirely on that, avoiding the situation where
    /// a caller fails to have any cleanup functionality and very occasionally
    /// `.tmp` files get left over anyway (and *this* code unjustifiably gets the blame).
    pub(super) fn write<W>(&self, writer: W) -> Result<(), CliError>
    where
        W: FnOnce(&mut dyn io::Write) -> io::Result<()>,
    {
        let mut w = self.start_writing()?;
        w.append_with(writer)?;
        w.finish()
    }

    /// Start writing the output file, with write-to-`.tmp`-and-rename
    /// in the case of the file being on the file system (i.e. no stdout).
    ///
    /// Returns a [`Writing`], which implements `io::Write` -
    /// but usually it's better to use [`Writing::append_with`]
    /// since that automatically converts errors to a nice `CliError`.
    ///
    /// When the output is complete, you *must* call [`Writing::finish`]
    /// to install the output file.
    ///
    /// If `Writing` is dropped, we leave the `.tmp` file lying about.
    /// See [`FilenameOrStdio::write`] for more information.
    ///
    /// Makes no attempt to preserve file permissions.
    pub(super) fn start_writing(&self) -> Result<Writing, CliError> {
        match self {
            FilenameOrStdio::Stdio => {
                //
                Ok(Writing {
                    handle: Box::new(io::stdout().lock()),
                    files: None,
                })
            }
            FilenameOrStdio::Path(main) => {
                let tmp = format!("{main}.tmp");
                let f = File::create(&tmp)
                    .with_context(|| format!("create {tmp:?}"))
                    .map_err(convert_output_error)?;
                let f = BufWriter::new(f);
                Ok(Writing {
                    handle: Box::new(f),
                    files: Some(WritingFiles {
                        tmp,
                        main: main.clone(),
                    }),
                })
            }
        }
    }
}

impl io::Write for Writing {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.handle.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}

impl Writing {
    /// Write to an output file, with a `dyn io::Write`, handling errors
    ///
    /// Calls `writer(self)` but converts the error into a nice `CliError`
    pub(super) fn append_with<W>(&mut self, writer: W) -> Result<(), CliError>
    where
        W: FnOnce(&mut dyn io::Write) -> io::Result<()>,
    {
        writer(self).map_err(self.handle_write_error())
    }

    /// Finish writing and install the output file
    pub(super) fn finish(mut self) -> Result<(), CliError> {
        self.flush().map_err(self.handle_write_error())?;

        if let Some(WritingFiles { main, tmp }) = &self.files {
            fs::rename(tmp, main)
                .with_context(|| format!("install {tmp:?} as {main:?}"))
                .map_err(convert_output_error)?;
        }

        Ok(())
    }

    /// Helper to handle errors from `io::Write::write` and `flush`
    fn handle_write_error(&self) -> impl FnOnce(io::Error) -> CliError {
        let msg = self
            .files
            .as_ref()
            .map(|files| format!("write to {:?}", files.tmp))
            .unwrap_or("write to stdout".into());
        move |e| convert_output_error(anyhow::Error::from(e).context(msg))
    }
}

/// Helper to convert an error encountered while writing to CliError
fn convert_output_error(e: anyhow::Error) -> CliError {
    CliError::OperationalError(e.context("write output"))
}
