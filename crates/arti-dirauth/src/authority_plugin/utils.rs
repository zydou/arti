//! Utilities

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read as _, Write as _};
use std::str::FromStr;

use anyhow::anyhow;

use super::*;

define_derive_deftly! {
    /// Define `fn new`
    ///
    /// # Field attributes
    ///
    ///  * `#[deftly(new(arg))]`: this field should be an argument to `new`.
    ///    If not specified, `Default` is used.
    //
    // TODO enhance documentation and promote somewhere?
    // tor_netdoc::Constructor is not suitable because all the fields would have to be pub(crate)
    // derive_more::Constructor is not suitable because it can't Default fields
    New beta_deftly:

    ${defcond ARG fmeta(new(arg))}

    $impl {
        $/// Make a new `$tname`
        $tvis fn new(
            $(
                ${when ARG}
                $fname: $ftype,
            )
        ) -> Self {
            $tname {
                $(
                    $fname
                    ${if not(ARG) {
                        : Default::default()
                    }},
                )
            }
        }
    }
}

/// Command line filename argument, allowing `-` for stdin/stdout
///
/// Doesn't implement `Display`; for content error reporting prefer
/// [`Reading::description`].
//
// TODO move this somewhere deeper in the stack (tor-basic-utils even maybe?)
// and replace open-coding in eg crates/arti/src/subcommands/hsc.rs display_service_discovery_key
// If we do that:
//   - consider whether we should preserve file permissions
//   - see the comment about leftover `.tmp` files in `write`, below
//   - fix the locking problem (see the two TODO locking/hang)
#[derive(Debug, Clone)]
pub(super) enum FilenameOrStdio {
    /// Filename
    Path(String),
    /// `-`
    Stdio,
}

/// Output file currently being read from
///
/// See [`FilenameOrStdio::start_reading`].
#[derive(Educe)]
#[educe(Debug)]
pub(super) struct Reading {
    /// Actual open-file
    #[educe(Debug(ignore))]
    handle: io::BufReader<Box<dyn io::Read>>,
    /// Description (for error messages), already quoted
    description: String,
}

/// Output file currently being written to
///
/// See [`FilenameOrStdio::start_writing`].
#[derive(Educe)]
#[educe(Debug)]
pub(super) struct Writing {
    /// Actual open-file
    #[educe(Debug(ignore))]
    handle: io::BufWriter<Box<dyn io::Write>>,
    /// Filenames
    files: Option<WritingFiles>,
}

/// Filenames when writing an output file
#[derive(Debug)]
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
                    // TODO locking/hang
                    //
                    // If multiple `FilenameOrStdio`s referring to stdin/stdout are
                    // used simultaneously (rather than sequentially), this will hang.
                    //
                    // Eg, `compute-mds --mds-out - --meta-out -` will hang.
                    //
                    // Unfortunately there is no `.try_lock()`.  We could have a private
                    // global lock to detect this situation.  That seems overkill for
                    // the dirauth plugin, but ought to be done before these routines
                    // are promoted to general utilities.
                    handle: BufWriter::new(Box::new(io::stdout().lock())),
                    files: None,
                })
            }
            FilenameOrStdio::Path(main) => {
                let tmp = format!("{main}.tmp");
                let f = File::create(&tmp)
                    .with_context(|| format!("create {tmp:?}"))
                    .map_err(convert_output_error)?;
                Ok(Writing {
                    handle: BufWriter::new(Box::new(f)),
                    files: Some(WritingFiles {
                        tmp,
                        main: main.clone(),
                    }),
                })
            }
        }
    }

    /// Start reading this input file
    pub(super) fn start_reading(&self) -> Result<Reading, CliError> {
        let (handle, description);
        match self {
            FilenameOrStdio::Stdio => {
                // TODO locking/hang, see above
                handle = Box::new(io::stdin().lock()) as _;
                description = "<stdin>".into();
            }
            FilenameOrStdio::Path(path) => {
                handle = Box::new(
                    File::open(path)
                        .with_context(|| format!("open input file {path:?}"))
                        .map_err(CliError::OperationalError)?,
                ) as _;
                description = format!("{path:?}");
            }
        }
        let handle = BufReader::new(handle);
        Ok(Reading {
            handle,
            description,
        })
    }
}

impl io::Read for Reading {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }
}

impl io::BufRead for Reading {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.handle.fill_buf()
    }
    #[allow(clippy::semicolon_if_nothing_returned)] // more consistent without the ;
    fn consume(&mut self, n: usize) {
        self.handle.consume(n)
    }
}

impl Reading {
    /// Reads the whole file into memory as a `String`
    ///
    /// Non-UTF-8 input is treated as an operational error, just like an io error.
    pub(crate) fn read_entire_string(mut self) -> Result<String, CliError> {
        let mut s = String::new();
        self.handle
            .read_to_string(&mut s)
            .map_err(self.handle_read_error())?;
        Ok(s)
    }

    /// Provide a human-readable description of what this is (eg for error reporting)
    pub(crate) fn description(&self) -> &str {
        &self.description
    }

    /// Returns an error handler for IO errors from this input file
    pub(crate) fn handle_read_error(&self) -> impl FnOnce(io::Error) -> CliError {
        let m = format!("error reading {}", self.description);
        move |e| CliError::OperationalError(anyhow::Error::from(e).context(m))
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

/// A network document, but possibly preceded by C Tor `@`-annotation(s)
///
/// Parsing adapter wrapper.
///
/// Implements `NetdocParseable`: discards any annotations,
/// and then parses `D`.
pub(crate) struct CTorAnnotated<D>(pub(crate) D);

impl<D: NetdocParseable> NetdocParseable for CTorAnnotated<D> {
    fn doctype_for_error() -> &'static str {
        D::doctype_for_error()
    }
    fn is_intro_item_keyword(kw: tor_netdoc::parse2::KeywordRef<'_>) -> bool {
        D::is_intro_item_keyword(kw)
    }
    fn is_structural_keyword(
        kw: tor_netdoc::parse2::KeywordRef<'_>,
    ) -> Option<parse2::IsStructural> {
        D::is_structural_keyword(kw)
    }
    fn from_items(
        input: &mut parse2::ItemStream<'_>,
        stop_at: tor_netdoc::stop_at!(),
    ) -> Result<Self, parse2::ErrorProblem> {
        input.with_inner_lines_mut(|lines| {
            while let Some(peeked) = lines.peek() {
                let line = lines.peeked_line(&peeked);
                if !line.starts_with('@') {
                    break;
                }
                let _: &str = lines.next().expect("just peeked");
            }
        });
        D::from_items(input, stop_at).map(CTorAnnotated)
    }
}
