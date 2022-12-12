//! The Report type which reports errors nicely

use std::error::Error as StdError;
use std::fmt::{self, Debug, Display};

/// Wraps any Error, providing a nicely-reporting Display impl
#[derive(Debug, Copy, Clone)]
#[allow(clippy::exhaustive_structs)] // this is a transparent wrapper
pub struct Report<E>(pub E)
where
    E: AsRef<dyn StdError>;

impl<E> Display for Report<E>
where
    E: AsRef<dyn StdError>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Non-generic inner function avoids code bloat
        fn inner(mut e: &dyn StdError, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "error")?;
            let mut last = String::new();
            loop {
                let this = e.to_string();
                if !last.contains(&this) {
                    write!(f, ": {}", &this)?;
                }
                last = this;

                if let Some(ne) = e.source() {
                    e = ne;
                } else {
                    break;
                }
            }
            Ok(())
        }

        inner(self.0.as_ref(), f)
    }
}

/// Report the error E to stderr, and exit the program
///
/// Does not return.  Return type is any type R, for convenience with eg `unwrap_or_else`.
#[allow(clippy::print_stderr)] // this is the point of this function
pub fn report_and_exit<E, R>(e: E) -> R
where
    E: AsRef<dyn StdError>,
{
    /// Non-generic inner function avoids code bloat
    fn eprint_progname() {
        if let Some(progname) = std::env::args().next() {
            eprint!("{}: ", progname);
        }
    }

    eprint_progname();
    eprintln!("{}", Report(e));
    std::process::exit(127)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io;
    use thiserror::Error;

    #[derive(Error, Debug)]
    #[error("terse")]
    struct TerseError {
        #[from]
        source: Box<dyn StdError>,
    }

    #[derive(Error, Debug)]
    #[error("verbose - {source}")]
    struct VerboseError {
        #[from]
        source: Box<dyn StdError>,
    }

    #[derive(Error, Debug)]
    #[error("shallow")]
    struct ShallowError;

    fn chk<E: StdError + 'static>(e: E, expected: &str) {
        let e: Box<dyn StdError> = Box::new(e);
        let got = Report(&e).to_string();
        assert_eq!(got, expected, "\nmismatch: {:?}", &e);
    }

    #[test]
    #[rustfmt::skip] // preserve layout of chk calls
    fn test() {
        chk(ShallowError,
            "error: shallow");

        let terse_1 = || TerseError { source: ShallowError.into() };
        chk(terse_1(),
            "error: terse: shallow");

        let verbose_1 = || VerboseError { source: ShallowError.into() };
        chk(verbose_1(),
            "error: verbose - shallow");

        chk(VerboseError { source: terse_1().into() },
            "error: verbose - terse: shallow");

        chk(TerseError { source: verbose_1().into() },
            "error: terse: verbose - shallow");

        chk(io::Error::new(io::ErrorKind::Other, ShallowError),
            "error: shallow");
    }
}
