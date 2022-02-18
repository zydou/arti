//! The Report type which reports errors nicely

use std::fmt::{self, Debug, Display};

/// Wraps any Error, providing a nicely-reporting Display impl
#[derive(Debug, Copy, Clone)]
#[allow(clippy::exhaustive_structs)] // this is a transparent wrapper
pub struct Report<E>(pub E);

impl<E> Display for Report<E>
where
    E: AsRef<dyn std::error::Error>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        /// Non-generic inner function avoids code bloat
        fn inner(mut e: &dyn std::error::Error, f: &mut fmt::Formatter) -> fmt::Result {
            if let Some(progname) = std::env::args().next() {
                write!(f, "{}: ", progname)?;
            }
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
#[allow(clippy::print-stderr)] // this is the point of this function
pub fn report_and_exit<E, R>(e: E) -> R
where
    E: AsRef<dyn std::error::Error>,
{
    eprintln!("{}", Report(e));
    std::process::exit(127)
}
