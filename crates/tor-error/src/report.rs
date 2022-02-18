//! The Report type which reports errors nicely

use std::fmt::{self, Debug, Display};

/// Wraps any Error, providing a nicely-reporting Display impl
#[derive(Debug, Copy, Clone)]
pub struct Report<E>(pub E);

impl<E> Display for Report<E> where E: AsRef<dyn std::error::Error> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn inner(mut e: &dyn std::error::Error, f: &mut fmt::Formatter) -> fmt::Result {
            if let Some(progname) = std::env::args().next() {
                write!(f, "{}: ", progname)?;
            }
            write!(f, "error")?;
            let mut last = String::new();
            loop {
                let this = e.to_string();
                if ! last.contains(&this) {
                    write!(f, ": {}", &this)?;
                }
                last = this;

                if let Some(ne) = e.source() {
                    e = ne
                } else {
                    break
                }
            }
            Ok(())
        }

        inner(self.0.as_ref(), f)
    }
}

pub fn report_and_exit<E, R>(e: E) -> R where E: AsRef<dyn std::error::Error> {
    eprintln!("{}", Report(e));
    std::process::exit(127)
}
