//! Helper: A cloneable wrapper for io::Result.
//!
//! This is all necessary because io::Error doesn't implement `Clone`.

use std::{io, sync::Arc};

/// A helper type for a variation on an `io::Error` that we can clone.
pub(crate) type ArcIoResult<R> = Result<R, Arc<io::Error>>;

/// Extension trait for `Result<T, Arc<io::Error>>`
pub(crate) trait ArcIoResultExt<T> {
    /// Create a new `io::Result<T>` from this `ArcIoResult<T>`
    ///
    /// We do this by making a new new io::Error (if necessary)
    /// with [`wrap_error`].
    fn io_result(&self) -> io::Result<T>;
}

impl<T: Clone> ArcIoResultExt<T> for ArcIoResult<T> {
    fn io_result(&self) -> io::Result<T> {
        match &self {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(wrap_error(e)),
        }
    }
}

/// Wrap an Arc<io::Error> as a new io::Error.
pub(crate) fn wrap_error(e: &Arc<io::Error>) -> io::Error {
    io::Error::new(e.kind(), Arc::clone(e))
}
