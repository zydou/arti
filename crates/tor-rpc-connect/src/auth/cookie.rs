//! Support for cookie authentication within the RPC protocol.
use fs_mistrust::Mistrust;
use safelog::Sensitive;
use std::{fs, io, path::Path, sync::Arc};
use zeroize::Zeroizing;

/// A secret cookie value, used in RPC authentication.
#[derive(Clone, Debug)]
pub struct Cookie {
    /// The value of the cookie.
    value: Sensitive<Zeroizing<[u8; COOKIE_LEN]>>,
}
impl AsRef<[u8; COOKIE_LEN]> for Cookie {
    fn as_ref(&self) -> &[u8; COOKIE_LEN] {
        self.value.as_inner()
    }
}

/// Length of an authentication cookie.
pub const COOKIE_LEN: usize = 32;

/// Length of `COOKIE_PREFIX`.
pub const COOKIE_PREFIX_LEN: usize = 32;

/// A value used to differentiate cookie files,
/// and as a personalization parameter within the RPC cookie authentication protocol.
///
/// This is equivalent to `P` in the RPC cookie spec.
pub const COOKIE_PREFIX: &[u8; COOKIE_PREFIX_LEN] = b"====== arti-rpc-cookie-v1 ======";

impl Cookie {
    /// Read an RPC cookie from a provided path.
    #[cfg(feature = "rpc-client")]
    pub fn load(path: &Path, mistrust: &Mistrust) -> Result<Cookie, CookieAccessError> {
        use std::io::Read;

        // If this is successful, then we can safely open and read the file without TOCTOU issues.
        mistrust.verifier().check(path)?;

        let mut file = fs::OpenOptions::new().read(true).open(path)?;
        let mut buf = [0_u8; COOKIE_PREFIX_LEN];
        file.read_exact(&mut buf)?;
        if &buf != COOKIE_PREFIX {
            return Err(CookieAccessError::FileFormat);
        }

        let mut cookie = Cookie {
            value: Default::default(),
        };
        file.read_exact(cookie.value.as_mut().as_mut())?;
        if file.read(&mut buf)? != 0 {
            return Err(CookieAccessError::FileFormat);
        }

        Ok(cookie)
    }

    /// Create a new RPC cookie and store it at a provided path,
    /// overwriting any previous file at that location.
    #[cfg(feature = "rpc-server")]
    pub fn create<R: rand::CryptoRng + rand::RngCore>(
        path: &Path,
        rng: &mut R,
        mistrust: &Mistrust,
    ) -> Result<Cookie, CookieAccessError> {
        use std::io::Write;

        // NOTE: We do not use the "write and rename" pattern here,
        // since it doesn't preserve file permissions.
        let parent = path.parent().ok_or(CookieAccessError::UnusablePath)?;
        let dir = mistrust.verifier().make_secure_dir(parent)?;
        // TODO RPC: This doesn't allow the file to be a symlink; we should fix that.
        let mut file = dir.open(
            path.file_name().ok_or(CookieAccessError::UnusablePath)?,
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true),
        )?;
        file.write_all(&COOKIE_PREFIX[..])?;
        let mut cookie = Cookie {
            value: Default::default(),
        };
        rng.fill_bytes(cookie.value.as_mut().as_mut());
        file.write_all(cookie.value.as_inner().as_ref())?;

        Ok(cookie)
    }
}

/// An error that has occurred while trying to load or create a cookie.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CookieAccessError {
    /// Unable to access cookie file due to an error from fs_mistrust
    #[error("Unable to access cookie file")]
    Access(#[from] fs_mistrust::Error),
    /// Unable to access cookie file due to an IO error.
    #[error("IO error while accessing cookie file")]
    Io(#[source] Arc<io::Error>),
    /// Calling `parent()` or `file_name() on the cookie path failed.
    #[error("Could not find parent directory or filename for cookie file")]
    UnusablePath,
    /// Cookie file wasn't in the right format.
    #[error("Path did not point to a cookie file")]
    FileFormat,
}
impl From<io::Error> for CookieAccessError {
    fn from(err: io::Error) -> Self {
        CookieAccessError::Io(Arc::new(err))
    }
}
impl crate::HasClientErrorAction for CookieAccessError {
    fn client_action(&self) -> crate::ClientErrorAction {
        use crate::ClientErrorAction as A;
        use CookieAccessError as E;
        match self {
            E::Access(err) => err.client_action(),
            E::Io(err) => crate::fs_error_action(err.as_ref()),
            E::UnusablePath => A::Decline,
            // Might just not be working; might be different version.
            //
            // TODO RPC: We should revisit this.  The spec says "If the cookie file is malformed,
            // the client also aborts. but this means that the client needs to take measures
            // to ensure that it never reads a partially written cookie file.
            E::FileFormat => A::Decline,
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::testing::tempdir;

    // Simple case: test creating and loading cookies.
    #[test]
    #[cfg(all(feature = "rpc-client", feature = "rpc-server"))]
    fn cookie_file() {
        let (_tempdir, dir, mistrust) = tempdir();
        let path1 = dir.join("foo/foo.cookie");
        let path2 = dir.join("bar.cookie");

        let s_c1 = Cookie::create(path1.as_path(), &mut rand::thread_rng(), &mistrust).unwrap();
        let s_c2 = Cookie::create(path2.as_path(), &mut rand::thread_rng(), &mistrust).unwrap();
        assert_ne!(s_c1.as_ref(), s_c2.as_ref());

        let c_c1 = Cookie::load(path1.as_path(), &mistrust).unwrap();
        let c_c2 = Cookie::load(path2.as_path(), &mistrust).unwrap();
        assert_eq!(s_c1.as_ref(), c_c1.as_ref());
        assert_eq!(s_c2.as_ref(), c_c2.as_ref());
    }
}
