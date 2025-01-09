//! Support for cookie authentication within the RPC protocol.
use fs_mistrust::Mistrust;
use safelog::Sensitive;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};
use subtle::ConstantTimeEq as _;
use tiny_keccak::Hasher as _;
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

/// Customization string used to initialize TupleHash.
const TUPLEHASH_CUSTOMIZATION: &[u8] = b"arti-rpc-cookie-v1";

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
        let cookie = Self::new(rng);
        file.write_all(&COOKIE_PREFIX[..])?;
        file.write_all(cookie.value.as_inner().as_ref())?;

        Ok(cookie)
    }

    /// Create a new random cookie.
    fn new<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut cookie = Cookie {
            value: Default::default(),
        };
        rng.fill_bytes(cookie.value.as_mut().as_mut());
        cookie
    }

    /// Return an appropriately personalized TupleHash instance, keyed from this cookie.
    fn new_mac(&self) -> tiny_keccak::TupleHash {
        let mut mac = tiny_keccak::TupleHash::v128(TUPLEHASH_CUSTOMIZATION);
        mac.update(&**self.value);
        mac
    }

    /// Compute the "server_mac" value as in the RPC cookie authentication protocol.
    pub fn server_mac(
        &self,
        client_nonce: &CookieAuthNonce,
        socket_canonical: &str,
    ) -> CookieAuthMac {
        // `server_mac = MAC(cookie, "Server", socket_canonical, client_nonce)`
        let mut mac = self.new_mac();
        mac.update(b"Server");
        mac.update(socket_canonical.as_bytes());
        mac.update(&**client_nonce.0);
        CookieAuthMac::finalize_from(mac)
    }

    /// Compute the "client_mac" value as in the RPC cookie authentication protocol.
    pub fn client_mac(
        &self,
        server_nonce: &CookieAuthNonce,
        socket_canonical: &str,
    ) -> CookieAuthMac {
        // `client_mac = MAC(cookie, "Client", socket_canonical, server_nonce)`
        let mut mac = self.new_mac();
        mac.update(b"Client");
        mac.update(socket_canonical.as_bytes());
        mac.update(&**server_nonce.0);
        CookieAuthMac::finalize_from(mac)
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

/// The location of a cookie on disk, and the rules to access it.
#[derive(Debug, Clone)]
pub struct CookieLocation {
    /// Where the cookie is on disk.
    pub(crate) path: PathBuf,
    /// The mistrust we should use when loading it.
    pub(crate) mistrust: Mistrust,
}

impl CookieLocation {
    #[cfg(feature = "rpc-client")]
    /// Try to read the cookie at this location.
    pub fn load(&self) -> Result<Cookie, CookieAccessError> {
        Cookie::load(self.path.as_ref(), &self.mistrust)
    }
}

/// An error when decoding a hexadecimal value.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HexError {
    /// Hexadecimal value was wrong, or had the wrong length.
    #[error("Invalid hexadecimal value")]
    InvalidHex,
}

/// A random nonce used during cookie authentication protocol.
#[derive(Clone, Debug)]
pub struct CookieAuthNonce(Sensitive<Zeroizing<[u8; 32]>>);
impl CookieAuthNonce {
    /// Create a new random nonce.
    pub fn new<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        let mut nonce = Self(Default::default());
        rng.fill_bytes(nonce.0.as_mut().as_mut());
        nonce
    }
    /// Convert this nonce to a hexadecimal string.
    pub fn to_hex(&self) -> String {
        base16ct::upper::encode_string(&**self.0)
    }
    /// Decode a nonce from a hexadecimal string.
    ///
    /// (Case-insensitive, no leading "0x" marker.  Output must be COOKIE_LEN bytes long.)
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        let mut nonce = Self(Default::default());
        base16ct::mixed::decode(s, nonce.0.as_mut()).map_err(|_| HexError::InvalidHex)?;
        Ok(nonce)
    }
}

/// A MAC derived during the cookie authentication protocol.
#[derive(Clone, Debug)]
pub struct CookieAuthMac(Sensitive<Zeroizing<[u8; 32]>>);
impl CookieAuthMac {
    /// Construct a MAC by finalizing the provided hasher.
    fn finalize_from(hasher: tiny_keccak::TupleHash) -> Self {
        let mut mac = Self(Default::default());
        hasher.finalize(mac.0.as_mut());
        mac
    }

    /// Convert this MAC to a hexadecimal string.
    pub fn to_hex(&self) -> String {
        base16ct::upper::encode_string(&**self.0)
    }
    /// Decode a MAC from a hexadecimal string.
    ///
    /// (Case-insensitive, no leading "0x" marker.  Output must be COOKIE_LEN bytes long.)
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        let mut mac = Self(Default::default());
        base16ct::mixed::decode(s, mac.0.as_mut()).map_err(|_| HexError::InvalidHex)?;
        Ok(mac)
    }
}
impl PartialEq for CookieAuthMac {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&**other.0).into()
    }
}
impl Eq for CookieAuthMac {}

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

    /// Helper: Compute a TupleHash over the elements in input.
    fn tuplehash(customization: &[u8], input: &[&[u8]]) -> [u8; 32] {
        let mut th = tiny_keccak::TupleHash::v128(customization);
        for v in input {
            th.update(v);
        }
        let mut output: [u8; 32] = Default::default();
        th.finalize(&mut output);
        output
    }

    // Conformance test test for cryptography for cookie auth.
    #[test]
    fn auth_roundtrip() {
        let addr = "127.0.0.1:9999";
        let mut rng = rand::thread_rng();
        let client_nonce = CookieAuthNonce::new(&mut rng);
        let server_nonce = CookieAuthNonce::new(&mut rng);
        let cookie = Cookie::new(&mut rng);

        let smac = cookie.server_mac(&client_nonce, addr);
        let cmac = cookie.client_mac(&server_nonce, addr);

        // `server_mac = MAC(cookie, "Server", socket_canonical, client_nonce)`
        let smac_expected = tuplehash(
            TUPLEHASH_CUSTOMIZATION,
            &[
                &**cookie.value,
                b"Server",
                addr.as_bytes(),
                &**client_nonce.0,
            ],
        );
        // `client_mac = MAC(cookie, "Client", socket_canonical, server_nonce)`
        let cmac_expected = tuplehash(
            TUPLEHASH_CUSTOMIZATION,
            &[
                &**cookie.value,
                b"Client",
                addr.as_bytes(),
                &**server_nonce.0,
            ],
        );
        assert_eq!(**smac.0, smac_expected);
        assert_eq!(**cmac.0, cmac_expected);

        let smac_hex = smac.to_hex();
        let smac2 = CookieAuthMac::from_hex(smac_hex.as_str()).unwrap();
        assert_eq!(smac, smac2);

        assert_ne!(cmac, smac); // Fails with P = 2^256 ;)
    }

    /// Basic tests for tuplehash crate, to make sure it does what we expect.
    #[test]
    fn tuplehash_testvec() {
        // From http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/TupleHash_samples.pdf
        use hex_literal::hex;
        let val = tuplehash(b"", &[&hex!("00 01 02"), &hex!("10 11 12 13 14 15")]);
        assert_eq!(
            val,
            hex!(
                "C5 D8 78 6C 1A FB 9B 82 11 1A B3 4B 65 B2 C0 04
                 8F A6 4E 6D 48 E2 63 26 4C E1 70 7D 3F FC 8E D1"
            )
        );

        let val = tuplehash(
            b"My Tuple App",
            &[&hex!("00 01 02"), &hex!("10 11 12 13 14 15")],
        );
        assert_eq!(
            val,
            hex!(
                "75 CD B2 0F F4 DB 11 54 E8 41 D7 58 E2 41 60 C5
                 4B AE 86 EB 8C 13 E7 F5 F4 0E B3 55 88 E9 6D FB"
            )
        );

        let val = tuplehash(
            b"My Tuple App",
            &[
                &hex!("00 01 02"),
                &hex!("10 11 12 13 14 15"),
                &hex!("20 21 22 23 24 25 26 27 28"),
            ],
        );
        assert_eq!(
            val,
            hex!(
                "E6 0F 20 2C 89 A2 63 1E DA 8D 4C 58 8C A5 FD 07
                 F3 9E 51 51 99 8D EC CF 97 3A DB 38 04 BB 6E 84"
            )
        );
    }
}
