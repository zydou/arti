//! Facility for detecting and preventing replays on introduction requests.
//!
//! If we were to permit the introduction point to replay the same request
//! multiple times, it would cause the service to contact the rendezvous point
//! again with the same rendezvous cookie as before, which could help with
//! traffic analysis.
//!
//! (This could also be a DoS vector if the introduction point decided to
//! overload the service.)
//!
//! Because we use the same introduction point keys across restarts, we need to
//! make sure that our replay logs are already persistent.  We do this by using
//! a file on disk.

use fslock::LockFile;
use hash::{hash, H, HASH_LEN};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};
use tor_cell::relaycell::msg::Introduce2;

/// A probabilistic data structure to record fingerprints of observed Introduce2
/// messages.
///
/// We need to record these fingerprints to prevent replay attacks; see the
/// module documentation for an explanation of why that would be bad.
///
/// A ReplayLog should correspond to a `KP_hss_ntor` key, and should have the
/// same lifespan: dropping it sooner will enable replays, but dropping it later
/// will waste disk and memory.
///
/// False positives are allowed, to conserve on space.
pub(crate) struct ReplayLog {
    /// The inner probabilistic data structure.
    seen: data::Filter,
    /// Persistent state file etc., if we're persistent
    ///
    /// If is is `None`, this RelayLog is ephemeral.
    file: Option<PersistFile>,
}

/// Persistent state file, and associated data
///
/// Stored as `ReplayLog.file`.
#[derive(Debug)]
pub(crate) struct PersistFile {
    /// A file logging fingerprints of the messages we have seen.
    file: BufWriter<File>,
    /// Whether we had a possible partial write
    ///
    /// See the comment inside [`ReplayLog::check_inner`].
    /// `Ok` means all is well.
    /// `Err` means we may have written partial data to the actual file,
    /// and need to make sure we're back at a record boundary.
    needs_resynch: Result<(), ()>,
    /// Filesystem lock which must not be released until after we finish writing
    ///
    /// Must come last so that the drop order is correct
    #[allow(dead_code)] // Held just so we unlock on drop
    lock: Arc<LockFile>,
}

/// A magic string that we put at the start of each log file, to make sure that
/// we don't confuse this file format with others.
const MAGIC: &[u8; 32] = b"<tor hss replay Kangaroo12>\n\0\0\0\0";

impl ReplayLog {
    /// Create a new ReplayLog not backed by any data storage.
    #[allow(dead_code)] // TODO #1186 Remove once something uses ReplayLog.
    pub(crate) fn new_ephemeral() -> Self {
        Self {
            seen: data::Filter::new(),
            file: None,
        }
    }
    /// Create a ReplayLog backed by the file at a given path.
    ///
    /// If the file already exists, load its contents and append any new
    /// contents to it; otherwise, create the file.
    ///
    /// **`lock` must already have been locked** and this
    /// *cannot be assured by the type system*.
    ///
    /// # Limitations
    ///
    /// It is the caller's responsibility to make sure that there are never two
    /// `ReplayLogs` open at once for the same path, or for two paths that
    /// resolve to the same file.
    pub(crate) fn new_logged(path: impl AsRef<Path>, lock: Arc<LockFile>) -> io::Result<Self> {
        let mut file = {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);

            #[cfg(target_family = "unix")]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }

            options.open(path)?
        };

        // If the file is new, we need to write the magic string. Else we must
        // read it.
        let file_len = file.metadata()?.len();
        if file_len == 0 {
            file.write_all(MAGIC)?;
        } else {
            let mut m = [0_u8; MAGIC.len()];
            file.read_exact(&mut m)?;
            if &m != MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    LogContentError::UnrecognizedFormat,
                ));
            }

            Self::truncate_to_multiple(&mut file, file_len)?;
        }

        // Now read the rest of the file.
        let mut seen = data::Filter::new();
        let mut r = BufReader::new(file);
        loop {
            let mut h = [0_u8; HASH_LEN];
            match r.read_exact(&mut h) {
                Ok(()) => {
                    let _ = seen.test_and_add(&H(h)); // ignore error.
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        let mut file = r.into_inner();
        file.seek(SeekFrom::End(0))?;

        let file = PersistFile {
            file: BufWriter::new(file),
            needs_resynch: Ok(()),
            lock,
        };

        Ok(Self {
            seen,
            file: Some(file),
        })
    }

    /// Truncate `file` to contain a whole number of records
    ///
    /// `current_len` should have come from `file.metadata()`.
    // If the file's length is not an even multiple of HASH_LEN after the MAGIC, truncate it.
    fn truncate_to_multiple(file: &mut File, current_len: u64) -> io::Result<()> {
        let excess = (current_len - MAGIC.len() as u64) % (HASH_LEN as u64);
        if excess != 0 {
            file.set_len(current_len - excess)?;
        }
        Ok(())
    }

    /// Test whether we have already seen `introduce`.
    ///
    /// If we have seen it, return `Err(ReplayError::AlreadySeen)`.  (Since this
    /// is a probabilistic data structure, there is a chance of returning this
    /// error even if we have we have _not_ seen this particular message)
    ///
    /// Otherwise, return `Ok(())`.
    pub(crate) fn check_for_replay(&mut self, introduce: &Introduce2) -> Result<(), ReplayError> {
        let h = hash(
            // This line here is really subtle!  The decision of _what object_
            // to check for replays is critical to making sure that the
            // introduction point cannot do replays by modifying small parts of
            // the replayed object.  So we don't check the header; instead, we
            // check the encrypted body.  This in turn works only because the
            // encryption format is non-malleable: modifying the encrypted
            // message has negligible probability of making a message that can
            // be decrypted.
            //
            // (Ancient versions of onion services used a malleable encryption
            // format here, which made replay detection even harder.
            // Fortunately, we don't have that problem in the current protocol)
            introduce.encrypted_body(),
        );
        self.check_inner(&h)
    }

    /// Implementation helper: test whether we have already seen `h`.
    ///
    /// Return values are as for `check_for_replay`
    fn check_inner(&mut self, h: &H) -> Result<(), ReplayError> {
        self.seen.test_and_add(h)?;
        if let Some(f) = self.file.as_mut() {
            (|| {
                // If write_all fails, it might have written part of the data;
                // in that case, we must truncate the file to resynchronise.
                // We set a note to truncate just before we call write_all
                // and clear it again afterwards.
                //
                // But, first, we need to deal with any previous note we left ourselves.

                // (With the current implementation of std::io::BufWriter, this is
                // unnecessary, because if the argument to write_all is smaller than
                // the buffer size, BufWriter::write_all always just copies to the buffer,
                // flushing first if necessary; and when it flushes, it uses write,
                // not write_all.  So the use of write_all never causes "lost" data.
                // However, this is not a documented guarantee.)
                match f.needs_resynch {
                    Ok(()) => {}
                    Err(()) => {
                        // We're going to reach behind the BufWriter, so we need to make
                        // sure it's in synch with the underlying File.
                        f.file.flush()?;
                        let inner = f.file.get_mut();
                        let len = inner.metadata()?.len();
                        Self::truncate_to_multiple(inner, len)?;
                        // cursor is now past end, must reset (see std::fs::File::set_len)
                        inner.seek(SeekFrom::End(0))?;
                    }
                }
                f.needs_resynch = Err(());

                f.file.write_all(&h.0[..])?;

                f.needs_resynch = Ok(());

                Ok(())
            })()
            .map_err(|e| ReplayError::Log(Arc::new(e)))?;
        }
        Ok(())
    }

    /// Flush any buffered data to disk.
    #[allow(dead_code)] // TODO #1208
    pub(crate) fn flush(&mut self) -> Result<(), io::Error> {
        if let Some(f) = self.file.as_mut() {
            f.file.flush()?;
        }
        Ok(())
    }
}

/// Implementation code for pre-hashing our inputs.
///
/// We do this because we don't actually want to record the entirety of each
/// encrypted introduction request.
///
/// We aren't terribly concerned about collision resistance: accidental
/// collision don't matter, since we are okay with a false-positive rate.
/// Intentional collisions are also okay, since the only impact of generating
/// one would be that you could make an introduce2 message _of your own_ get
/// rejected.
///
/// The impact of preimages is also not so bad. If somebody can reconstruct the
/// original message, they still get an encrypted object, and need the
/// `KP_hss_ntor` key to do anything with it. A second preimage attack just
/// gives another message we won't accept.
mod hash {
    /// Length of the internal hash.
    ///
    /// We only keep 128 bits; see note above in the module documentation about why
    /// this is okay.
    pub(super) const HASH_LEN: usize = 16;

    /// The hash of an input.
    pub(super) struct H(pub(super) [u8; HASH_LEN]);

    /// Compute a hash from a given bytestring.
    pub(super) fn hash(s: &[u8]) -> H {
        // I'm choosing kangaroo-twelve for its speed. This doesn't affect
        // compatibility, so it's okay to use something a bit odd, since we can
        // change it later if we want.
        use digest::{ExtendableOutput, Update};
        use k12::KangarooTwelve;
        let mut d = KangarooTwelve::default();
        let mut output = H([0; HASH_LEN]);
        d.update(s);
        d.finalize_xof_into(&mut output.0);
        output
    }
}

/// Wrapper around a fast-ish data structure for detecting replays with some
/// false positive rate.  Bloom filters, cuckoo filters, and xorf filters are all
/// an option here.  You could even use a HashSet.
///
/// We isolate this code to make it easier to replace.
mod data {
    use super::ReplayError;
    use growable_bloom_filter::GrowableBloom;

    /// A probabilistic membership filter.
    pub(super) struct Filter(pub(crate) GrowableBloom);

    impl Filter {
        /// Create a new empty filter
        pub(super) fn new() -> Self {
            // TODO: Perhaps we should make the capacity here tunable, based on
            // the number of entries we expect.  These values are more or less
            // pulled out of thin air.
            let desired_error_prob = 1.0 / 100_000.0;
            let est_insertions = 100_000;
            Filter(GrowableBloom::new(desired_error_prob, est_insertions))
        }
        /// Try to add `h` to this filter if it isn't already there.
        ///
        /// Return Ok(()) or Err(AlreadySeen).
        pub(super) fn test_and_add(&mut self, h: &super::H) -> Result<(), ReplayError> {
            if self.0.insert(&h.0[..]) {
                Ok(())
            } else {
                Err(ReplayError::AlreadySeen)
            }
        }
    }
}

/// A problem that prevents us from reading a ReplayLog from disk.
///
/// (This only exists so we can wrap it up in an [`io::Error`])
#[derive(thiserror::Error, Clone, Debug)]
enum LogContentError {
    /// The magic number on the log file was incorrect.
    #[error("unrecognized data format")]
    UnrecognizedFormat,
}

/// An error occurred while checking whether we've seen an element before.
#[derive(thiserror::Error, Clone, Debug)]
pub(crate) enum ReplayError {
    /// We have already seen this item.
    #[error("Already seen")]
    AlreadySeen,

    /// We were unable to record this item in the log.
    #[error("Unable to log data")]
    Log(Arc<std::io::Error>),
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::path::PathBuf;

    use super::*;
    use crate::test_temp_dir;
    use crate::test_temp_dir::{TestTempDir, TestTempDirGuard};
    use rand::Rng;

    fn rand_h<R: Rng>(rng: &mut R) -> H {
        H(rng.gen())
    }

    #[test]
    fn hash_basics() {
        let a = hash(b"123");
        let b = hash(b"123");
        let c = hash(b"1234");
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
    }

    /// Basic tests on an ephemeral ReplayLog.
    #[test]
    fn simple_usage() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();

        let mut log = ReplayLog::new_ephemeral();
        // Add everything in group 1.
        for h in &group_1 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
        // Make sure that everything in group 1 is still there.
        for h in &group_1 {
            assert!(log.check_inner(h).is_err());
        }
        // Make sure that group 2 is detected as not-there.
        for h in &group_2 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
    }

    const TEST_TEMP_SUBDIR: &str = "replaylog";

    fn create_logged(dir: &TestTempDir) -> TestTempDirGuard<ReplayLog> {
        dir.subdir_used_by(TEST_TEMP_SUBDIR, |dir| {
            let lock = LockFile::open(&dir.join("lock")).unwrap();
            // Really ReplayLog::new should take a lock file type that guarantees the
            // returned value has actually been locked.  But it doesn't.  Because
            // the LockFile API is defective and doesn't provide such a type.
            // So, we can skip actually locking, in these tests...
            let p: PathBuf = dir.join("logfile");
            ReplayLog::new_logged(p, Arc::new(lock)).unwrap()
        })
    }

    /// Basic tests on an persistent ReplayLog.
    #[test]
    fn logging_basics() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();

        let dir = test_temp_dir!();
        let mut log = create_logged(&dir);
        // Add everything in group 1, then close and reload.
        for h in &group_1 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure everything in group 1 is still there.
        for h in &group_1 {
            assert!(log.check_inner(h).is_err());
        }
        // Now add everything in group 2, then close and reload.
        for h in &group_2 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure that groups 1 and 2 are still there.
        for h in group_1.iter().chain(group_2.iter()) {
            assert!(log.check_inner(h).is_err());
        }
    }

    /// Test for a log that gets truncated mid-write.
    #[test]
    fn test_truncated() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_h(&mut rng)).collect();

        let dir = test_temp_dir!();
        let mut log = create_logged(&dir);
        for h in &group_1 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
        drop(log);
        // Truncate the file by 7 bytes.
        dir.subdir_used_by(TEST_TEMP_SUBDIR, |dir| {
            let file = OpenOptions::new()
                .write(true)
                .open(dir.join("logfile"))
                .unwrap();
            // Make sure that the file has the length we expect.
            let expected_len = MAGIC.len() + HASH_LEN * group_1.len();
            assert_eq!(expected_len as u64, file.metadata().unwrap().len());
            file.set_len((expected_len - 7) as u64).unwrap();
        });
        // Now, reload the log. We should be able to recover every non-truncated
        // item...
        let mut log = create_logged(&dir);
        for h in &group_1[..group_1.len() - 1] {
            assert!(log.check_inner(h).is_err());
        }
        // But not the last one, which we truncated.  (Checking will add it, though.)
        assert!(
            log.check_inner(&group_1[group_1.len() - 1]).is_ok(),
            "False positive"
        );
        // Now add everything in group 2, then close and reload.
        for h in &group_2 {
            assert!(log.check_inner(h).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure that groups 1 and 2 are still there.
        for h in group_1.iter().chain(group_2.iter()) {
            assert!(log.check_inner(h).is_err());
        }
    }

    /// Test for a partial write
    #[test]
    #[cfg(target_family = "unix")] // no idea how to do elsewhere, hopefully this is enough
    fn test_partial_write() {
        use std::env;
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        // TODO this contraption should perhaps be productised and put somewhere else

        const ENV_NAME: &str = "TOR_HSSERVICE_TEST_PARTIAL_WRITE_SUBPROCESS";
        // for a wait status different from any of libtest's
        const GOOD_SIGNAL: i32 = libc::SIGUSR2;

        match env::var(ENV_NAME) {
            Err(env::VarError::NotPresent) => {
                eprintln!("in test runner process, forking..,");
                let st = Command::new(env::current_exe().unwrap())
                    .args(["--nocapture", "replay::test::test_partial_write"])
                    .env(ENV_NAME, "1")
                    .status()
                    .unwrap();
                eprintln!("reaped actual test process {st:?} (expecting signal {GOOD_SIGNAL})");
                assert_eq!(st.signal(), Some(GOOD_SIGNAL));
                return;
            }
            Ok(y) if y == "1" => {}
            other => panic!("bad env var {ENV_NAME:?} {other:?}"),
        };

        // Now we are in our own process, and can mess about with ulimit etc.

        use std::fs;
        use std::mem::MaybeUninit;
        use std::ptr;

        fn set_ulimit(size: usize) {
            unsafe {
                const RLIM: libc::__rlimit_resource_t = libc::RLIMIT_FSIZE;
                let mut rlim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let r = libc::getrlimit(RLIM, (&mut rlim) as _);
                assert_eq!(r, 0);
                rlim.rlim_cur = size.try_into().unwrap();
                let r = libc::setrlimit(RLIM, (&rlim) as _);
                assert_eq!(r, 0);
            }
        }

        // This test is quite complicated.
        //
        // We want to test partial writes.  We could perhaps have done this by
        // parameterising ReplayLog so it could have something other than File,
        // but that would probably leak into the public API.
        //
        // Instead, we cause *actual* partial writes.  We use the Unix setrlimit
        // call to limit the size of files our process is allowed to write.
        // This causes the underlying write(2) calls to (i) generate SIGXFSZ
        // (ii) if that doesn't kill the process, return partial writes.

        test_temp_dir!().used_by(|dir| {
            let path = dir.join("test.log");
            let mut lock = fslock::LockFile::open(&dir.join("dummy.lock")).unwrap();
            lock.lock().unwrap(); // for form's sake, we don't really need this
            let lock = Arc::new(lock);
            let mut rl = ReplayLog::new_logged(&path, lock.clone()).unwrap();

            const BUF: usize = 8192; // BufWriter default; if that changes, test will break

            // We let ourselves write one whole buffer plus an odd amount of extra
            const ALLOW: usize = BUF + 37;

            // Ignore SIGXFSZ (default disposition is for exceeding the rlimit to kill us)
            unsafe {
                let mut set = MaybeUninit::uninit();
                libc::sigemptyset(set.as_mut_ptr());
                let sa = libc::sigaction {
                    sa_sigaction: libc::SIG_IGN,
                    sa_mask: set.assume_init(),
                    sa_flags: 0,
                    sa_restorer: None,
                };
                let r = libc::sigaction(libc::SIGXFSZ, (&sa) as _, ptr::null_mut());
                assert_eq!(r, 0);
            }

            let demand_efbig = |e| match e {
                // MSRV:: io::ErrorKind::FileTooLarge is still unstable
                ReplayError::Log(e) if e.raw_os_error() == Some(libc::EFBIG) => {}
                other => panic!("expected EFBUG, got {other:?}"),
            };

            // Generate a distinct Hash given a phase and a counter
            #[allow(clippy::identity_op)]
            let mk_h = |phase: u8, i: usize| {
                let i = u32::try_from(i).unwrap();
                let mut h = [0_u8; HASH_LEN];
                h[0] = phase;
                h[1] = phase;
                h[4] = (i >> 24) as _;
                h[5] = (i >> 16) as _;
                h[6] = (i >> 8) as _;
                h[7] = (i >> 0) as _;
                H(h)
            };

            // Number of hashes we can write to the file before failure occurs
            const CAN_DO: usize = (ALLOW + BUF - MAGIC.len()) / HASH_LEN;
            dbg!(MAGIC.len(), HASH_LEN, BUF, ALLOW, CAN_DO);

            // Record of the hashes that ReplayLog tells us were OK and not replays;
            // ie, which it therefore ought to have recorded.
            let mut gave_ok = Vec::new();

            set_ulimit(ALLOW);

            for i in 0..CAN_DO {
                let h = mk_h(b'y', i);
                rl.check_inner(&h).unwrap();
                gave_ok.push(h);
            }

            let md = fs::metadata(&path).unwrap();
            dbg!(md.len(), &rl.file);

            // Now we have written what we can.  The next two calls will fail,
            // since the BufWriter buffer is full and can't be flushed.

            for i in 0..2 {
                eprintln!("expecting EFBIG {i}");
                demand_efbig(rl.check_inner(&mk_h(b'n', i)).unwrap_err());
                let md = fs::metadata(&path).unwrap();
                assert_eq!(md.len(), u64::try_from(ALLOW).unwrap());
            }

            // Enough that we don't get any further file size exceedances
            set_ulimit(ALLOW * 10);

            // Now we should be able to recover.  We write two more hashes.
            for i in 0..2 {
                eprintln!("recovering {i}");
                let h = mk_h(b'r', i);
                rl.check_inner(&h).unwrap();
                gave_ok.push(h);
            }

            // flush explicitly just so we catch any error
            // (drop would flush, but it can't report errors)
            rl.flush().unwrap();
            drop(rl);

            // Reopen the log - reading in the written data.
            // We can then check that everything the earlier ReplayLog
            // claimed to have written, is indeed recorded.

            let mut rl = ReplayLog::new_logged(&path, lock.clone()).unwrap();
            for h in &gave_ok {
                match rl.check_inner(h) {
                    Err(ReplayError::AlreadySeen) => {}
                    other => panic!("expected AlreadySeen, got {other:?}"),
                }
            }

            eprintln!("recovered file contents checked, all good");
        });

        unsafe {
            libc::raise(libc::SIGUSR2);
        }
        panic!("we survived raise SIGUSR2");
    }
}
