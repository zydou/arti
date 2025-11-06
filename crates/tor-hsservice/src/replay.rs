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

mod ipt;
#[cfg(feature = "hs-pow-full")]
mod pow;

use crate::internal_prelude::*;

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
pub(crate) struct ReplayLog<T> {
    /// The inner probabilistic data structure.
    seen: data::Filter,
    /// Persistent state file etc., if we're persistent
    ///
    /// If is is `None`, this RelayLog is ephemeral.
    file: Option<PersistFile>,
    /// [`PhantomData`] so rustc doesn't complain about the unused type param.
    ///
    /// This type represents the type of data that we're storing, as well as the type of the
    /// key/name for that data.
    replay_log_type: PhantomData<T>,
}

/// A [`ReplayLog`] for [`Introduce2`](tor_cell::relaycell::msg::Introduce2) messages.
pub(crate) type IptReplayLog = ReplayLog<ipt::IptReplayLogType>;

/// A [`ReplayLog`] for Proof-of-Work [`Nonce`](tor_hscrypto::pow::v1::Nonce)s.
#[cfg(feature = "hs-pow-full")]
pub(crate) type PowNonceReplayLog = ReplayLog<pow::PowNonceReplayLogType>;

/// The length of the [`ReplayLogType::MAGIC`] constant.
///
// TODO: If Rust's constant expressions supported generics we wouldn't need this at all.
const MAGIC_LEN: usize = 32;

/// The length of the message that we store on disk, in bytes.
///
/// If the message is longer than this, then we will need to hash or truncate it before storing it
/// to disk.
///
// TODO: Once const generics are good, this should be a associated constant for ReplayLogType.
pub(crate) const OUTPUT_LEN: usize = 16;

/// A trait to represent a set of types that ReplayLog can be used with.
pub(crate) trait ReplayLogType {
    // TODO: It would be nice to encode the directory name as a associated constant here, rather
    // than having the external code pass it in to us.

    /// The name of this item, used for the log filename.
    type Name;

    /// The type of the messages that we are ensuring the uniqueness of.
    type Message;

    /// A magic string that we put at the start of each log file, to make sure that
    /// we don't confuse this file format with others.
    const MAGIC: &'static [u8; MAGIC_LEN];

    /// Convert [`Self::Name`] to a [`String`]
    fn format_filename(name: &Self::Name) -> String;

    /// Convert [`Self::Message`] to bytes that will be stored in the log.
    fn transform_message(message: &Self::Message) -> [u8; OUTPUT_LEN];

    /// Parse a filename into [`Self::Name`].
    fn parse_log_leafname(leaf: &OsStr) -> Result<Self::Name, Cow<'static, str>>;
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
    /// See the comment inside [`ReplayLog::check_for_replay`].
    /// `Ok` means all is well.
    /// `Err` means we may have written partial data to the actual file,
    /// and need to make sure we're back at a record boundary.
    needs_resynch: Result<(), ()>,
    /// Filesystem lock which must not be released until after we finish writing
    ///
    /// Must come last so that the drop order is correct
    #[allow(dead_code)] // Held just so we unlock on drop
    lock: Arc<LockFileGuard>,
}

/// Replay log files have a `.bin` suffix.
///
/// The name of the file is determined by [`ReplayLogType::format_filename`].
const REPLAY_LOG_SUFFIX: &str = ".bin";

impl<T: ReplayLogType> ReplayLog<T> {
    /// Create a new ReplayLog not backed by any data storage.
    #[allow(dead_code)] // TODO #1186 Remove once something uses ReplayLog.
    pub(crate) fn new_ephemeral() -> Self {
        Self {
            seen: data::Filter::new(),
            file: None,
            replay_log_type: PhantomData,
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
    pub(crate) fn new_logged(
        dir: &InstanceRawSubdir,
        name: &T::Name,
    ) -> Result<Self, OpenReplayLogError> {
        let leaf = T::format_filename(name);
        let path = dir.as_path().join(leaf);
        let lock_guard = dir.raw_lock_guard();

        Self::new_logged_inner(&path, lock_guard).map_err(|error| OpenReplayLogError {
            file: path,
            error: error.into(),
        })
    }

    /// Inner function for `new_logged`, with reified arguments and raw error type
    fn new_logged_inner(path: impl AsRef<Path>, lock: Arc<LockFileGuard>) -> io::Result<Self> {
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
            file.write_all(T::MAGIC)?;
        } else {
            let mut m = [0_u8; MAGIC_LEN];
            file.read_exact(&mut m)?;
            if &m != T::MAGIC {
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
            let mut msg = [0_u8; OUTPUT_LEN];
            match r.read_exact(&mut msg) {
                Ok(()) => {
                    let _ = seen.test_and_add(&msg); // ignore error.
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
            replay_log_type: PhantomData,
        })
    }

    /// Truncate `file` to contain a whole number of records
    ///
    /// `current_len` should have come from `file.metadata()`.
    // If the file's length is not an even multiple of MESSAGE_LEN after the MAGIC, truncate it.
    fn truncate_to_multiple(file: &mut File, current_len: u64) -> io::Result<()> {
        let excess = (current_len - T::MAGIC.len() as u64) % (OUTPUT_LEN as u64);
        if excess != 0 {
            file.set_len(current_len - excess)?;
        }
        Ok(())
    }

    /// Test whether we have already seen `message`.
    ///
    /// If we have seen it, return `Err(ReplayError::AlreadySeen)`.  (Since this
    /// is a probabilistic data structure, there is a chance of returning this
    /// error even if we have we have _not_ seen this particular message)
    ///
    /// Otherwise, return `Ok(())`.
    pub(crate) fn check_for_replay(&mut self, message: &T::Message) -> Result<(), ReplayError> {
        let h = T::transform_message(message);
        self.seen.test_and_add(&h)?;
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

                f.file.write_all(&h[..])?;

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

    /// Tries to parse a filename in the replay logs directory
    ///
    /// If the leafname refers to a file that would be created by
    /// [`ReplayLog::new_logged`], returns the name as a Rust type.
    ///
    /// Otherwise returns an error explaining why it isn't,
    /// as a plain string (for logging).
    pub(crate) fn parse_log_leafname(leaf: &OsStr) -> Result<T::Name, Cow<'static, str>> {
        T::parse_log_leafname(leaf)
    }
}

/// Wrapper around a fast-ish data structure for detecting replays with some
/// false positive rate.  Bloom filters, cuckoo filters, and xorf filters are all
/// an option here.  You could even use a HashSet.
///
/// We isolate this code to make it easier to replace.
mod data {
    use super::{OUTPUT_LEN, ReplayError};
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

        /// Try to add `msg` to this filter if it isn't already there.
        ///
        /// Return Ok(()) or Err(AlreadySeen).
        pub(super) fn test_and_add(&mut self, msg: &[u8; OUTPUT_LEN]) -> Result<(), ReplayError> {
            if self.0.insert(&msg[..]) {
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

/// Error occured while opening replay log.
#[derive(thiserror::Error, Clone, Debug)]
#[error("unable to open replay log: {file:?}")]
pub struct OpenReplayLogError {
    /// What filesystem object we tried to do it to
    pub(crate) file: PathBuf,
    /// What happened
    #[source]
    pub(crate) error: Arc<io::Error>,
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use crate::test::mk_state_instance;
    use rand::Rng;
    use test_temp_dir::{TestTempDir, TestTempDirGuard, test_temp_dir};

    struct TestReplayLogType;

    type TestReplayLog = ReplayLog<TestReplayLogType>;

    impl ReplayLogType for TestReplayLogType {
        type Name = IptLocalId;
        type Message = [u8; OUTPUT_LEN];

        const MAGIC: &'static [u8; MAGIC_LEN] = b"<tor test replay>\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

        fn format_filename(name: &IptLocalId) -> String {
            format!("{name}{REPLAY_LOG_SUFFIX}")
        }

        fn transform_message(message: &[u8; OUTPUT_LEN]) -> [u8; OUTPUT_LEN] {
            message.clone()
        }

        fn parse_log_leafname(leaf: &OsStr) -> Result<IptLocalId, Cow<'static, str>> {
            let leaf = leaf.to_str().ok_or("not proper unicode")?;
            let lid = leaf.strip_suffix(REPLAY_LOG_SUFFIX).ok_or("not *.bin")?;
            let lid: IptLocalId = lid
                .parse()
                .map_err(|e: crate::InvalidIptLocalId| e.to_string())?;
            Ok(lid)
        }
    }

    fn rand_msg<R: Rng>(rng: &mut R) -> [u8; OUTPUT_LEN] {
        rng.random()
    }

    /// Basic tests on an ephemeral IptReplayLog.
    #[test]
    fn simple_usage() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();

        let mut log = TestReplayLog::new_ephemeral();
        // Add everything in group 1.
        for msg in &group_1 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
        // Make sure that everything in group 1 is still there.
        for msg in &group_1 {
            assert!(log.check_for_replay(msg).is_err());
        }
        // Make sure that group 2 is detected as not-there.
        for msg in &group_2 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
    }

    const TEST_TEMP_SUBDIR: &str = "replaylog";

    fn create_logged(dir: &TestTempDir) -> TestTempDirGuard<TestReplayLog> {
        dir.subdir_used_by(TEST_TEMP_SUBDIR, |dir| {
            let inst = mk_state_instance(&dir, "allium");
            let raw = inst.raw_subdir("iptreplay").unwrap();
            TestReplayLog::new_logged(&raw, &IptLocalId::dummy(1)).unwrap()
        })
    }

    /// Basic tests on an persistent IptReplayLog.
    #[test]
    fn logging_basics() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();

        let dir = test_temp_dir!();
        let mut log = create_logged(&dir);
        // Add everything in group 1, then close and reload.
        for msg in &group_1 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure everything in group 1 is still there.
        for msg in &group_1 {
            assert!(log.check_for_replay(msg).is_err());
        }
        // Now add everything in group 2, then close and reload.
        for msg in &group_2 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure that groups 1 and 2 are still there.
        for msg in group_1.iter().chain(group_2.iter()) {
            assert!(log.check_for_replay(msg).is_err());
        }
    }

    /// Test for a log that gets truncated mid-write.
    #[test]
    fn test_truncated() {
        let mut rng = tor_basic_utils::test_rng::testing_rng();
        let group_1: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();
        let group_2: Vec<_> = (0..=100).map(|_| rand_msg(&mut rng)).collect();

        let dir = test_temp_dir!();
        let mut log = create_logged(&dir);
        for msg in &group_1 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
        drop(log);
        // Truncate the file by 7 bytes.
        dir.subdir_used_by(TEST_TEMP_SUBDIR, |dir| {
            let path = dir.join(format!("hss/allium/iptreplay/{}.bin", IptLocalId::dummy(1)));
            let file = OpenOptions::new().write(true).open(path).unwrap();
            // Make sure that the file has the length we expect.
            let expected_len = MAGIC_LEN + OUTPUT_LEN * group_1.len();
            assert_eq!(expected_len as u64, file.metadata().unwrap().len());
            file.set_len((expected_len - 7) as u64).unwrap();
        });
        // Now, reload the log. We should be able to recover every non-truncated
        // item...
        let mut log = create_logged(&dir);
        for msg in &group_1[..group_1.len() - 1] {
            assert!(log.check_for_replay(msg).is_err());
        }
        // But not the last one, which we truncated.  (Checking will add it, though.)
        assert!(
            log.check_for_replay(&group_1[group_1.len() - 1]).is_ok(),
            "False positive"
        );
        // Now add everything in group 2, then close and reload.
        for msg in &group_2 {
            assert!(log.check_for_replay(msg).is_ok(), "False positive");
        }
        drop(log);
        let mut log = create_logged(&dir);
        // Make sure that groups 1 and 2 are still there.
        for msg in group_1.iter().chain(group_2.iter()) {
            assert!(log.check_for_replay(msg).is_err());
        }
    }

    /// Test for a partial write
    #[test]
    #[cfg(target_os = "linux")] // different platforms have different definitions of sigaction
    fn test_partial_write() {
        use std::env;
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        // TODO this contraption should perhaps be productised and put somewhere else

        const ENV_NAME: &str = "TOR_HSSERVICE_TEST_PARTIAL_WRITE_SUBPROCESS";
        // for a wait status different from any of libtest's
        const GOOD_SIGNAL: i32 = libc::SIGUSR2;

        let sigemptyset = || unsafe {
            let mut set = MaybeUninit::uninit();
            libc::sigemptyset(set.as_mut_ptr());
            set.assume_init()
        };

        // Check that SIGUSR2 starts out as SIG_DFL and unblocked
        //
        // We *reject* such situations, rather than fixing them up, because this is an
        // irregular and broken environment that can cause arbitrarily weird behaviours.
        // Programs on Unix are entitled to assume that their signal dispositions are
        // SIG_DFL on entry, with signals unblocked.  (With a few exceptions.)
        //
        // So we want to detect and report any such environment, not let it slide.
        unsafe {
            let mut sa = MaybeUninit::uninit();
            let r = libc::sigaction(GOOD_SIGNAL, ptr::null(), sa.as_mut_ptr());
            assert_eq!(r, 0);
            let sa = sa.assume_init();
            assert_eq!(
                sa.sa_sigaction,
                libc::SIG_DFL,
                "tests running in broken environment (SIGUSR2 not SIG_DFL)"
            );

            let empty_set = sigemptyset();
            let mut current_set = MaybeUninit::uninit();
            let r = libc::sigprocmask(
                libc::SIG_UNBLOCK,
                (&empty_set) as _,
                current_set.as_mut_ptr(),
            );
            assert_eq!(r, 0);
            let current_set = current_set.assume_init();
            let blocked = libc::sigismember((&current_set) as _, GOOD_SIGNAL);
            assert_eq!(
                blocked, 0,
                "tests running in broken environment (SIGUSR2 blocked)"
            );
        }

        match env::var(ENV_NAME) {
            Err(env::VarError::NotPresent) => {
                eprintln!("in test runner process, forking..,");
                let output = Command::new(env::current_exe().unwrap())
                    .args(["--nocapture", "replay::test::test_partial_write"])
                    .env(ENV_NAME, "1")
                    .output()
                    .unwrap();
                let print_output = |prefix, data| match std::str::from_utf8(data) {
                    Ok(s) => {
                        for l in s.split("\n") {
                            eprintln!(" {prefix} {l}");
                        }
                    }
                    Err(e) => eprintln!(" UTF-8 ERROR {prefix} {e}"),
                };
                print_output("!", &output.stdout);
                print_output(">", &output.stderr);
                let st = output.status;
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
                use libc::RLIMIT_FSIZE;
                let mut rlim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let r = libc::getrlimit(RLIMIT_FSIZE, (&mut rlim) as _);
                assert_eq!(r, 0);
                rlim.rlim_cur = size.try_into().unwrap();
                let r = libc::setrlimit(RLIMIT_FSIZE, (&rlim) as _);
                assert_eq!(r, 0);
            }
        }

        // This test is quite complicated.
        //
        // We want to test partial writes.  We could perhaps have done this by
        // parameterising IptReplayLog so it could have something other than File,
        // but that would probably leak into the public API.
        //
        // Instead, we cause *actual* partial writes.  We use the Unix setrlimit
        // call to limit the size of files our process is allowed to write.
        // This causes the underlying write(2) calls to (i) generate SIGXFSZ
        // (ii) if that doesn't kill the process, return partial writes.

        test_temp_dir!().used_by(|dir| {
            let path = dir.join("test.log");
            let lock = LockFileGuard::lock(dir.join("dummy.lock")).unwrap();
            let lock = Arc::new(lock);
            let mut rl = TestReplayLog::new_logged_inner(&path, lock.clone()).unwrap();

            const BUF: usize = 8192; // BufWriter default; if that changes, test will break

            // We let ourselves write one whole buffer plus an odd amount of extra
            const ALLOW: usize = BUF + 37;

            // Ignore SIGXFSZ (default disposition is for exceeding the rlimit to kill us)
            unsafe {
                let sa = libc::sigaction {
                    sa_sigaction: libc::SIG_IGN,
                    sa_mask: sigemptyset(),
                    sa_flags: 0,
                    sa_restorer: None,
                };
                let r = libc::sigaction(libc::SIGXFSZ, (&sa) as _, ptr::null_mut());
                assert_eq!(r, 0);
            }

            let demand_efbig = |e| match e {
                ReplayError::Log(e) if e.kind() == io::ErrorKind::FileTooLarge => {}
                other => panic!("expected EFBIG, got {other:?}"),
            };

            // Generate a distinct message given a phase and a counter
            #[allow(clippy::identity_op)]
            let mk_msg = |phase: u8, i: usize| {
                let i = u32::try_from(i).unwrap();
                let mut msg = [0_u8; OUTPUT_LEN];
                msg[0] = phase;
                msg[1] = phase;
                msg[4] = (i >> 24) as _;
                msg[5] = (i >> 16) as _;
                msg[6] = (i >> 8) as _;
                msg[7] = (i >> 0) as _;
                msg
            };

            // Number of hashes we can write to the file before failure occurs
            const CAN_DO: usize = (ALLOW + BUF - MAGIC_LEN) / OUTPUT_LEN;
            dbg!(MAGIC_LEN, OUTPUT_LEN, BUF, ALLOW, CAN_DO);

            // Record of the hashes that TestReplayLog tells us were OK and not replays;
            // ie, which it therefore ought to have recorded.
            let mut gave_ok = Vec::new();

            set_ulimit(ALLOW);

            for i in 0..CAN_DO {
                let h = mk_msg(b'y', i);
                rl.check_for_replay(&h).unwrap();
                gave_ok.push(h);
            }

            let md = fs::metadata(&path).unwrap();
            dbg!(md.len(), &rl.file);

            // Now we have written what we can.  The next two calls will fail,
            // since the BufWriter buffer is full and can't be flushed.

            for i in 0..2 {
                eprintln!("expecting EFBIG {i}");
                demand_efbig(rl.check_for_replay(&mk_msg(b'n', i)).unwrap_err());
                let md = fs::metadata(&path).unwrap();
                assert_eq!(md.len(), u64::try_from(ALLOW).unwrap());
            }

            // Enough that we don't get any further file size exceedances
            set_ulimit(ALLOW * 10);

            // Now we should be able to recover.  We write two more hashes.
            for i in 0..2 {
                eprintln!("recovering {i}");
                let h = mk_msg(b'r', i);
                rl.check_for_replay(&h).unwrap();
                gave_ok.push(h);
            }

            // flush explicitly just so we catch any error
            // (drop would flush, but it can't report errors)
            rl.flush().unwrap();
            drop(rl);

            // Reopen the log - reading in the written data.
            // We can then check that everything the earlier IptReplayLog
            // claimed to have written, is indeed recorded.

            let mut rl = TestReplayLog::new_logged_inner(&path, lock.clone()).unwrap();
            for msg in &gave_ok {
                match rl.check_for_replay(msg) {
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
