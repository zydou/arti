//! `tor_memtrack::tracker::test`

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
#![allow(clippy::let_and_return)] // TODO this lint is annoying and we should disable it

use super::*;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use itertools::Itertools;
use rand::Rng;
use slotmap::Key as _;
use tracing_test::traced_test;

use tor_basic_utils::RngExt as _;
use tor_rtcompat::{CoarseDuration, CoarseTimeProvider as _, Runtime};
use tor_rtmock::MockRuntime;

//---------- useful utilities ----------

pub(crate) const TEST_DEFAULT_LIMIT: usize = mby(20);
pub(crate) const TEST_DEFAULT_LOWWATER: usize = mby(15);

fn secs(s: u64) -> CoarseDuration {
    Duration::from_secs(s).into()
}

pub(crate) const fn mby(mib: usize) -> usize {
    mib * 1024 * 1024
}

fn mk_config() -> Config {
    Config::builder()
        .max(TEST_DEFAULT_LIMIT)
        .low_water(TEST_DEFAULT_LOWWATER)
        .build()
        .unwrap()
}

pub(crate) fn mk_tracker(rt: &impl Runtime) -> Arc<MemoryQuotaTracker> {
    MemoryQuotaTracker::new(&rt, mk_config()).unwrap()
}

fn test_with_various_mocks<F, Fut>(f: F)
where
    F: Fn(tor_rtmock::MockRuntime) -> Fut,
    Fut: Future<Output = ()>,
{
    MockRuntime::test_with_various(|rt| async {
        // Make sure we can talk about times at least 1000s in the past
        // TODO maybe this should be a feature of MockRuntime but what value to pick?
        rt.advance_by(Duration::from_secs(1000)).await;
        f(rt).await;
    });
}

//---------- consistency check (test invariants against outside view) ----------

use consistency::*;
mod consistency {
    use super::*;

    #[derive(Default)]
    pub(super) struct CallerInfoCollector {
        g: usize,
        acs: BTreeMap<AId, refcount::RawCount>,
        pcs: BTreeMap<(AId, PId), (refcount::RawCount, usize)>,
        debug_dump: String,
    }

    pub(super) trait HasCallerInfo {
        fn note_consistency_caller_info(&self, collector: &mut CallerInfoCollector);
    }

    impl CallerInfoCollector {
        pub(super) fn note_account(&mut self, acct: &Account, reclaimed: ReclaimedOrOk) {
            writeln!(self.debug_dump, "acct {acct:?} {reclaimed:?}").unwrap();
            if acct.aid.is_null() || reclaimed.is_err() {
                return;
            }
            let ac = self.acs.entry(*acct.aid).or_default();
            *ac += 1;
        }
        pub(super) fn note_particip(
            &mut self,
            p: &Participation,
            reclaimed: ReclaimedOrOk,
            used: usize,
        ) {
            writeln!(self.debug_dump, "particip {p:?} {reclaimed:?} {used:?}").unwrap();
            if p.pid.is_null() || p.aid.is_null() || reclaimed.is_err() {
                return;
            }
            self.note_partn_core(p, used);
        }
        pub(super) fn note_partn_clone(&mut self, p: &Participation) {
            writeln!(self.debug_dump, "partn {p:?}").unwrap();
            if p.pid.is_null() {
                return;
            }
            self.note_partn_core(p, 0);
        }
        fn note_partn_core(&mut self, p: &Participation, x_used: usize) {
            let pc = self.pcs.entry((p.aid, *p.pid)).or_default();
            let used = *p.cache.as_raw() + x_used;
            pc.0 += 1;
            pc.1 += used;
            self.g += used;
        }
    }

    pub(super) fn check_consistency_general(
        trk: &Arc<MemoryQuotaTracker>,
        collect_caller_info: impl FnOnce(&mut CallerInfoCollector),
    ) {
        let state = trk.lock().unwrap();

        let (expected, debug_dump) = {
            let mut c = CallerInfoCollector::default();
            collect_caller_info(&mut c);
            ((c.g, c.acs, c.pcs), c.debug_dump)
        };

        let got = {
            let mut gc = 0;
            let mut acs = BTreeMap::new();
            let mut pcs = BTreeMap::new();
            for (aid, arecord) in &state.accounts {
                acs.insert(aid, *arecord.refcount);
                for (pid, precord) in &arecord.ps {
                    let used = *precord.used.as_raw();
                    gc += used;
                    pcs.insert((aid, pid), (*precord.refcount, used));
                }
            }

            (gc, acs, pcs)
        };

        assert_eq!(
            expected, got,
            "\n----- dump (start) -----\n{debug_dump}----- dump (end) -----",
        );
    }
}

//---------- common test participant (state) ----------

#[derive(Debug)]
struct PartnState {
    partn: Participation,
    age: Option<CoarseInstant>,
    used: usize,
    reclaimed: ReclaimedOrOk,
    show: String,
}

#[derive(Debug)]
struct TestPartn {
    state: Mutex<PartnState>,
}

impl TestPartn {
    fn lock(&self) -> MutexGuard<PartnState> {
        self.state.lock().unwrap()
    }
}

impl From<PartnState> for TestPartn {
    fn from(state: PartnState) -> TestPartn {
        TestPartn {
            state: Mutex::new(state),
        }
    }
}

impl TestPartn {
    fn get_oldest(&self) -> Option<CoarseInstant> {
        self.lock().age
    }
    fn reclaim(&self) -> ReclaimFuture {
        let () = mem::replace(&mut self.lock().reclaimed, Err(())).expect("reclaimed twice!");
        Box::pin(async { Reclaimed::Collapsing })
    }
    fn is_reclaimed(&self) -> Result<(), ()> {
        self.lock().reclaimed
    }
}

impl IsParticipant for TestPartn {
    fn get_oldest(&self) -> Option<CoarseInstant> {
        self.get_oldest()
    }
    fn reclaim(self: Arc<Self>) -> ReclaimFuture {
        (*self.clone()).reclaim()
    }
}

impl PartnState {
    fn claim(&mut self, qty: usize) -> Result<(), crate::Error> {
        claim_via(&mut self.partn, &self.show, &mut self.used, qty)
    }

    fn release(&mut self, qty: usize) {
        release_via(&mut self.partn, &self.show, &mut self.used, qty);
    }
}

fn claim_via(
    via: &mut Participation,
    show: impl Display,
    used: &mut usize,
    qty: usize,
) -> Result<(), crate::Error> {
    eprintln!("{show} claim {qty} {qty:#x}");
    via.claim(qty)?;
    *used += qty;
    Ok(())
}

fn release_via(via: &mut Participation, show: impl Display, used: &mut usize, qty: usize) {
    eprintln!("{show} release {qty} {qty:#x}");
    via.release(qty);
    *used -= qty;
}

impl HasCallerInfo for PartnState {
    fn note_consistency_caller_info(&self, collector: &mut CallerInfoCollector) {
        collector.note_particip(&self.partn, self.reclaimed, self.used);
    }
}

//---------- test participant which is directly the accountholder ----------

#[derive(Debug, Deref)]
struct UnifiedP {
    acct: Account,
    #[deref]
    state: TestPartn,
}

type ReclaimedOrOk = Result<(), ()>;

impl IsParticipant for UnifiedP {
    fn get_oldest(&self) -> Option<CoarseInstant> {
        self.state.get_oldest()
    }
    fn reclaim(self: Arc<Self>) -> ReclaimFuture {
        self.state.reclaim()
    }
}

impl UnifiedP {
    fn new(
        rt: &impl Runtime,
        trk: &Arc<MemoryQuotaTracker>,
        parent: Option<&Account>,
        age: CoarseDuration,
        show: impl Display,
    ) -> Arc<Self> {
        let acct = trk.new_account(parent).unwrap();

        let now = rt.now_coarse();

        acct.register_participant_with(now, |partn| {
            Ok::<_, Void>((
                Arc::new(UnifiedP {
                    acct: acct.clone(),
                    state: PartnState {
                        partn,
                        age: Some(now - age),
                        show: show.to_string(),
                        used: 0,
                        reclaimed: Ok(()),
                    }
                    .into(),
                }),
                (),
            ))
        })
        .unwrap()
        .void_unwrap()
        .0
    }

    async fn settle_check_consistency<'i>(
        rt: &'i MockRuntime,
        trk: &'i Arc<MemoryQuotaTracker>,
        ups: impl IntoIterator<Item = &'i Arc<Self>> + 'i,
    ) {
        rt.advance_until_stalled().await;

        check_consistency_general(trk, |collector| {
            for up in ups {
                up.note_consistency_caller_info(collector);
            }
        });
    }
}

impl HasCallerInfo for UnifiedP {
    fn note_consistency_caller_info(&self, collector: &mut CallerInfoCollector) {
        let state = self.lock();
        collector.note_account(&self.acct, state.reclaimed);
        state.note_consistency_caller_info(collector);
    }
}

//---------- test cases with unified accountholder/participant ----------

#[traced_test]
#[test]
fn basic() {
    test_with_various_mocks(|rt| async move {
        let trk = mk_tracker(&rt);

        let ps: Vec<Arc<UnifiedP>> = (0..21)
            .map(|i| UnifiedP::new(&rt, &trk, None, secs(i), i))
            .collect();

        for p in &ps[0..19] {
            p.lock().claim(mby(1)).unwrap();
            UnifiedP::settle_check_consistency(&rt, &trk, &ps).await;
        }

        let count_uncollapsed = || ps.iter().filter(|p| p.is_reclaimed().is_ok()).count();

        assert_eq!(count_uncollapsed(), 21);

        for p in &ps[20..] {
            // check that we are exercising a situation with nonzero cached
            // (this is set up by register_participant
            assert_ne!(p.lock().partn.cache, Qty(0));

            p.lock()
                .claim(mby(1))
                .expect("allocation rejected, during collapse, but collapse is async");
        }

        UnifiedP::settle_check_consistency(&rt, &trk, &ps).await;

        assert_eq!(count_uncollapsed(), 14);

        // Now we drop everything.  This exercises much of the teardown!
    });
}

#[traced_test]
#[test]
fn parent() {
    test_with_various_mocks(|rt| async move {
        for ages in [[10, 20], [20, 10]] {
            eprintln!("ages: {ages:?}");
            let [parent_age, child_age] = ages.map(secs);

            let trk = mk_tracker(&rt);

            let mk_p = |parent, age, show| UnifiedP::new(&rt, &trk, parent, age, show);

            let parent = mk_p(None, parent_age, "parent");
            parent.lock().claim(mby(7)).unwrap();
            rt.advance_until_stalled().await;
            assert!(parent.is_reclaimed().is_ok());

            let child = mk_p(Some(&parent.acct), child_age, "child");
            child.lock().claim(mby(7)).unwrap();
            assert!(parent.is_reclaimed().is_ok());
            assert!(child.is_reclaimed().is_ok());

            let trigger = mk_p(None, secs(0), "trigger");
            trigger.lock().claim(mby(7)).unwrap();
            assert!(trigger.is_reclaimed().is_ok());

            rt.advance_until_stalled().await;

            if parent_age > child_age {
                // parent is older than child, we're supposed to have reclaimed
                // from the parent, causing reclamation of the child.
                assert!(parent.is_reclaimed().is_err());
                assert!(child.is_reclaimed().is_err());
            } else {
                // supposed to have reclaimed from child only
                assert!(parent.is_reclaimed().is_ok());
                assert!(child.is_reclaimed().is_err());
            }
        }
    });
}

#[traced_test]
#[test]
fn cache() {
    test_with_various_mocks(|rt| async move {
        let seq = [
            1,
            1000,
            *MAX_CACHE - 2000,
            3000,
            *MAX_CACHE,
            *MAX_CACHE - 1,
            *MAX_CACHE + 1,
        ];

        let trk = mk_tracker(&rt);
        let p = UnifiedP::new(&rt, &trk, None, secs(0), "p");

        for qty in seq {
            p.lock().claim(qty).unwrap();
            UnifiedP::settle_check_consistency(&rt, &trk, [&p]).await;
        }

        for qty in seq {
            p.lock().release(qty);
            UnifiedP::settle_check_consistency(&rt, &trk, [&p]).await;
        }

        let mut p2 = p.lock().partn.clone();

        let mut rng = tor_basic_utils::test_rng::Config::Deterministic.into_rng();
        for _iter in 0..10_000 {
            let qty = rng.gen_range_checked(0..=*MAX_CACHE).unwrap();
            let p_use_i = rng.gen_range_checked(1..=3).unwrap();
            {
                let mut state = p.lock();
                let state = &mut *state;

                let mut p_use_buf;
                let p_use = match p_use_i {
                    1 => &mut state.partn,
                    2 => &mut p2,
                    3 => {
                        p_use_buf = p2.clone();
                        &mut p_use_buf
                    }
                    x => panic!("{}", x),
                };

                if rng.gen() || qty > state.used {
                    claim_via(p_use, p_use_i, &mut state.used, qty).unwrap();
                } else {
                    release_via(p_use, p_use_i, &mut state.used, qty);
                }
            }

            rt.advance_until_stalled().await;
            check_consistency_general(&trk, |collector| {
                p.note_consistency_caller_info(collector);
                collector.note_partn_clone(&p2);
            });
        }
    });
}

#[traced_test]
#[test]
fn explicit_destroy() {
    test_with_various_mocks(|rt| async move {
        let trk = mk_tracker(&rt);

        let p0 = UnifiedP::new(&rt, &trk, None, secs(0), "0");
        let p1 = p0.clone();

        p0.lock().claim(mby(1)).unwrap();
        UnifiedP::settle_check_consistency(&rt, &trk, [&p0]).await;

        p1.lock().claim(mby(2)).unwrap();
        UnifiedP::settle_check_consistency(&rt, &trk, [&p0]).await;

        p1.lock().partn.clone().destroy_participant();

        rt.advance_until_stalled().await;
        check_consistency_general(&trk, |collector| {
            collector.note_account(&p0.acct, Ok(()));
            // We don't note the participation, since it's dead.
        });

        assert!(p1.lock().claim(mby(3)).is_err());

        // Now we drop everything.  This exercises much of the teardown!
    });
}

//---------- test client with multiple participants per account ----------

#[derive(Debug)]
struct ComplexAH {
    acct: Account,
    ps: Vec<Arc<TestPartn>>,
}

impl HasCallerInfo for ComplexAH {
    fn note_consistency_caller_info(&self, collector: &mut CallerInfoCollector) {
        let reclaimed = self
            .ps
            .iter()
            .map(|p| p.lock().reclaimed)
            .dedup()
            .exactly_one()
            .unwrap();

        collector.note_account(&self.acct, reclaimed);
        for p in &self.ps {
            p.lock().note_consistency_caller_info(collector);
        }
    }
}

impl ComplexAH {
    fn new(trk: &Arc<MemoryQuotaTracker>) -> Self {
        ComplexAH {
            acct: trk.new_account(None).unwrap(),
            ps: vec![],
        }
    }

    fn add_p(&mut self, now: CoarseInstant, age: CoarseDuration, show: impl Display) -> usize {
        let (cp, x) = self
            .acct
            .register_participant_with(now, |partn| {
                Ok::<_, Void>((
                    Arc::new(TestPartn::from(PartnState {
                        partn,
                        age: Some(now - age),
                        show: show.to_string(),
                        used: 0,
                        reclaimed: Ok(()),
                    })),
                    42,
                ))
            })
            .unwrap()
            .void_unwrap();

        assert_eq!(x, 42);

        let i = self.ps.len();
        self.ps.push(cp);
        i
    }
}

#[traced_test]
#[test]
fn complex() {
    test_with_various_mocks(|rt| async move {
        let trk = mk_tracker(&rt);

        let up = UnifiedP::new(&rt, &trk, None, secs(0), "U");
        let mut ah = ComplexAH::new(&trk);
        let now = rt.now_coarse();

        for age in [5, 9] {
            ah.add_p(now, secs(age), age);
        }

        let settle_check_consistency = || async {
            rt.advance_until_stalled().await;

            check_consistency_general(&trk, |collector| {
                up.note_consistency_caller_info(collector);
                ah.note_consistency_caller_info(collector);
            });
        };

        up.lock().claim(mby(1)).unwrap();
        ah.ps[0].lock().claim(mby(11)).unwrap();

        settle_check_consistency().await;

        assert!(up.is_reclaimed().is_ok());
        for p in &ah.ps {
            assert!(p.is_reclaimed().is_ok());
        }

        ah.ps[1].lock().claim(mby(11)).unwrap();

        settle_check_consistency().await;
        assert!(up.is_reclaimed().is_ok());
        for p in &ah.ps {
            assert!(p.is_reclaimed().is_err());
        }
    });
}

//---------- various error cases ----------

#[derive(Debug)]
struct DummyParticipant;

impl IsParticipant for DummyParticipant {
    fn get_oldest(&self) -> Option<CoarseInstant> {
        None
    }
    fn reclaim(self: Arc<Self>) -> ReclaimFuture {
        Box::pin(async { Reclaimed::Collapsing })
    }
}

#[traced_test]
#[test]
fn errors() {
    test_with_various_mocks(|rt| async move {
        let trk = mk_tracker(&rt);
        let now = rt.now_coarse();

        let mk_ah = || {
            let mut ah = ComplexAH::new(&trk);
            ah.add_p(now, secs(5), "p");
            ah
        };

        const CLAIM: usize = MAX_CACHE.as_usize() + 1;

        let dummy_dangling = || {
            let p = Arc::new(DummyParticipant);
            Arc::downgrade(&p)
            // p dropped here
        };
        assert!(dummy_dangling().upgrade().is_none());

        macro_rules! assert_error { { $error:ident, $r:expr } => {
            let r = $r;
            assert!(matches!(r, Err(Error::$error)), "unexpected: {:?} => {:?}", stringify!($r), &r);
        } }

        // Dropped account
        {
            let mut ah = mk_ah();
            let wa1: WeakAccount = ah.acct.downgrade();
            let p = ah.ps.pop().unwrap();
            let wa2: WeakAccount = p.lock().partn.account();
            drop(ah.acct);

            rt.advance_until_stalled().await;
            check_consistency_general(&trk, |_collector| ());

            // account should be dead now
            assert!(p.lock().claim(1).is_ok()); // from cache!
            assert_error!(AccountClosed, p.lock().claim(CLAIM));
            assert_error!(AccountClosed, wa1.upgrade());
            assert_error!(AccountClosed, wa2.upgrade());

            // but we can still release
            p.lock().release(1);
        }

        // Dropped IsParticipant
        {
            let mut ah = mk_ah();
            let p = ah.ps.pop().unwrap();
            let mut state = Arc::into_inner(p).unwrap().state.into_inner().unwrap();

            state.claim(mby(30)).unwrap(); // will trigger reclaim, which discovers the loss

            rt.advance_until_stalled().await;
            check_consistency_general(&trk, |collector| {
                let reclaimed = Ok(()); // didn't manage to make the callback!
                collector.note_account(&ah.acct, reclaimed);
            });

            assert_error!(ParticipantShutdown, state.claim(CLAIM));
        }

        // Reclaimed account
        {
            let ah = mk_ah();
            ah.ps[0].lock().claim(mby(30)).unwrap();

            rt.advance_until_stalled().await;
            check_consistency_general(&trk, |_collector| ());

            let p = &ah.ps[0];

            assert!(p.lock().reclaimed.is_err());
            assert_error!(AccountClosed, p.lock().claim(CLAIM));

            let cloned = ah.acct.clone();
            assert!(cloned.aid.is_null());
            assert_error!(
                AccountClosed,
                ah.acct.register_participant(dummy_dangling())
            );

            let mut cloned = p.lock().partn.clone();
            assert!(cloned.pid.is_null());
            assert_error!(AccountClosed, cloned.claim(CLAIM));

            // but we can still release
            p.lock().release(1);
        }

        // Dropped tracker
        {
            let mut ah = mk_ah();
            let p = ah.ps.pop().unwrap();
            let wa = ah.acct.downgrade();
            drop(ah.acct);
            let _: MemoryQuotaTracker = Arc::into_inner(trk).unwrap();

            assert_error!(TrackerShutdown, wa.upgrade());
            assert_error!(TrackerShutdown, p.lock().partn.account().upgrade());
            assert_error!(TrackerShutdown, p.lock().claim(CLAIM));
        }
    });
}
