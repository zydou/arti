use crate::usage::{SupportedCircUsage, TargetCircUsage};
use crate::{timeouts, DirInfo, Error, PathConfig, Result};

#[cfg(feature = "vanguards")]
use tor_guardmgr::vanguards::VanguardMgr;
use tor_linkspec::CircTarget;
use tor_proto::circuit::{CircParameters, Path, UniqId};
use tor_rtcompat::Runtime;

use async_trait::async_trait;
use std::sync::{self, Arc};
use std::time::Duration;

use crate::isolation::test::IsolationTokenEq;
use crate::usage::ExitPolicy;
use crate::{StreamIsolation, TargetPorts};
use std::sync::atomic::{self, AtomicUsize};
use tracing::trace;

use super::mgr::{AbstractCirc, AbstractCircBuilder, MockablePlan};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
pub(crate) struct FakeId {
    pub(crate) id: usize,
}

static NEXT_FAKE_ID: AtomicUsize = AtomicUsize::new(0);
impl FakeId {
    pub(crate) fn next() -> Self {
        let id = NEXT_FAKE_ID.fetch_add(1, atomic::Ordering::SeqCst);
        FakeId { id }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub(crate) struct FakeCirc {
    pub(crate) id: FakeId,
}

#[async_trait]
impl AbstractCirc for FakeCirc {
    type Id = FakeId;
    fn id(&self) -> FakeId {
        self.id
    }
    fn usable(&self) -> bool {
        true
    }

    fn path_ref(&self) -> Arc<Path> {
        todo!()
    }

    fn n_hops(&self) -> usize {
        todo!()
    }

    fn is_closing(&self) -> bool {
        todo!()
    }

    fn unique_id(&self) -> UniqId {
        todo!()
    }

    async fn extend_ntor<T: CircTarget + std::marker::Sync>(
        &self,
        _target: &T,
        _params: &CircParameters,
    ) -> tor_proto::Result<()> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FakePlan {
    spec: SupportedCircUsage,
    op: FakeOp,
}

#[derive(Debug)]
pub(crate) struct FakeBuilder<RT: Runtime> {
    runtime: RT,
    pub(crate) script: sync::Mutex<Vec<(TargetCircUsage, FakeOp)>>,
}

#[derive(Debug, Clone)]
pub(crate) enum FakeOp {
    Succeed,
    Fail,
    Delay(Duration),
    Timeout,
    TimeoutReleaseAdvance(String),
    NoPlan,
    WrongSpec(SupportedCircUsage),
}

impl MockablePlan for FakePlan {
    fn add_blocked_advance_reason(&mut self, reason: String) {
        if let FakeOp::Timeout = self.op {
            self.op = FakeOp::TimeoutReleaseAdvance(reason);
        }
    }
}

const FAKE_CIRC_DELAY: Duration = Duration::from_millis(30);

#[async_trait]
impl<RT: Runtime> AbstractCircBuilder<RT> for FakeBuilder<RT> {
    type Circ = FakeCirc;
    type Plan = FakePlan;

    fn plan_circuit(
        &self,
        spec: &TargetCircUsage,
        _dir: DirInfo<'_>,
    ) -> Result<(FakePlan, SupportedCircUsage)> {
        let next_op = self.next_op(spec);
        if matches!(next_op, FakeOp::NoPlan) {
            return Err(Error::NoRelay {
                path_kind: "example",
                role: "example",
                problem: "called with no plan".to_string(),
            });
        }
        let supported_circ_usage = match spec {
            TargetCircUsage::Exit {
                ports,
                isolation,
                country_code,
                require_stability,
            } => SupportedCircUsage::Exit {
                policy: ExitPolicy::from_target_ports(&TargetPorts::from(&ports[..])),
                isolation: if isolation.isol_eq(&StreamIsolation::no_isolation()) {
                    None
                } else {
                    Some(isolation.clone())
                },
                country_code: *country_code,
                all_relays_stable: *require_stability,
            },
            _ => unimplemented!(),
        };
        let plan = FakePlan {
            spec: supported_circ_usage.clone(),
            op: next_op,
        };
        Ok((plan, supported_circ_usage))
    }

    async fn build_circuit(&self, plan: FakePlan) -> Result<(SupportedCircUsage, Arc<FakeCirc>)> {
        let op = plan.op;
        let sl = self.runtime.sleep(FAKE_CIRC_DELAY);
        self.runtime.allow_one_advance(FAKE_CIRC_DELAY);
        sl.await;
        match op {
            FakeOp::Succeed => Ok((plan.spec, Arc::new(FakeCirc { id: FakeId::next() }))),
            FakeOp::WrongSpec(s) => Ok((s, Arc::new(FakeCirc { id: FakeId::next() }))),
            FakeOp::Fail => Err(Error::CircTimeout(None)),
            FakeOp::Delay(d) => {
                let sl = self.runtime.sleep(d);
                self.runtime.allow_one_advance(d);
                sl.await;
                Err(Error::PendingCanceled)
            }
            FakeOp::Timeout => unreachable!(), // should be converted to the below
            FakeOp::TimeoutReleaseAdvance(reason) => {
                trace!("releasing advance to fake a timeout");
                self.runtime.release_advance(reason);
                let () = futures::future::pending().await;
                unreachable!()
            }
            FakeOp::NoPlan => unreachable!(),
        }
    }

    fn learning_timeouts(&self) -> bool {
        false
    }

    fn save_state(&self) -> Result<bool> {
        todo!()
    }

    fn path_config(&self) -> Arc<PathConfig> {
        todo!()
    }

    fn set_path_config(&self, _new_config: PathConfig) {
        todo!()
    }

    fn estimator(&self) -> &timeouts::Estimator {
        todo!()
    }

    #[cfg(feature = "vanguards")]
    fn vanguardmgr(&self) -> &Arc<VanguardMgr<RT>> {
        todo!()
    }
}

impl<RT: Runtime> FakeBuilder<RT> {
    pub(crate) fn new(rt: &RT) -> Self {
        FakeBuilder {
            runtime: rt.clone(),
            script: sync::Mutex::new(vec![]),
        }
    }

    /// set a plan for a given TargetCircUsage.
    pub(crate) fn set<I>(&self, spec: &TargetCircUsage, v: I)
    where
        I: IntoIterator<Item = FakeOp>,
    {
        let mut ops: Vec<_> = v.into_iter().collect();
        ops.reverse();
        let mut lst = self.script.lock().expect("Couldn't get lock on script");
        for op in ops {
            lst.push((spec.clone(), op));
        }
    }

    fn next_op(&self, spec: &TargetCircUsage) -> FakeOp {
        let mut script = self.script.lock().expect("Couldn't get lock on script");

        let idx = script
            .iter()
            .enumerate()
            .find_map(|(i, s)| spec.isol_eq(&s.0).then_some(i));

        if let Some(i) = idx {
            let (_, op) = script.remove(i);
            op
        } else {
            FakeOp::Succeed
        }
    }
}
