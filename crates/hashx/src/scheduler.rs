//! Scheduling model for program generation
//!
//! HashX uses a simple scheduling model inspired by the Intel Ivy Bridge
//! microarchitecture to choose registers that should be available and
//! avoid stalls.

use crate::program::{Instruction, Opcode};
use crate::register::{NUM_REGISTERS, RegisterId};

/// Scheduling information for each opcode
mod model {
    use crate::program::Opcode;

    /// Number of simulated cycles we run before stopping program generation
    pub(super) const TARGET_CYCLES: usize = 192;

    /// Total number of cycles to store schedule data for
    pub(super) const SCHEDULE_SIZE: usize = TARGET_CYCLES + MAX_LATENCY;

    /// Number of execution ports in our simulated microarchitecture
    pub(super) const NUM_EXECUTION_PORTS: usize = 3;

    /// Identify one or more CPU execution ports
    ///
    /// They are inspired by the Intel Ivy Bridge design and the original HashX
    /// implementation names them P5, P0, and P1.
    ///
    /// We can mostly ignore the names and treat this as an array of three
    /// ports specified in the order that HashX tries to allocate them. The
    /// original HashX implementation explains this allocation order as an
    /// optimistic strategy which assumes P1 will typically be reserved for
    /// multiplication.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub(super) struct ExecPorts(pub(super) u8);

    /// Port P5 (first choice) only
    const P5: ExecPorts = ExecPorts(1 << 0);
    /// Port P0 (second choice) only
    const P0: ExecPorts = ExecPorts(1 << 1);
    /// Port P1 (third choice) only
    const P1: ExecPorts = ExecPorts(1 << 2);
    /// Either port P0 or P1
    const P01: ExecPorts = ExecPorts(P0.0 | P1.0);
    /// Either port P0 or P5
    const P05: ExecPorts = ExecPorts(P0.0 | P5.0);
    /// Any of the three ports
    const P015: ExecPorts = ExecPorts(P0.0 | P1.0 | P5.0);

    /// Maximum value of [`instruction_latency_cycles()`] for any Opcode
    const MAX_LATENCY: usize = 4;

    /// Latency for each operation, in cycles
    #[inline(always)]
    pub(super) fn instruction_latency_cycles(op: Opcode) -> usize {
        match op {
            Opcode::AddConst => 1,
            Opcode::AddShift => 1,
            Opcode::Branch => 1,
            Opcode::Rotate => 1,
            Opcode::Sub => 1,
            Opcode::Target => 1,
            Opcode::Xor => 1,
            Opcode::XorConst => 1,
            Opcode::Mul => 3,
            Opcode::SMulH => 4,
            Opcode::UMulH => 4,
        }
    }

    /// Break an instruction down into one or two micro-operation port sets.
    #[inline(always)]
    pub(super) fn micro_operations(op: Opcode) -> (ExecPorts, Option<ExecPorts>) {
        match op {
            Opcode::AddConst => (P015, None),
            Opcode::Sub => (P015, None),
            Opcode::Xor => (P015, None),
            Opcode::XorConst => (P015, None),
            Opcode::Mul => (P1, None),
            Opcode::AddShift => (P01, None),
            Opcode::Rotate => (P05, None),
            Opcode::SMulH => (P1, Some(P5)),
            Opcode::UMulH => (P1, Some(P5)),
            Opcode::Branch => (P015, Some(P015)),
            Opcode::Target => (P015, Some(P015)),
        }
    }

    /// Each instruction advances the earliest possible issuing cycle by one
    /// sub-cycle per micro-op.
    #[inline(always)]
    pub(super) fn instruction_sub_cycle_count(op: Opcode) -> usize {
        match micro_operations(op) {
            (_, None) => 1,
            (_, Some(_)) => 2,
        }
    }
}

/// One single execution port
///
/// Formatted to use easily as an array index.
/// It's helpful for this to be a compact data type.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ExecPortIndex {
    /// Equivalent to a bit position in [`model::ExecPorts`].
    index: u8,
}

/// Overall state for the simulated execution schedule
#[derive(Debug, Default, Clone)]
pub(crate) struct Scheduler {
    /// Current timestamp in the schedule, in sub-cycles
    ///
    /// Sub-cycles advance as code is generated, modeling the time taken to
    /// fetch and decode instructions.
    sub_cycle: SubCycle,

    /// Current timestamp in the schedule, in cycles
    ///
    /// Derived from sub_cycle.
    cycle: Cycle,

    /// State for scheduling execution by fitting micro-ops into execution ports
    exec: ExecSchedule,

    /// State for scheduling register access by keeping track of data latency
    data: DataSchedule,
}

impl Scheduler {
    /// Create a new empty execution schedule at cycle 0
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Stall for one cycle.
    ///
    /// Used when register allocation fails.
    /// Returns `Ok` if we had enough time, or `Err` if we ran out.
    #[inline(always)]
    pub(crate) fn stall(&mut self) -> Result<(), ()> {
        self.advance(SubCycle::PER_CYCLE as usize)
    }

    /// Return the current instruction fetch/decode timestamp in sub-cycles.
    #[inline(always)]
    pub(crate) fn instruction_stream_sub_cycle(&self) -> SubCycle {
        self.sub_cycle
    }

    /// Advance forward in time by some number of sub-cycles.
    ///
    /// Stops just before reaching `Cycle::target()`, where we stop
    /// scheduling new instructions.
    #[inline(always)]
    fn advance(&mut self, n: usize) -> Result<(), ()> {
        let sub_cycle = self.sub_cycle.add_usize(n)?;
        let cycle = sub_cycle.cycle();
        if cycle < Cycle::target() {
            self.sub_cycle = sub_cycle;
            self.cycle = cycle;
            Ok(())
        } else {
            Err(())
        }
    }

    /// Advance time forward by the modeled duration of the instruction fetch
    /// and decode, in sub-cycles.
    ///
    /// Returns Ok if we still have enough time to schedule more, or Err if the
    /// schedule would be full.
    #[inline(always)]
    pub(crate) fn advance_instruction_stream(&mut self, op: Opcode) -> Result<(), ()> {
        self.advance(model::instruction_sub_cycle_count(op))
    }

    /// Calculate a timing plan describing the cycle and execution units
    /// on which a particular opcode could run, at the earliest.
    #[inline(always)]
    pub(crate) fn instruction_plan(&self, op: Opcode) -> Result<InstructionPlan, ()> {
        self.exec.instruction_plan(self.cycle, op)
    }

    /// Commit to using a plan returned by [`Self::instruction_plan()`],
    /// for a particular concrete [`Instruction`] instance.
    ///
    /// Marks as busy each execution unit cycle in the plan, and updates the
    /// latency for the [`Instruction`]'s destination register if it has one.
    #[inline(always)]
    pub(crate) fn commit_instruction_plan(&mut self, plan: &InstructionPlan, inst: &Instruction) {
        self.exec.mark_instruction_busy(plan);
        if let Some(dst) = inst.destination() {
            self.data
                .plan_register_write(dst, plan.cycle_retired(inst.opcode()));
        }
    }

    /// Look up if a register will be available at or before the indicated cycle.
    #[inline(always)]
    pub(crate) fn register_available(&self, reg: RegisterId, cycle: Cycle) -> bool {
        self.data.register_available(reg, cycle)
    }

    /// Return the overall data latency.
    ///
    /// This is the Cycle at which we expect every register
    /// to reach its final simulated state.
    #[inline(always)]
    pub(crate) fn overall_latency(&self) -> Cycle {
        self.data.overall_latency()
    }
}

/// Cycle timestamp
///
/// Measured from the beginning of the program, assuming no branches taken.
/// It's useful to be able to store these compactly in register latency arrays.
#[derive(Debug, Default, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct Cycle(u8);

impl Cycle {
    /// HashX stops generating code once the issue cycle reaches this target.
    #[inline(always)]
    fn target() -> Self {
        Cycle(
            model::TARGET_CYCLES
                .try_into()
                .expect("Cycle type wide enough for target count"),
        )
    }

    /// Cast this Cycle count to a usize losslessly.
    #[inline(always)]
    pub(crate) fn as_usize(&self) -> usize {
        self.0.into()
    }

    /// Add an integer number of cycles, returning Err(()) if we reach the end.
    #[inline(always)]
    fn add_usize(&self, n: usize) -> Result<Self, ()> {
        let result = self.as_usize() + n;
        if result < model::SCHEDULE_SIZE {
            Ok(Cycle(
                result
                    .try_into()
                    .expect("Cycle type wide enough for full schedule size"),
            ))
        } else {
            Err(())
        }
    }
}

/// Sub-cycle timestamp
///
/// Timer for instruction decode, at a finer resolution than the Cycle
/// we use for keeping schedule records. Doesn't need to be compact.
#[derive(Debug, Default, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) struct SubCycle(u16);

impl SubCycle {
    /// Number of sub-cycles per cycle
    const PER_CYCLE: u16 = 3;

    /// Maximum value of a sub-cycle counter, based on the schedule size
    const MAX: Self = SubCycle(model::SCHEDULE_SIZE as u16 * Self::PER_CYCLE - 1);

    /// Cast this sub-cycle count into a usize losslessly.
    #[inline(always)]
    pub(crate) fn as_usize(&self) -> usize {
        self.0.into()
    }

    /// Convert this sub-cycle into a full Cycle timestamp.
    #[inline(always)]
    fn cycle(&self) -> Cycle {
        Cycle(
            (self.0 / Self::PER_CYCLE)
                .try_into()
                .expect("Cycle type wide enough for conversion from SubCycle"),
        )
    }

    /// Advance by an integer number of sub-cycles.
    ///
    /// Returns the new advanced [`SubCycle`], or `Err(())`
    /// if we reach the end of the schedule.
    #[inline(always)]
    fn add_usize(&self, n: usize) -> Result<Self, ()> {
        let result = self.as_usize() + n;
        if result < Self::MAX.0.into() {
            Ok(SubCycle(result.try_into().expect(
                "SubCycle type wide enough for full schedule size",
            )))
        } else {
            Err(())
        }
    }
}

/// Busy tracking for one CPU execution port
#[derive(Debug, Default, Clone)]
struct PortSchedule {
    /// Bit array indicating when this port is busy, indexed by Cycle
    busy: SimpleBitArray<
        { (usize::BITS as usize + model::SCHEDULE_SIZE - 1) / (usize::BITS as usize) },
    >,
}

/// Latency tracking for all relevant CPU registers
#[derive(Debug, Default, Clone)]
struct DataSchedule {
    /// Cycle count at which this register is available, indexed by register ID
    latencies: [Cycle; NUM_REGISTERS],
}

impl DataSchedule {
    /// Plan to finish a register write at the indicated cycle
    #[inline(always)]
    fn plan_register_write(&mut self, dst: RegisterId, cycle: Cycle) {
        self.latencies[dst.as_usize()] = cycle;
    }

    /// Look up if a register will be available at or before the indicated cycle.
    #[inline(always)]
    fn register_available(&self, reg: RegisterId, cycle: Cycle) -> bool {
        self.latencies[reg.as_usize()] <= cycle
    }

    /// Return the overall latency, the [`Cycle`] at which we expect
    /// every register to reach its latest simulated state.
    #[inline(always)]
    fn overall_latency(&self) -> Cycle {
        match self.latencies.iter().max() {
            Some(cycle) => *cycle,
            None => Default::default(),
        }
    }
}

/// Execution schedule for all ports
///
/// This is a scoreboard that keeps track of which CPU units are busy in which
/// cycles, so we can estimate a timestamp at which each instruction will write
/// its result.
#[derive(Debug, Default, Clone)]
struct ExecSchedule {
    /// Execution schedule (busy flags) for each port
    ports: [PortSchedule; model::NUM_EXECUTION_PORTS],
}

impl ExecSchedule {
    /// Calculate the next cycle at which we could schedule one micro-op.
    ///
    /// HashX always searches execution ports in the same order, and it will
    /// look ahead up to the entire length of the schedule before failing.
    #[inline(always)]
    fn micro_plan(&self, begin: Cycle, ports: model::ExecPorts) -> Result<MicroOpPlan, ()> {
        let mut cycle = begin;
        loop {
            for index in 0..(model::NUM_EXECUTION_PORTS as u8) {
                if (ports.0 & (1 << index)) != 0
                    && !self.ports[index as usize].busy.get(cycle.as_usize())
                {
                    return Ok(MicroOpPlan {
                        cycle,
                        port: ExecPortIndex { index },
                    });
                }
            }
            cycle = cycle.add_usize(1)?;
        }
    }

    /// Mark the schedule busy according to a previously calculated plan.
    #[inline(always)]
    fn mark_micro_busy(&mut self, plan: MicroOpPlan) {
        self.ports[plan.port.index as usize]
            .busy
            .set(plan.cycle.as_usize(), true);
    }

    /// Calculate a timing plan describing the cycle and execution units
    /// we could use for scheduling one entire instruction.
    ///
    /// This takes place after the [`Opcode`] has been chosen but before
    /// a full [`Instruction`] can be assembled.
    #[inline(always)]
    fn instruction_plan(&self, begin: Cycle, op: Opcode) -> Result<InstructionPlan, ()> {
        match model::micro_operations(op) {
            // Single-op instructions
            (single_port, None) => {
                InstructionPlan::from_micro_plans(self.micro_plan(begin, single_port)?, None)
            }

            // HashX schedules two-op instructions by searching forward
            // until we find the first cycle where both ports are
            // simultaneously available.
            (first_port, Some(second_port)) => {
                let mut cycle = begin;
                loop {
                    if let (Ok(first_plan), Ok(second_plan)) = (
                        self.micro_plan(cycle, first_port),
                        self.micro_plan(cycle, second_port),
                    ) {
                        if let Ok(joint_plan) =
                            InstructionPlan::from_micro_plans(first_plan, Some(second_plan))
                        {
                            return Ok(joint_plan);
                        }
                    }
                    cycle = cycle.add_usize(1)?;
                }
            }
        }
    }

    /// Mark each micro-op in an InstructionPlan as busy in the schedule.
    #[inline(always)]
    fn mark_instruction_busy(&mut self, plan: &InstructionPlan) {
        let (first, second) = plan.as_micro_plans();
        self.mark_micro_busy(first);
        if let Some(second) = second {
            self.mark_micro_busy(second);
        }
    }
}

/// Detailed execution schedule for one micro-operation
///
/// Includes the [`Cycle`] it begins on, and the actual
/// execution port it was assigned.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct MicroOpPlan {
    /// The Cycle this operation begins on
    cycle: Cycle,
    /// Index of the execution port it runs on
    port: ExecPortIndex,
}

/// Detailed execution schedule for one instruction
///
/// This is defined as either one or two micro-operations
/// scheduled on the same cycle.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct InstructionPlan {
    /// The Cycle this whole instruction begins on
    cycle: Cycle,
    /// First execution port, always present
    first_port: ExecPortIndex,
    /// Optional second execution port ID, for two-uop instructions
    second_port: Option<ExecPortIndex>,
}

impl InstructionPlan {
    /// Get the Cycle this whole instruction begins on.
    #[inline(always)]
    pub(crate) fn cycle_issued(&self) -> Cycle {
        self.cycle
    }

    /// Calculate the cycle this instruction is complete by.
    #[inline(always)]
    pub(crate) fn cycle_retired(&self, op: Opcode) -> Cycle {
        self.cycle
            .add_usize(model::instruction_latency_cycles(op))
            .expect("instruction retired prior to end of schedule")
    }

    /// Convert this `InstructionPlan` back to one or two [`MicroOpPlan`]s.
    #[inline(always)]
    fn as_micro_plans(&self) -> (MicroOpPlan, Option<MicroOpPlan>) {
        (
            MicroOpPlan {
                cycle: self.cycle,
                port: self.first_port,
            },
            self.second_port.map(|port| MicroOpPlan {
                cycle: self.cycle,
                port,
            }),
        )
    }

    /// Bundle two [`MicroOpPlan`]s into an [`InstructionPlan`],
    /// if they are on matching cycles.
    ///
    /// Returns `Err(())` if the combination is not possible.
    #[inline(always)]
    fn from_micro_plans(first_op: MicroOpPlan, second_op: Option<MicroOpPlan>) -> Result<Self, ()> {
        let second_port = match second_op {
            None => None,
            Some(second_op) => {
                if first_op.cycle == second_op.cycle {
                    Some(second_op.port)
                } else {
                    return Err(());
                }
            }
        };
        Ok(Self {
            cycle: first_op.cycle,
            first_port: first_op.port,
            second_port,
        })
    }
}

/// Simple packed bit array implementation
///
/// This could use the `bitvec` crate if we cared to depend on it, but the
/// functionality we need is so tiny let's keep this simple.
#[derive(Debug, Clone, Eq, PartialEq)]
struct SimpleBitArray<const N: usize> {
    /// Array of words to use as a bit vector, in LSB-first order
    inner: [usize; N],
}

impl<const N: usize> Default for SimpleBitArray<N> {
    #[inline(always)]
    fn default() -> Self {
        Self {
            inner: [0_usize; N],
        }
    }
}

impl<const N: usize> SimpleBitArray<N> {
    /// Set or clear one bit in the array.
    ///
    /// Panics if the index is out of range.
    #[inline(always)]
    fn set(&mut self, index: usize, value: bool) {
        let word_size = usize::BITS as usize;
        let word_index = index / word_size;
        let bit_mask = 1 << (index % word_size);
        if value {
            self.inner[word_index] |= bit_mask;
        } else {
            self.inner[word_index] &= !bit_mask;
        }
    }

    /// Get one bit from the array.
    ///
    /// Panics if the index is out of range.
    #[inline(always)]
    fn get(&self, index: usize) -> bool {
        let word_size = usize::BITS as usize;
        let word_index = index / word_size;
        let bit_mask = 1 << (index % word_size);
        0 != (self.inner[word_index] & bit_mask)
    }
}
