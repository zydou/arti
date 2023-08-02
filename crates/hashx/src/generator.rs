//! Pseudorandom generator for hash programs and parts thereof

use crate::constraints::{self, Pass, RegisterWriter, Validator};
use crate::program::{Instruction, InstructionArray, Opcode, Program};
use crate::rand::RngBuffer;
use crate::register::{RegisterId, RegisterSet};
use crate::scheduler::{InstructionPlan, Scheduler};
use crate::Error;
use rand_core::RngCore;

/// The `model` attempts to document HashX program generation choices,
/// separate from the main body of the program generator.
mod model {
    use crate::constraints::Pass;
    use crate::generator::OpcodeSelector;
    use crate::program::Opcode;
    use crate::scheduler::SubCycle;

    /// Choose the next [`OpcodeSelector`].
    ///
    /// HashX uses a repeating pattern of opcode selectors, based on the
    /// current sub_cycle timestamp simulated for instruction fetch/decode.
    /// This gives a roughly constant program layout since most instructions do
    /// only take one sub-cycle to decode, but we do skip a sub-cycle every time
    /// there's a 2-op instruction (wide mul, target, branch). The repeating
    /// selector pattern is designed to ensure these skipped selectors are
    /// always the Normal type, so the overall number of multiply and branch
    /// instructions stays constant.
    ///
    /// The basic pattern is `(Mul, Normal, Normal)` but `Branch`, `Target`,
    /// and `WideMul` operations are mixed in at fixed locations in a 36-cycle
    /// repetition.
    ///
    /// Normal cycles are all replaced by `ImmediateSrc` if this is the retry
    /// pass, so that retries won't need to attempt source register selection
    /// in this case.
    #[inline(always)]
    pub(super) fn choose_opcode_selector(pass: Pass, sub_cycle: SubCycle) -> OpcodeSelector {
        let n = sub_cycle.as_usize() % 36;
        if n == 1 {
            OpcodeSelector::Target
        } else if n == 19 {
            OpcodeSelector::Branch
        } else if n == 12 || n == 24 {
            OpcodeSelector::WideMul
        } else if (n % 3) == 0 {
            OpcodeSelector::Mul
        } else {
            match pass {
                Pass::Original => OpcodeSelector::Normal,
                Pass::Retry => OpcodeSelector::ImmediateSrc,
            }
        }
    }

    /// Opcode choices for [`OpcodeSelector::WideMul`]
    pub(super) const WIDE_MUL_OPS_TABLE: [Opcode; 2] = [Opcode::SMulH, Opcode::UMulH];

    /// Opcode choices for [`OpcodeSelector::ImmediateSrc`]
    pub(super) const IMMEDIATE_SRC_OPS_TABLE: [Opcode; 4] = [
        Opcode::Rotate,
        Opcode::XorConst,
        Opcode::AddConst,
        Opcode::AddConst,
    ];

    /// Opcode choices for [`OpcodeSelector::Normal`]
    pub(super) const NORMAL_OPS_TABLE: [Opcode; 8] = [
        Opcode::Rotate,
        Opcode::XorConst,
        Opcode::AddConst,
        Opcode::AddConst,
        Opcode::Sub,
        Opcode::Xor,
        Opcode::XorConst,
        Opcode::AddShift,
    ];

    /// Masks for [`super::Instruction::Branch`] always have a constant
    /// number of bits set.
    ///
    /// The probability of taking a branch is approximately
    /// `1.0 / (1 << BRANCH_MASK_BIT_WEIGHT)`
    pub(super) const BRANCH_MASK_BIT_WEIGHT: usize = 4;
}

/// Generate a hash program from an arbitrary [`RngCore`] implementer.
///
/// This can return [`Error::ProgramConstraints`] if the HashX post-generation
/// program verification fails. During normal use this will happen once per
/// several thousand random seeds, and the caller should skip to another seed.
pub(crate) fn generate_program<T: RngCore>(rng: &mut T) -> Result<Program, Error> {
    Generator::new(rng).generate_program()
}

/// Internal state for the program generator
struct Generator<'r, R: RngCore> {
    /// The program generator wraps a random number generator, via [`RngBuffer`].
    rng: RngBuffer<'r, R>,

    /// Keep track of when execution units and registers will be ready,
    /// and ultimately generate a list of candidate available registers
    /// for any particular cycle.
    scheduler: Scheduler,

    /// Additional constraints on the entire program and pieces thereof
    /// are implemented in this separate Validator module.
    validator: Validator,

    /// Last [`Opcode`] chosen by an instruction selector
    ///
    /// Some of the instruction selectors have the notion of avoiding
    /// duplicates, but `HashX` designs this check based on the sequence of
    /// selector results rather than the sequence of committed instructions.
    last_selector_result_op: Option<Opcode>,
}

impl<'r, R: RngCore> Generator<'r, R> {
    /// Create a fresh program generator from a random number generator state.
    #[inline(always)]
    fn new(rng: &'r mut R) -> Self {
        Generator {
            rng: RngBuffer::new(rng),
            scheduler: Scheduler::new(),
            validator: Validator::new(),
            last_selector_result_op: None,
        }
    }

    /// Pick a pseudorandom register from a RegisterSet.
    ///
    /// Returns `Err(())` if the set is empty. Consumes one `u32` from the `Rng`
    /// only if the set contains more than one item.
    ///
    /// The choice is perfectly uniform only if the register set is a power of
    /// two length. Uniformity is not critical here.
    #[inline(always)]
    fn select_register(&mut self, reg_options: RegisterSet) -> Result<RegisterId, ()> {
        match reg_options.len() {
            0 => Err(()),
            1 => Ok(reg_options.index(0)),
            num_options => {
                let num_options: u32 = num_options
                    .try_into()
                    .expect("register set length always fits in u32");
                let index = self.rng.next_u32() % num_options;
                Ok(reg_options.index(
                    index
                        .try_into()
                        .expect("register set length always fits in usize"),
                ))
            }
        }
    }

    /// Pick a pseudorandom operation from a list of options.
    ///
    /// The `options` slice must be between 2 and 255 options in length.
    /// For uniformity and efficiency it's best if the length is also a power
    /// of two. All actual operation lists used by HashX have power-of-two
    /// lengths.
    #[inline(always)]
    fn select_op<'a, T, const SIZE: usize>(&mut self, options: &'a [T; SIZE]) -> &'a T {
        &options[(self.rng.next_u8() as usize) % options.len()]
    }

    /// Generate a random u32 bit mask, with a constant number of bits set.
    ///
    /// This uses an iterative algorithm that selects one bit at a time
    /// using a u8 from the Rng for each, discarding duplicates.
    #[inline(always)]
    fn select_constant_weight_bit_mask(&mut self, num_ones: usize) -> u32 {
        let mut result = 0_u32;
        let mut count = 0;
        while count < num_ones {
            let bit = 1 << ((self.rng.next_u8() as usize) % 32);
            if (result & bit) == 0 {
                result |= bit;
                count += 1;
            }
        }
        result
    }

    /// Generate random nonzero values.
    ///
    /// Iteratively picks a random u32, masking it, and discarding results that
    /// would be all zero.
    #[inline(always)]
    fn select_nonzero_u32(&mut self, mask: u32) -> u32 {
        loop {
            let result = self.rng.next_u32() & mask;
            if result != 0 {
                return result;
            }
        }
    }

    /// Generate an entire program.
    ///
    /// This generates instructions until the state can't be advanced any
    /// further. Returns with [`Error::ProgramConstraints`] if the program
    /// fails the `HashX` whole-program checks. These constraint failures occur
    /// in normal use, on a small fraction of seed values.
    #[inline(always)]
    fn generate_program(&mut self) -> Result<Program, Error> {
        let mut array: InstructionArray = Default::default();
        while array.len() < array.capacity() {
            match self.generate_instruction() {
                Err(()) => break,
                Ok((inst, regw)) => {
                    let state_advance = self.commit_instruction_state(&inst, regw);
                    array.push(inst);
                    if let Err(()) = state_advance {
                        break;
                    }
                }
            }
        }
        let result = self.validator.check_whole_program(&self.scheduler, &array);
        match result {
            Err(()) => Err(Error::ProgramConstraints),
            Ok(()) => Ok(Program::new(array)),
        }
    }

    /// Generate the next instruction.
    ///
    /// This is a multi-pass approach, starting with a [`Pass::Original`] that
    /// normally succeeds, followed by a [`Pass::Retry`] with simplifications
    /// to improve success rate, followed by a timing stall that advances the
    /// simulated cycle count forward and tries again with the benefit of newly
    /// available registers in the schedule.
    ///
    /// This only returns `Err(())` if we've hit a stopping condition for the
    /// program.
    #[inline(always)]
    fn generate_instruction(&mut self) -> Result<(Instruction, Option<RegisterWriter>), ()> {
        loop {
            if let Ok(result) = self.instruction_gen_attempt(Pass::Original) {
                return Ok(result);
            }
            if let Ok(result) = self.instruction_gen_attempt(Pass::Retry) {
                return Ok(result);
            }
            self.scheduler.stall()?;
        }
    }

    /// Choose an opcode using the current [`OpcodeSelector`], subject to
    /// stateful constraints on adjacent opcode choices.
    #[inline(always)]
    fn choose_opcode(&mut self, pass: Pass) -> Opcode {
        let op = loop {
            let sub_cycle = self.scheduler.instruction_stream_sub_cycle();
            let op = model::choose_opcode_selector(pass, sub_cycle).apply(self);
            if let Ok(()) = constraints::opcode_pair_allowed(self.last_selector_result_op, op) {
                break op;
            }
        };
        self.last_selector_result_op = Some(op);
        op
    }

    /// Make one attempt at instruction generation.
    ///
    /// This picks an [`OpcodeSelector`], chooses an opcode, then finishes
    /// choosing the opcode-specific parts of the instruction. Each of these
    /// choices affects the Rng state, and may fail if conditions are not met.
    #[inline(always)]
    fn instruction_gen_attempt(
        &mut self,
        pass: Pass,
    ) -> Result<(Instruction, Option<RegisterWriter>), ()> {
        let op = self.choose_opcode(pass);
        let plan = self.scheduler.instruction_plan(op)?;
        let (inst, regw) = self.choose_instruction_with_opcode_plan(op, pass, &plan)?;
        assert_eq!(inst.opcode(), op);
        self.scheduler.commit_instruction_plan(&plan, &inst);
        Ok((inst, regw))
    }

    /// Choose both a source and destination register using a normal
    /// [`RegisterWriter`] for two-operand instructions.
    #[inline(always)]
    fn choose_src_dst_regs(
        &mut self,
        op: Opcode,
        pass: Pass,
        timing_plan: &InstructionPlan,
    ) -> Result<(RegisterId, RegisterId, RegisterWriter), ()> {
        let avail_set = self
            .scheduler
            .registers_available(timing_plan.cycle_issued());
        let src_set = constraints::src_registers_allowed(avail_set, op);
        let src = self.select_register(src_set)?;
        let writer_info = RegisterWriter::RegSource(op, src);
        let dst_set =
            self.validator
                .dst_registers_allowed(avail_set, op, pass, &writer_info, Some(src));
        let dst = self.select_register(dst_set)?;
        Ok((src, dst, writer_info))
    }

    /// Choose both a source and destination register, with a custom
    /// [`RegisterWriter`] constraint that doesn't depend on source
    /// register choice.
    #[inline(always)]
    fn choose_src_dst_regs_with_writer_info(
        &mut self,
        op: Opcode,
        pass: Pass,
        writer_info: &RegisterWriter,
        timing_plan: &InstructionPlan,
    ) -> Result<(RegisterId, RegisterId), ()> {
        let avail_set = self
            .scheduler
            .registers_available(timing_plan.cycle_issued());
        let src_set = constraints::src_registers_allowed(avail_set, op);
        let src = self.select_register(src_set)?;
        let dst_set =
            self.validator
                .dst_registers_allowed(avail_set, op, pass, writer_info, Some(src));
        let dst = self.select_register(dst_set)?;
        Ok((src, dst))
    }

    /// Choose a destination register only.
    #[inline(always)]
    fn choose_dst_reg(
        &mut self,
        op: Opcode,
        pass: Pass,
        writer_info: &RegisterWriter,
        timing_plan: &InstructionPlan,
    ) -> Result<RegisterId, ()> {
        let avail_set = self
            .scheduler
            .registers_available(timing_plan.cycle_issued());
        let dst_set = self
            .validator
            .dst_registers_allowed(avail_set, op, pass, writer_info, None);
        let dst = self.select_register(dst_set)?;
        Ok(dst)
    }

    /// With an [`Opcode`] and an execution unit timing plan already in mind,
    /// generate the other pieces necessary to fully describe an
    /// [`Instruction`].
    ///
    /// This can fail if register selection fails.
    #[inline(always)]
    fn choose_instruction_with_opcode_plan(
        &mut self,
        op: Opcode,
        pass: Pass,
        plan: &InstructionPlan,
    ) -> Result<(Instruction, Option<RegisterWriter>), ()> {
        Ok(match op {
            Opcode::Target => (Instruction::Target, None),

            Opcode::Branch => (
                Instruction::Branch {
                    mask: self.select_constant_weight_bit_mask(model::BRANCH_MASK_BIT_WEIGHT),
                },
                None,
            ),

            Opcode::UMulH => {
                let regw = RegisterWriter::WideMul(op, self.rng.next_u32());
                let (src, dst) =
                    self.choose_src_dst_regs_with_writer_info(op, pass, &regw, plan)?;
                (Instruction::UMulH { src, dst }, Some(regw))
            }

            Opcode::SMulH => {
                let regw = RegisterWriter::WideMul(op, self.rng.next_u32());
                let (src, dst) =
                    self.choose_src_dst_regs_with_writer_info(op, pass, &regw, plan)?;
                (Instruction::SMulH { src, dst }, Some(regw))
            }

            Opcode::Mul => {
                let (src, dst, regw) = self.choose_src_dst_regs(op, pass, plan)?;
                (Instruction::Mul { src, dst }, Some(regw))
            }

            Opcode::Sub => {
                let (src, dst, regw) = self.choose_src_dst_regs(op, pass, plan)?;
                (Instruction::Sub { src, dst }, Some(regw))
            }

            Opcode::Xor => {
                let (src, dst, regw) = self.choose_src_dst_regs(op, pass, plan)?;
                (Instruction::Xor { src, dst }, Some(regw))
            }

            Opcode::AddShift => {
                let left_shift = (self.rng.next_u32() & 3) as u8;
                let (src, dst, regw) = self.choose_src_dst_regs(op, pass, plan)?;
                (
                    Instruction::AddShift {
                        src,
                        dst,
                        left_shift,
                    },
                    Some(regw),
                )
            }

            Opcode::AddConst => {
                let regw = RegisterWriter::ConstSource(op);
                let src = self.select_nonzero_u32(u32::MAX) as i32;
                let dst = self.choose_dst_reg(op, pass, &regw, plan)?;
                (Instruction::AddConst { src, dst }, Some(regw))
            }

            Opcode::XorConst => {
                let regw = RegisterWriter::ConstSource(op);
                let src = self.select_nonzero_u32(u32::MAX) as i32;
                let dst = self.choose_dst_reg(op, pass, &regw, plan)?;
                (Instruction::XorConst { src, dst }, Some(regw))
            }

            Opcode::Rotate => {
                let regw = RegisterWriter::ConstSource(op);
                let right_rotate: u8 = self.select_nonzero_u32(63) as u8;
                let dst = self.choose_dst_reg(op, pass, &regw, plan)?;
                (Instruction::Rotate { dst, right_rotate }, Some(regw))
            }
        })
    }

    /// Commit all state modifications associated with a chosen instruction
    /// that's certainly being written to the final program.
    ///
    /// Returns `Ok(())` on success or `Err(())` if the new state would no
    /// longer be valid for program generation and we're done writing code.
    #[inline(always)]
    fn commit_instruction_state(
        &mut self,
        inst: &Instruction,
        regw: Option<RegisterWriter>,
    ) -> Result<(), ()> {
        self.validator.commit_instruction(inst, regw);
        self.scheduler.advance_instruction_stream(inst.opcode())
    }
}

/// HashX uses a limited number of different instruction selection strategies,
/// chosen based on the sub-cycle timing of our position in the
/// instruction stream.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum OpcodeSelector {
    /// Main ALU instruction chooser, picks from Add/Sub/Xor/Rotate
    Normal,
    /// Retry pass if Normal fails, instructions with immediate source only
    ImmediateSrc,
    /// Only multiply instructions, no additional register selection work.
    Mul,
    /// Wide multiply instructions, randomly choosing signedness
    WideMul,
    /// Only branch targets
    Target,
    /// Only branch instructions
    Branch,
}

impl OpcodeSelector {
    /// Apply the selector, advancing the Rng state and returning an Opcode.
    #[inline(always)]
    fn apply<R: RngCore>(&self, gen: &mut Generator<'_, R>) -> Opcode {
        match self {
            OpcodeSelector::Target => Opcode::Target,
            OpcodeSelector::Branch => Opcode::Branch,
            OpcodeSelector::Mul => Opcode::Mul,
            OpcodeSelector::Normal => *gen.select_op(&model::NORMAL_OPS_TABLE),
            OpcodeSelector::ImmediateSrc => *gen.select_op(&model::IMMEDIATE_SRC_OPS_TABLE),
            OpcodeSelector::WideMul => *gen.select_op(&model::WIDE_MUL_OPS_TABLE),
        }
    }
}