//! Constraints that affect program generation
//!
//! Defines specific configurations that are not allowed, causing programs
//! or program fragments to be rejected during the generation process.
//!
//! The motivation for these constraints are in producing a good quality hash
//! function by avoiding hazards that affect timing or hash mixing. However,
//! they also form an integral part of the program generation model.
//! Generating correct HashX output depends on applying exactly the right
//! constraints.

use crate::program::{Instruction, InstructionVec, Opcode};
use crate::register::{NUM_REGISTERS, RegisterId, RegisterSet};
use crate::scheduler::Scheduler;

pub(crate) use model::{Pass, RegisterWriter};

/// The `model` attempts to document what the HashX constraints are, separate
/// from the process of implementing those constraints.
mod model {
    use crate::program::{NUM_INSTRUCTIONS, Opcode};
    use crate::register::{self, RegisterId};

    /// Programs require an exact number of instructions. (The instruction
    /// buffer must have filled without any of the other stopping conditions)
    pub(super) const REQUIRED_INSTRUCTIONS: usize = NUM_INSTRUCTIONS;

    /// Programs require an exact overall data latency, represented as the
    /// simulated cycle at which the last register write completes.
    pub(super) const REQUIRED_OVERALL_RESULT_AT_CYCLE: usize = 194;

    /// Programs require an exact total number of multiply instructions, they
    /// can't be skipped for any reason.
    pub(super) const REQUIRED_MULTIPLIES: usize = 192;

    /// Determine which ops count when testing [`REQUIRED_MULTIPLIES`].
    #[inline(always)]
    pub(super) fn is_multiply(op: Opcode) -> bool {
        matches!(op, Opcode::Mul | Opcode::SMulH | Opcode::UMulH)
    }

    /// Does an instruction prohibit using the same register for src and dst?
    ///
    /// Meaningful only for ops that have both a source and destination register.
    #[inline(always)]
    pub(super) fn disallow_src_is_dst(op: Opcode) -> bool {
        matches!(
            op,
            Opcode::AddShift | Opcode::Mul | Opcode::Sub | Opcode::Xor
        )
    }

    /// Special case for register R5
    ///
    /// HashX special-cases one specific register for AddShift in order to fit
    /// in the constraints of x86_64 under the encodings chosen by HashX's
    /// original x86 compiler backend. See Table 2-5 in the Intel 64 and IA-32
    /// Software Developer Manual Volume 2A, "Special Cases of REX Encodings".
    /// Register R13 in x86_64 maps directly to R5 in the original HashX
    /// implementation. Even on backends where this constraint is not relevant,
    /// the program generation process requires us to take it into account.
    pub(super) const DISALLOW_REGISTER_FOR_ADDSHIFT: RegisterId = register::R5;

    /// Should `proposed` be rejected as the immediate successor of `previous`?
    #[inline(always)]
    pub(super) fn disallow_opcode_pair(previous: Opcode, proposed: Opcode) -> bool {
        match proposed {
            // Never rejected at this stage
            Opcode::Mul | Opcode::UMulH | Opcode::SMulH | Opcode::Target | Opcode::Branch => false,
            // Disallow exact opcode duplicates
            Opcode::AddConst | Opcode::Xor | Opcode::XorConst | Opcode::Rotate => {
                previous == proposed
            }
            // Register add/sub can't be chosen back to back
            Opcode::AddShift | Opcode::Sub => {
                previous == Opcode::AddShift || previous == Opcode::Sub
            }
        }
    }

    /// Should `this_writer` be allowed on a register which was previously
    /// written using `last_writer`?
    ///
    /// Requires the current [`Pass`].
    #[inline(always)]
    pub(super) fn writer_pair_allowed(
        pass: Pass,
        last_writer: RegisterWriter,
        this_writer: RegisterWriter,
    ) -> bool {
        match (last_writer, this_writer) {
            // HashX disallows back-to-back 64-bit multiplies on the
            // same destination register in Pass::Original but permits
            // them on the retry if the source register isn't identical.
            (RegisterWriter::Mul(_), RegisterWriter::Mul(_)) if matches!(pass, Pass::Original) => {
                false
            }

            // Other pairings are allowed if the writer info differs at all.
            (last_writer, this_writer) => last_writer != this_writer,
        }
    }

    /// One specific pass in the multi-pass instruction choice process
    ///
    /// [`super::Instruction`] choice can take multiple attempts to complete,
    /// and we allow the [`super::Validator`] to make different decisions on
    /// each pass.
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub(crate) enum Pass {
        /// First pass, nothing has failed
        Original,
        /// Single retry pass before a timing stall
        Retry,
    }

    /// Information about the instruction that writes to a register, from the
    /// perspective of our particular constraints here
    ///
    /// This is conceptually similar to storing the last [`super::Instruction`]
    /// that wrote to a register, but HashX sometimes needs information for
    /// constraints which won't end up in the final `Instruction`.
    ///
    /// We've chosen the encoding to minimize the code size in
    /// writer_pair_allowed. Most pairwise comparisons can just be a register
    /// equality test.
    ///
    /// The instructions here fall into three categories which use their own
    /// format for encoding arguments:
    ///
    ///  - Wide Multiply, extra u32
    ///
    ///    UMulH and SMulH use an additional otherwise unused 32-bit value
    ///    from the Rng when considering writer collisions.
    ///
    ///    As far as I can tell this is a bug in the original implementation
    ///    but we can't change the behavior without breaking compatibility.
    ///
    ///    The collisions are rare enough not to be a worthwhile addition
    ///    to ASIC-resistance. It seems like this was a vestigial feature
    ///    left over from immediate value matching features which were removed
    ///    during the development of HashX, but I can't be sure.
    ///
    ///  - Constant source
    ///
    ///    Only considers the opcode itself, not the specific immediate value.
    ///
    ///  - Register source
    ///
    ///    Considers the source register, collapses add/subtract into one op.
    ///
    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
    pub(crate) enum RegisterWriter {
        /// Register not written yet
        #[default]
        None,
        /// Register source writer for [`super::Instruction::Mul`]
        Mul(RegisterId),
        /// Wide multiply writer for [`super::Instruction::UMulH`]
        UMulH(u32),
        /// Wide multiply writer for [`super::Instruction::SMulH`]
        SMulH(u32),
        /// Register source writer for [`super::Instruction::AddShift`]
        /// and [`super::Instruction::Sub`]
        AddSub(RegisterId),
        /// Constant source writer for [`super::Instruction::AddConst`]
        AddConst,
        /// Register source writer for [`super::Instruction::Xor`]
        Xor(RegisterId),
        /// Constant source writer for [`super::Instruction::XorConst`]
        XorConst,
        /// Constant source writer for [`super::Instruction::Rotate`]
        Rotate,
    }
}

/// Stateful program constraint checker
///
/// This keeps additional state during the construction of a new program,
/// in order to check constraints that may reject registers and entire programs.
#[derive(Debug, Clone)]
pub(crate) struct Validator {
    /// For each register in the file, keep track of the instruction it was
    /// written by.
    ///
    /// This becomes part of the constraints for
    /// destination registers in future instructions.
    writer_map: RegisterWriterMap,

    /// Total multiplication operations of all types
    multiply_count: usize,
}

impl Validator {
    /// Construct a new empty Validator.
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self {
            writer_map: RegisterWriterMap::new(),
            multiply_count: 0,
        }
    }

    /// Commit a new instruction to the validator state.
    #[inline(always)]
    pub(crate) fn commit_instruction(&mut self, inst: &Instruction, regw: RegisterWriter) {
        if model::is_multiply(inst.opcode()) {
            self.multiply_count += 1;
        }
        match inst.destination() {
            None => debug_assert_eq!(regw, RegisterWriter::None),
            Some(dst) => self.writer_map.insert(dst, regw),
        }
    }

    /// Is the completed program acceptable?
    ///
    /// Once the whole program is assembled, HashX still has a chance to reject
    /// it if it fails certain criteria.
    #[inline(always)]
    pub(crate) fn check_whole_program(
        &self,
        scheduler: &Scheduler,
        instructions: &InstructionVec,
    ) -> Result<(), ()> {
        if instructions.len() == model::REQUIRED_INSTRUCTIONS
            && scheduler.overall_latency().as_usize() == model::REQUIRED_OVERALL_RESULT_AT_CYCLE
            && self.multiply_count == model::REQUIRED_MULTIPLIES
        {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Begin checking which destination registers are allowed for an op after
    /// its source is known, using the current state of the validator.
    ///
    /// Returns a DstRegisterChecker which can be used to test each specific
    /// destination RegisterId quickly.
    #[inline(always)]
    pub(crate) fn dst_registers_allowed(
        &self,
        op: Opcode,
        pass: Pass,
        writer_info: RegisterWriter,
        src: Option<RegisterId>,
    ) -> DstRegisterChecker<'_> {
        DstRegisterChecker {
            pass,
            writer_info,
            writer_map: &self.writer_map,
            op_is_add_shift: op == Opcode::AddShift,
            disallow_equal: if model::disallow_src_is_dst(op) {
                src
            } else {
                None
            },
        }
    }
}

/// State information returned by [`Validator::dst_registers_allowed`]
#[derive(Debug, Clone)]
pub(crate) struct DstRegisterChecker<'v> {
    /// Is this the original or retry pass?
    pass: Pass,
    /// Reference to a table of [`RegisterWriter`] information for each register
    writer_map: &'v RegisterWriterMap,
    /// The new [`RegisterWriter`] under consideration
    writer_info: RegisterWriter,
    /// Was this [`Opcode::AddShift`]?
    op_is_add_shift: bool,
    /// Optionally disallow one matching register, used to implement [`model::disallow_src_is_dst`]
    disallow_equal: Option<RegisterId>,
}

impl<'v> DstRegisterChecker<'v> {
    /// Check a single destination register for usability, using context from
    /// [`Validator::dst_registers_allowed`]
    #[inline(always)]
    pub(crate) fn check(&self, dst: RegisterId) -> bool {
        // One register specified by DISALLOW_REGISTER_FOR_ADDSHIFT can't
        // be used as destination for AddShift.
        if self.op_is_add_shift && dst == model::DISALLOW_REGISTER_FOR_ADDSHIFT {
            return false;
        }

        // A few instructions disallow choosing src and dst as the same
        if Some(dst) == self.disallow_equal {
            return false;
        }

        // Additional constraints are written on the pair of previous and
        // current instructions with the same destination.
        model::writer_pair_allowed(self.pass, self.writer_map.get(dst), self.writer_info)
    }
}

/// Figure out the allowed register set for an operation, given what's available
/// in the schedule.
#[inline(always)]
pub(crate) fn src_registers_allowed(available: RegisterSet, op: Opcode) -> RegisterSet {
    // HashX defines a special case DISALLOW_REGISTER_FOR_ADDSHIFT for
    // destination registers, and it also includes a look-ahead
    // condition here in source register allocation to prevent the dst
    // allocation from getting stuck as often. If we have only two
    // remaining registers for AddShift and one is the disallowed reg,
    // HashX defines that the random choice is short-circuited early
    // here and we always choose the one combination which is actually
    // allowed.
    if op == Opcode::AddShift
        && available.contains(model::DISALLOW_REGISTER_FOR_ADDSHIFT)
        && available.len() == 2
    {
        RegisterSet::from_filter(
            #[inline(always)]
            |reg| reg == model::DISALLOW_REGISTER_FOR_ADDSHIFT,
        )
    } else {
        available
    }
}

/// Should `proposed` be allowed as an opcode selector output immediately
/// following an output of `previous`?
///
/// Some pairs of adjacent [`Opcode`]s are rejected at the opcode selector level
/// without causing an entire instruction generation pass to fail.
#[inline(always)]
pub(crate) fn opcode_pair_allowed(previous: Option<Opcode>, proposed: Opcode) -> Result<(), ()> {
    match previous {
        None => Ok(()),
        Some(previous) => {
            if model::disallow_opcode_pair(previous, proposed) {
                Err(())
            } else {
                Ok(())
            }
        }
    }
}

/// Map each [`RegisterId`] to an [`RegisterWriter`]
#[derive(Default, Debug, Clone)]
struct RegisterWriterMap([RegisterWriter; NUM_REGISTERS]);

impl RegisterWriterMap {
    /// Make a new empty register writer map.
    ///
    /// All registers are set to None.
    #[inline(always)]
    fn new() -> Self {
        Default::default()
    }

    /// Write or overwrite the last [`RegisterWriter`] associated with `reg`.
    #[inline(always)]
    fn insert(&mut self, reg: RegisterId, writer: RegisterWriter) {
        self.0[reg.as_usize()] = writer;
    }

    /// Return the most recent mapping for 'reg', if any.
    #[inline(always)]
    fn get(&self, reg: RegisterId) -> RegisterWriter {
        self.0[reg.as_usize()]
    }
}
